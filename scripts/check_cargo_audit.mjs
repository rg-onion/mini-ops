#!/usr/bin/env node

import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024;
const REGISTRY_SOURCE = 'registry+https://github.com/rust-lang/crates.io-index';

export const REVIEWED_YANK = Object.freeze({
  name: 'spin',
  version: '0.9.8',
  source: REGISTRY_SOURCE,
  checksum: '6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67',
  directDependents: Object.freeze(['flume@0.11.1']),
});
// Advisories ignored in .cargo/audit.toml by exact ID, reviewed 2026-11-21
// (re-review by 2027-02-21). Each is pinned to the exact Cargo.lock entry it
// was reviewed against; see validateReviewedLockPackages.
export const REVIEWED_LOCK_PACKAGES = Object.freeze([
  Object.freeze({
    advisory: 'RUSTSEC-2026-0459',
    name: 'libsqlite3-sys',
    version: '0.30.1',
    source: REGISTRY_SOURCE,
    checksum: '2e99fb7a497b1e3339bc746195567ed8d3e24945ecd636e3619d20b9de9e9149',
  }),
  Object.freeze({
    advisory: 'RUSTSEC-2026-0543',
    name: 'chrono',
    version: '0.4.43',
    source: REGISTRY_SOURCE,
    checksum: 'fac4744fb15ae8337dc853fee7fb3f4e48c0fbaa23d0afe49c447b4fab126118',
  }),
  Object.freeze({
    advisory: 'RUSTSEC-2026-0441',
    name: 'pin-utils',
    version: '0.1.0',
    source: REGISTRY_SOURCE,
    checksum: '8b870d8c151b6f2fb93e84a13146138f05d02ed11c7e7c54f8826aaaf7c9f184',
  }),
]);
const REVIEWED_ADVISORY_IGNORES = Object.freeze(
  ['RUSTSEC-2023-0071', ...REVIEWED_LOCK_PACKAGES.map((entry) => entry.advisory)].sort(),
);
const REQUIRED_INFORMATIONAL_WARNINGS = Object.freeze(['notice', 'unmaintained', 'unsound']);

class AuditPolicyError extends Error {}

function requireCondition(condition, message) {
  if (!condition) {
    throw new AuditPolicyError(message);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function validateAuditReport(report) {
  requireCondition(isObject(report), 'cargo audit returned an invalid report');
  requireCondition(isObject(report.settings), 'cargo audit report is missing settings');
  requireCondition(
    Array.isArray(report.settings.ignore) &&
      JSON.stringify([...report.settings.ignore].sort()) ===
        JSON.stringify(REVIEWED_ADVISORY_IGNORES),
    'cargo audit advisory ignore policy changed',
  );
  requireCondition(
    Array.isArray(report.settings.informational_warnings) &&
      JSON.stringify([...report.settings.informational_warnings].sort()) ===
        JSON.stringify(REQUIRED_INFORMATIONAL_WARNINGS),
    'cargo audit informational warning policy changed',
  );
  requireCondition(
    Array.isArray(report.settings.target_arch) &&
      report.settings.target_arch.length === 0 &&
      Array.isArray(report.settings.target_os) &&
      report.settings.target_os.length === 0,
    'cargo audit target filters are not allowed',
  );
  requireCondition(
    isObject(report.vulnerabilities),
    'cargo audit report is missing vulnerabilities',
  );
  requireCondition(
    report.vulnerabilities.found === false &&
      report.vulnerabilities.count === 0 &&
      Array.isArray(report.vulnerabilities.list) &&
      report.vulnerabilities.list.length === 0,
    'cargo audit found a vulnerability',
  );
  requireCondition(
    isObject(report.warnings),
    'cargo audit report has an invalid warnings section',
  );
  const warningCategories = Object.keys(report.warnings);
  requireCondition(
    warningCategories.length > 0,
    'reviewed yank is no longer reported; remove the exception',
  );
  requireCondition(
    JSON.stringify(warningCategories) === JSON.stringify(['yanked']),
    'cargo audit warning categories changed',
  );

  const warnings = [];
  for (const [category, entries] of Object.entries(report.warnings)) {
    requireCondition(
      Array.isArray(entries),
      `cargo audit warning category ${category} is invalid`,
    );
    for (const warning of entries) {
      warnings.push({ category, warning });
    }
  }

  requireCondition(
    warnings.length === 1,
    warnings.length === 0
      ? 'reviewed yank is no longer reported; remove the exception'
      : 'cargo audit reported warnings outside the reviewed exception',
  );

  const [{ category, warning }] = warnings;
  requireCondition(
    category === 'yanked' && isObject(warning) && warning.kind === 'yanked',
    'cargo audit reported a non-yank warning',
  );
  requireCondition(
    isObject(warning.package),
    'cargo audit yanked warning is missing package metadata',
  );

  const pkg = warning.package;
  requireCondition(
    pkg.name === REVIEWED_YANK.name &&
      pkg.version === REVIEWED_YANK.version &&
      pkg.source === REVIEWED_YANK.source &&
      pkg.checksum === REVIEWED_YANK.checksum,
    'cargo audit reported an unreviewed yanked package',
  );
}

export function validateDependencyTree(tree) {
  requireCondition(typeof tree === 'string', 'cargo tree returned an invalid report');
  const lines = tree.trim().split('\n');
  const parsedLines = lines.map((line) => {
    const match = /^(\d+)([A-Za-z0-9_.-]+) v([^\s]+)(?: .*)?$/.exec(line);
    requireCondition(match !== null, 'cargo tree returned an unexpected line');
    return {
      depth: Number(match[1]),
      name: match[2],
      version: match[3],
    };
  });
  requireCondition(
    parsedLines[0].depth === 0 &&
      parsedLines[0].name === REVIEWED_YANK.name &&
      parsedLines[0].version === REVIEWED_YANK.version,
    'reviewed yanked package is missing from the active dependency tree',
  );
  const directDependents = parsedLines
    .filter((line) => line.depth === 1)
    .map((line) => `${line.name}@${line.version}`)
    .sort();
  requireCondition(
    JSON.stringify(directDependents) === JSON.stringify(REVIEWED_YANK.directDependents),
    'reviewed yanked package has an unreviewed dependency path',
  );
  requireCondition(
    parsedLines.some((line) => line.depth > 1 && line.name === 'mini-ops'),
    'reviewed yanked package is no longer reachable; remove the exception',
  );
}

function parseLockPackages(lockText) {
  const entries = [];
  for (const block of lockText.split(/^\[\[package\]\]$/m).slice(1)) {
    const field = (key) => new RegExp(`^${key} = "([^"\\n]*)"$`, 'm').exec(block)?.[1];
    entries.push({
      name: field('name'),
      version: field('version'),
      source: field('source'),
      checksum: field('checksum'),
    });
  }
  return entries;
}

// The ignores for REVIEWED_LOCK_PACKAGES hide their advisories for any version,
// so the exact reviewed Cargo.lock entry must stay in place. A changed version
// (including a patched one) or a removed package fails until the exception is
// re-reviewed or removed.
export function validateReviewedLockPackages(lockText) {
  requireCondition(
    typeof lockText === 'string' && lockText.length > 0,
    'Cargo.lock is missing or empty',
  );
  const entries = parseLockPackages(lockText);
  for (const reviewed of REVIEWED_LOCK_PACKAGES) {
    const matches = entries.filter((entry) => entry.name === reviewed.name);
    requireCondition(
      matches.length > 0,
      `reviewed ${reviewed.name} is no longer in Cargo.lock; remove the ${reviewed.advisory} exception`,
    );
    requireCondition(
      matches.length === 1 &&
        matches[0].version === reviewed.version &&
        matches[0].source === reviewed.source &&
        matches[0].checksum === reviewed.checksum,
      `reviewed ${reviewed.name} changed in Cargo.lock; re-review or remove the ${reviewed.advisory} exception`,
    );
  }
}

export function validateAuditPolicy(report, dependencyTree, lockText) {
  validateAuditReport(report);
  validateDependencyTree(dependencyTree);
  validateReviewedLockPackages(lockText);
}

function readBoundedJson(filePath) {
  let size;
  try {
    size = statSync(filePath).size;
  } catch {
    throw new AuditPolicyError('audit policy report is missing');
  }
  requireCondition(
    size > 0 && size <= MAX_COMMAND_OUTPUT_BYTES,
    'audit policy report exceeds its size boundary',
  );
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    throw new AuditPolicyError('audit policy report contains invalid JSON');
  }
}

function readBoundedText(filePath) {
  let size;
  try {
    size = statSync(filePath).size;
  } catch {
    throw new AuditPolicyError('audit policy report is missing');
  }
  requireCondition(
    size > 0 && size <= MAX_COMMAND_OUTPUT_BYTES,
    'audit policy report exceeds its size boundary',
  );
  return readFileSync(filePath, 'utf8');
}

function main() {
  const cliArguments = process.argv.slice(2);
  requireCondition(
    cliArguments.length === 2,
    'usage: node scripts/check_cargo_audit.mjs <audit-json> <dependency-tree>',
  );
  const report = readBoundedJson(cliArguments[0]);
  const dependencyTree = readBoundedText(cliArguments[1]);
  const lockText = readBoundedText(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'Cargo.lock'),
  );
  validateAuditPolicy(report, dependencyTree, lockText);
  console.log(
    `Rust audit policy passed: only reviewed yank ${REVIEWED_YANK.name} ${REVIEWED_YANK.version} ` +
      `and reviewed ignores ${REVIEWED_ADVISORY_IGNORES.join(', ')}`,
  );
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    const message = error instanceof AuditPolicyError ? error.message : 'unexpected audit policy error';
    console.error(`Rust audit policy failed: ${message}`);
    process.exitCode = 1;
  }
}
