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
const REVIEWED_ADVISORY_IGNORES = Object.freeze(['RUSTSEC-2023-0071']);
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

export function validateAuditPolicy(report, dependencyTree) {
  validateAuditReport(report);
  validateDependencyTree(dependencyTree);
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
  validateAuditPolicy(report, dependencyTree);
  console.log(
    `Rust audit policy passed: only reviewed yank ${REVIEWED_YANK.name} ${REVIEWED_YANK.version}`,
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
