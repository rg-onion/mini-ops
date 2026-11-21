#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  REVIEWED_LOCK_PACKAGES,
  REVIEWED_YANK,
  validateAuditPolicy,
  validateAuditReport,
  validateDependencyTree,
  validateReviewedLockPackages,
} from '../check_cargo_audit.mjs';

function auditReport(warnings = undefined) {
  return {
    settings: {
      ignore: [
        'RUSTSEC-2023-0071',
        'RUSTSEC-2026-0459',
        'RUSTSEC-2026-0543',
        'RUSTSEC-2026-0441',
      ],
      informational_warnings: ['unmaintained', 'unsound', 'notice'],
      target_arch: [],
      target_os: [],
    },
    vulnerabilities: { found: false, count: 0, list: [] },
    warnings:
      warnings ?? {
        yanked: [
          {
            kind: 'yanked',
            package: {
              name: REVIEWED_YANK.name,
              version: REVIEWED_YANK.version,
              source: REVIEWED_YANK.source,
              checksum: REVIEWED_YANK.checksum,
            },
          },
        ],
      },
  };
}

function dependencyTree(extraParent = false) {
  return [
    '0spin v0.9.8',
    '1flume v0.11.1',
    '2sqlx-sqlite v0.8.6',
    '3sqlx v0.8.6',
    '4mini-ops v1.1.0 (/workspace/mini-ops)',
    ...(extraParent
      ? ['1unreviewed-parent v1.0.0', '2mini-ops v1.1.0 (/workspace/mini-ops)']
      : []),
  ].join('\n');
}

function lockFile(overrides = {}, omit = []) {
  return REVIEWED_LOCK_PACKAGES.filter((entry) => !omit.includes(entry.name))
    .map((entry) => {
      const merged = { ...entry, ...(overrides[entry.name] ?? {}) };
      return [
        '[[package]]',
        `name = "${merged.name}"`,
        `version = "${merged.version}"`,
        `source = "${merged.source}"`,
        `checksum = "${merged.checksum}"`,
        'dependencies = [',
        ' "unrelated",',
        ']',
        '',
      ].join('\n');
    })
    .join('\n');
}

validateAuditPolicy(auditReport(), dependencyTree(), lockFile());

assert.throws(
  () =>
    validateAuditReport({
      settings: auditReport().settings,
      vulnerabilities: { found: true, count: 1, list: [{}] },
      warnings: auditReport().warnings,
    }),
  /found a vulnerability/,
);
assert.throws(() => validateAuditReport(auditReport({})), /remove the exception/);
const changedIgnore = auditReport();
changedIgnore.settings.ignore.push('RUSTSEC-2099-0001');
assert.throws(() => validateAuditReport(changedIgnore), /ignore policy changed/);
assert.throws(
  () =>
    validateAuditReport(
      auditReport({
        yanked: [
          {
            kind: 'yanked',
            package: {
              name: 'another-crate',
              version: '1.0.0',
              source: REVIEWED_YANK.source,
              checksum: 'different',
            },
          },
        ],
      }),
    ),
  /unreviewed yanked package/,
);
assert.throws(
  () => validateAuditReport(auditReport({ unsound: [{ kind: 'unsound' }] })),
  /warning categories changed/,
);
assert.throws(
  () => validateDependencyTree(dependencyTree(true)),
  /unreviewed dependency path/,
);
assert.throws(
  () => validateDependencyTree('0spin v0.9.8\n1flume v0.11.1'),
  /no longer reachable/,
);

validateReviewedLockPackages(lockFile());
for (const reviewed of REVIEWED_LOCK_PACKAGES) {
  assert.throws(
    () => validateReviewedLockPackages(lockFile({ [reviewed.name]: { version: '9.9.9' } })),
    new RegExp(`${reviewed.name} changed in Cargo.lock; re-review or remove the ${reviewed.advisory}`),
  );
  assert.throws(
    () =>
      validateReviewedLockPackages(lockFile({ [reviewed.name]: { checksum: 'different' } })),
    /changed in Cargo.lock/,
  );
  assert.throws(
    () => validateReviewedLockPackages(lockFile({}, [reviewed.name])),
    new RegExp(`${reviewed.name} is no longer in Cargo.lock; remove the ${reviewed.advisory}`),
  );
  // A second, unreviewed version of the same crate must not ride on the exception.
  assert.throws(
    () =>
      validateReviewedLockPackages(
        `${lockFile()}\n${lockFile({ [reviewed.name]: { version: '9.9.9' } })}`,
      ),
    /changed in Cargo.lock/,
  );
}
assert.throws(() => validateReviewedLockPackages(''), /Cargo.lock is missing or empty/);
assert.throws(
  () => validateAuditPolicy(auditReport(), dependencyTree(), undefined),
  /Cargo.lock is missing or empty/,
);
const droppedIgnore = auditReport();
droppedIgnore.settings.ignore = ['RUSTSEC-2023-0071'];
assert.throws(() => validateAuditReport(droppedIgnore), /ignore policy changed/);
const extraIgnore = auditReport();
extraIgnore.settings.ignore.push('RUSTSEC-2026-0460');
assert.throws(() => validateAuditReport(extraIgnore), /ignore policy changed/);

console.log('Cargo audit policy fixture tests passed');
