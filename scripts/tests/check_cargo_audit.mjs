#!/usr/bin/env node

import assert from 'node:assert/strict';
import {
  REVIEWED_YANK,
  validateAuditPolicy,
  validateAuditReport,
  validateDependencyTree,
} from '../check_cargo_audit.mjs';

function auditReport(warnings = undefined) {
  return {
    settings: {
      ignore: ['RUSTSEC-2023-0071'],
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

validateAuditPolicy(auditReport(), dependencyTree());

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

console.log('Cargo audit policy fixture tests passed');
