#!/usr/bin/env node
'use strict';

const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');

const CLI = path.join(__dirname, '..', 'leakhound.js');
const FIXTURES = path.join(__dirname, 'fixtures');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`  ok - ${name}`);
}

console.log('leakhound tests');

test('dirty fixtures yield findings and exit code 1', () => {
  const res = run([path.join(FIXTURES, 'dirty'), '--json']);
  assert.strictEqual(res.status, 1, `expected exit 1, got ${res.status}\n${res.stderr}`);
  const findings = JSON.parse(res.stdout);
  assert.ok(Array.isArray(findings), 'JSON output must be an array');
  assert.ok(findings.length > 0, 'expected findings > 0');
  const rules = new Set(findings.map((f) => f.rule));
  for (const expected of [
    'aws-access-key-id',
    'google-api-key',
    'github-token',
    'stripe-live-secret-key',
    'slack-token',
    'omise-live-secret-key',
    'jwt',
    'private-key-block',
    'generic-secret-assignment',
    'gbprimepay-key',
  ]) {
    assert.ok(rules.has(expected), `expected rule "${expected}" to fire; got: ${[...rules].join(', ')}`);
  }
  // redaction: no finding may contain the full raw secret
  for (const f of findings) {
    assert.ok(f.match.includes('*'), `match should be redacted: ${f.match}`);
  }
});

test('clean fixture yields 0 findings and exit code 0', () => {
  const res = run([path.join(FIXTURES, 'clean'), '--json']);
  assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}\n${res.stdout}${res.stderr}`);
  const findings = JSON.parse(res.stdout);
  assert.strictEqual(findings.length, 0, `expected 0 findings, got ${findings.length}`);
});

test('--ignore skips matching files', () => {
  const res = run([path.join(FIXTURES, 'dirty'), '--json', '--ignore', '*.txt', 'config.example.js', '.env']);
  assert.strictEqual(res.status, 0, `expected exit 0 with everything ignored, got ${res.status}`);
  assert.strictEqual(JSON.parse(res.stdout).length, 0);
});

test('pretty output contains summary and redacted match', () => {
  const res = run([path.join(FIXTURES, 'dirty')]);
  assert.strictEqual(res.status, 1);
  assert.ok(/Summary:/.test(res.stdout), 'expected Summary line');
  assert.ok(/aws-access-key-id/.test(res.stdout), 'expected rule name in output');
  assert.ok(!/AKIAIOSFODNN7EXAMPLE/.test(res.stdout), 'full secret must never be printed');
});

test('env-style unquoted assignment (DB_PASSWORD=...) is detected', () => {
  const res = run([path.join(FIXTURES, 'dirty'), '--json']);
  const findings = JSON.parse(res.stdout);
  assert.ok(
    findings.some((f) => f.file === '.env' && f.rule === 'generic-secret-assignment'),
    'expected generic-secret-assignment finding in .env'
  );
});

test('lockfiles are skipped (sha512 integrity hashes are not findings)', () => {
  const res = run([path.join(FIXTURES, 'dirty'), '--json']);
  const findings = JSON.parse(res.stdout);
  assert.ok(
    !findings.some((f) => f.file === 'package-lock.json'),
    'package-lock.json must not produce findings'
  );
});

test('single-file scan works', () => {
  const res = run([path.join(FIXTURES, 'dirty', 'notes.txt'), '--json']);
  assert.strictEqual(res.status, 1);
  const findings = JSON.parse(res.stdout);
  assert.ok(findings.some((f) => f.rule === 'jwt'), 'expected jwt finding in notes.txt');
});

test('unknown option exits 2', () => {
  const res = run(['--bogus']);
  assert.strictEqual(res.status, 2);
});

test('nonexistent path exits 2', () => {
  const res = run([path.join(FIXTURES, 'no-such-dir')]);
  assert.strictEqual(res.status, 2);
});

test('--version prints version and exits 0', () => {
  const res = run(['--version']);
  assert.strictEqual(res.status, 0);
  assert.ok(/leakhound \d+\.\d+\.\d+/.test(res.stdout), `unexpected version output: ${res.stdout}`);
});

test('context word matching: "pipeline" does not trigger line-notify-token', () => {
  const { scanContent, RULES } = require('../leakhound.js');
  const token = 'Zk9x7Qw2Lm4Rt8Vb1Ny6Pc3Hd5Jf0Sg9AbCdEfGhIj1';
  const fp = scanContent(`pipelineId = "${token}"`, 'x.js', RULES, []).filter(
    (f) => f.rule === 'line-notify-token'
  );
  assert.strictEqual(fp.length, 0, 'pipeline context must not trigger LINE rule');
  const tp = scanContent(`LINE_NOTIFY_TOKEN = "${token}"`, 'x.js', RULES, []).filter(
    (f) => f.rule === 'line-notify-token'
  );
  assert.strictEqual(tp.length, 1, 'LINE context should trigger LINE rule');
});

console.log(`\n${passed} test(s) passed.`);
