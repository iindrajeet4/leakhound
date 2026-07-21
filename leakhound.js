#!/usr/bin/env node
/**
 * leakhound — zero-dependency secret scanner for project directories.
 *
 * Concept inspired by gitleaks / truffleHog (MIT); fully independent
 * implementation with an added Thai-services rule pack.
 *
 * Usage:
 *   node leakhound.js [path] [--json] [--staged] [--ignore <pattern> [<pattern> ...]]
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = usage/runtime error.
 *
 * Requires Node.js 20+. No dependencies.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const BINARY_SNIFF_BYTES = 8192;
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'coverage',
  '.next', '.nuxt', '.svn', '.hg', '__pycache__', '.venv', 'venv',
]);
// Lockfiles are full of high-entropy integrity hashes (sha512-… base64) that
// look exactly like long bearer tokens — never real secrets, always noise.
const SKIP_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json',
  'composer.lock', 'Cargo.lock', 'Gemfile.lock', 'poetry.lock', 'go.sum',
]);
const ENTROPY_THRESHOLD = 3.5;

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
function c(color, text) {
  return useColor ? COLORS[color] + text + COLORS.reset : text;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------
// Each rule: { name, regex, entropy?: bool (apply Shannon-entropy filter to
// the captured group or full match), group?: index of the secret portion }

const RULES = [
  // --- Generic / global services ---
  {
    name: 'aws-access-key-id',
    regex: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
  },
  {
    name: 'google-api-key',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
  },
  {
    name: 'private-key-block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    name: 'jwt',
    regex: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g,
    entropy: true,
  },
  {
    name: 'slack-token',
    regex: /\bxox[abprs]-[0-9A-Za-z\-]{10,}\b/g,
  },
  {
    name: 'github-token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  {
    name: 'stripe-live-secret-key',
    regex: /\bsk_live_[0-9A-Za-z]{16,}\b/g,
  },
  {
    name: 'openai-api-key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/g,
    entropy: true,
    exclude: /^sk-ant-/, // handled by anthropic rule
  },
  {
    name: 'anthropic-api-key',
    regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
  },
  {
    name: 'generic-secret-assignment',
    // password/api_key/secret/token = high-entropy value.
    // Allows a compound name prefix (DB_PASSWORD, stripeApiKey) and
    // unquoted values (.env style: SECRET_KEY=...).
    regex:
      /\b[A-Za-z0-9_\-]*(?:password|passwd|pwd|api[_\-]?key|apikey|secret|token|auth[_\-]?key|access[_\-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{16,})["']?/gi,
    entropy: true,
    group: 1,
  },

  // --- Thai-services pack ---
  {
    name: 'line-channel-access-token',
    // Long-lived channel access tokens are long base64-ish strings ending in '='
    // padding; heuristic: 100+ chars of base64 charset with '+' or '/' present
    // (plain hex/alnum blobs like content hashes must NOT match).
    regex: /\b(?=[A-Za-z0-9]*[+/])[A-Za-z0-9+/]{100,}={0,2}(?=\s|["'`,;]|$)/g,
    entropy: true,
    heuristic: true,
  },
  {
    name: 'line-notify-token',
    // LINE Notify tokens: 43 chars, base64url-ish (service EOL'd but leaks persist).
    regex: /(?<![A-Za-z0-9_\-])(?:Bearer\s+)?([A-Za-z0-9_\-]{43})(?=\s|["'`,;]|$)/g,
    entropy: true,
    group: 1,
    heuristic: true,
    // Only flag when the line mentions LINE (as its own word: LINE_TOKEN,
    // line-notify — not "pipeline"/"inline") or Notify.
    requireContext: /(^|[^a-z])line([^a-z]|$)|notify/i,
  },
  {
    name: 'omise-live-secret-key',
    regex: /\bskey_(?:live_)?[0-9a-z]{16,}\b/g,
  },
  {
    name: 'omise-live-public-key',
    regex: /\bpkey_(?:live_)?[0-9a-z]{16,}\b/g,
  },
  {
    name: 'gbprimepay-key',
    // GB Prime Pay secret/customer/public keys: 32-hex-ish tokens near a GBP context.
    regex: /\b[0-9a-fA-F]{32,64}\b/g,
    entropy: false,
    heuristic: true,
    requireContext: /gb[\s_\-]?prime|gbprimepay|gbp[_\-]?(secret|public|customer|token|key)/i,
  },
  {
    name: 'thai-bank-api-bearer',
    // SCB / KBank open-API style bearer tokens (heuristic): long token next to
    // an SCB/KBank context keyword.
    regex: /\b[A-Za-z0-9+/_\-]{32,}={0,2}(?![A-Za-z0-9+/=_\-])/g,
    entropy: true,
    heuristic: true,
    requireContext: /\b(scb|kbank|kasikorn|siam\s*commercial|x-api-key|consumer[_\-]?(key|secret))\b/i,
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Shannon entropy (bits per character) of a string. */
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Redact a secret: keep first/last 4 chars. */
function redact(secret) {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return secret.slice(0, 4) + '*'.repeat(Math.min(secret.length - 8, 12)) + secret.slice(-4);
}

/** Detect binary content via null byte in the first 8 KB. */
function isBinary(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(BINARY_SNIFF_BYTES);
    const bytesRead = fs.readSync(fd, buf, 0, BINARY_SNIFF_BYTES, 0);
    for (let i = 0; i < bytesRead; i++) {
      if (buf[i] === 0) return true;
    }
    return false;
  } catch {
    return true; // unreadable — treat as skip
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Convert a glob-ish pattern (*, **, ?) to a RegExp matched against a
 *  forward-slash relative path. A bare name also matches any path segment. */
function globToRegExp(pattern) {
  const norm = pattern.replace(/\\/g, '/');
  let re = '';
  for (let i = 0; i < norm.length; i++) {
    const ch = norm[i];
    if (ch === '*') {
      if (norm[i + 1] === '*') {
        re += '.*';
        i++;
        if (norm[i + 1] === '/') i++;
      } else {
        re += '[^/]*';
      }
    } else if (ch === '?') {
      re += '[^/]';
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  // Match full relative path, or as a path segment anywhere.
  return new RegExp(`(^|/)${re}($|/)`);
}

// ---------------------------------------------------------------------------
// Config (.leakhoundrc.json)
// ---------------------------------------------------------------------------

function loadConfig(rootDir) {
  const rcPath = path.join(rootDir, '.leakhoundrc.json');
  const config = { extraRules: [], allowlist: [], ignoredPaths: [] };
  if (!fs.existsSync(rcPath)) return config;
  try {
    const raw = JSON.parse(fs.readFileSync(rcPath, 'utf8'));
    for (const r of raw.rules || []) {
      if (r.name && r.regex) {
        config.extraRules.push({ name: r.name, regex: new RegExp(r.regex, 'g'), custom: true });
      }
    }
    for (const a of raw.allowlist || []) config.allowlist.push(new RegExp(a));
    for (const p of raw.ignore || raw.ignoredPaths || []) config.ignoredPaths.push(p);
  } catch (err) {
    process.stderr.write(c('yellow', `warning: could not parse .leakhoundrc.json: ${err.message}\n`));
  }
  return config;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

function scanContent(content, relPath, rules, allowlist) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  for (let lineNo = 0; lineNo < lines.length; lineNo++) {
    const line = lines[lineNo];
    if (line.length > 10000) continue; // pathological minified line — skip
    if (/leakhound:ignore/i.test(line)) continue;
    for (const rule of rules) {
      if (rule.requireContext && !rule.requireContext.test(line)) continue;
      rule.regex.lastIndex = 0;
      let m;
      while ((m = rule.regex.exec(line)) !== null) {
        const secret = rule.group ? m[rule.group] : m[0];
        if (!secret) continue;
        if (rule.exclude && rule.exclude.test(m[0])) continue;
        if (rule.entropy && shannonEntropy(secret) < ENTROPY_THRESHOLD) continue;
        if (allowlist.some((re) => re.test(secret) || re.test(m[0]))) continue;
        findings.push({
          file: relPath,
          line: lineNo + 1,
          rule: rule.name,
          heuristic: !!rule.heuristic,
          match: redact(secret),
        });
        if (rule.regex.lastIndex === m.index) rule.regex.lastIndex++; // safety
      }
    }
  }
  return findings;
}

function shouldScanFile(absPath) {
  let stat;
  try {
    stat = fs.statSync(absPath);
  } catch {
    return false;
  }
  if (!stat.isFile()) return false;
  if (SKIP_FILES.has(path.basename(absPath))) return false;
  if (stat.size === 0 || stat.size > MAX_FILE_SIZE) return false;
  if (isBinary(absPath)) return false;
  return true;
}

function* walk(dir, rootDir, ignoreMatchers) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    const rel = path.relative(rootDir, abs).replace(/\\/g, '/');
    if (ignoreMatchers.some((re) => re.test(rel))) continue;
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(abs, rootDir, ignoreMatchers);
    } else if (entry.isFile()) {
      yield { abs, rel };
    }
  }
}

function stagedFiles(rootDir) {
  // core.quotepath=off: keep non-ASCII filenames as-is instead of
  // backslash-escaped octal quoting.
  const res = spawnSync('git', ['-c', 'core.quotepath=off', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'], {
    cwd: rootDir,
    encoding: 'utf8',
  });
  if (res.error || res.status !== 0) {
    return null; // not a git repo / git missing
  }
  return res.stdout
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((rel) => ({ abs: path.join(rootDir, rel), rel: rel.replace(/\\/g, '/') }));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { path: '.', json: false, staged: false, ignore: [] };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '--json') {
      opts.json = true;
    } else if (a === '--staged') {
      opts.staged = true;
    } else if (a === '--ignore') {
      i++;
      while (i < argv.length && !argv[i].startsWith('--')) {
        opts.ignore.push(argv[i]);
        i++;
      }
      continue;
    } else if (a === '--help' || a === '-h') {
      opts.help = true;
    } else if (a === '--version' || a === '-v') {
      opts.version = true;
    } else if (a.startsWith('--')) {
      process.stderr.write(`unknown option: ${a}\n`);
      process.exit(2);
    } else {
      opts.path = a;
    }
    i++;
  }
  return opts;
}

const HELP = `leakhound — scan a directory for accidentally committed secrets

Usage: leakhound [path] [--json] [--staged] [--ignore <pattern> ...]

  path          directory (or single file) to scan (default: current directory)
  --json        machine-readable JSON output
  --staged      scan only git staged files (git diff --cached)
  --ignore      glob-ish patterns to skip (e.g. "*.min.js" "docs/**");
                consumes every following argument up to the next --flag,
                so put the path before it
  -v, --version print version and exit
  -h, --help    show this help

Skipped automatically: node_modules, .git, dist, build, vendor, coverage,
lockfiles, binary files, and files over 1 MB. Set NO_COLOR to disable color.

Config: .leakhoundrc.json in the scan root may define
  { "rules": [{"name": "...", "regex": "..."}], "allowlist": ["regex"], "ignore": ["pattern"] }

Exit codes: 0 clean, 1 findings, 2 error.`;

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`leakhound ${require('./package.json').version}\n`);
    return 0;
  }

  const target = path.resolve(opts.path);
  let targetStat;
  try {
    targetStat = fs.statSync(target);
  } catch {
    process.stderr.write(c('red', `error: no such file or directory: ${target}\n`));
    return 2;
  }
  const singleFile = targetStat.isFile();
  const rootDir = singleFile ? path.dirname(target) : target;

  const config = loadConfig(rootDir);
  const rules = [...RULES, ...config.extraRules];
  const ignoreMatchers = [...opts.ignore, ...config.ignoredPaths].map(globToRegExp);

  let files;
  if (singleFile) {
    files = [{ abs: target, rel: path.basename(target) }];
  } else if (opts.staged) {
    files = stagedFiles(rootDir);
    if (files === null) {
      process.stderr.write(
        c('yellow', 'leakhound: --staged requires a git repository (git not found or not a repo); nothing scanned.\n')
      );
      return 0;
    }
    files = files.filter(
      (f) => !ignoreMatchers.some((re) => re.test(f.rel)) && !f.rel.split('/').some((seg) => SKIP_DIRS.has(seg))
    );
  } else {
    files = [...walk(rootDir, rootDir, ignoreMatchers)];
  }

  const findings = [];
  let scanned = 0;
  for (const { abs, rel } of files) {
    if (rel === '.leakhoundrc.json') continue;
    if (!shouldScanFile(abs)) continue;
    scanned++;
    let content;
    try {
      content = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    if (content.charCodeAt(0) === 0xfeff) content = content.slice(1); // strip UTF-8 BOM
    findings.push(...scanContent(content, rel, rules, config.allowlist));
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(findings, null, 2) + '\n');
  } else {
    if (findings.length === 0) {
      process.stdout.write(c('green', `✔ leakhound: no secrets found (${scanned} files scanned)\n`));
    } else {
      process.stdout.write(c('bold', `\nleakhound found ${findings.length} potential secret(s):\n\n`));
      for (const f of findings) {
        const loc = c('cyan', `${f.file}:${f.line}`);
        const rule = c('magenta', f.rule) + (f.heuristic ? c('dim', ' (heuristic)') : '');
        process.stdout.write(`  ${c('red', '✖')} ${loc}  ${rule}\n      ${c('yellow', f.match)}\n`);
      }
      const heuristicCount = findings.filter((f) => f.heuristic).length;
      const files_ = new Set(findings.map((f) => f.file)).size;
      process.stdout.write(
        `\n${c('bold', 'Summary:')} ${c('red', String(findings.length))} finding(s)` +
          (heuristicCount ? ` (${heuristicCount} heuristic)` : '') +
          ` in ${files_} file(s), ${scanned} scanned.\n`
      );
      process.stdout.write(c('dim', 'Add `leakhound:ignore` on a line, or allowlist in .leakhoundrc.json, to suppress.\n'));
    }
  }

  return findings.length > 0 ? 1 : 0;
}

if (require.main === module) {
  process.exit(main());
}

module.exports = { scanContent, shannonEntropy, redact, RULES, globToRegExp };
