# leakhound

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20deps-zero-blue.svg)](#)
[![Node](https://img.shields.io/badge/node-%3E%3D%2020-brightgreen.svg)](#)

Zero-dependency Node.js CLI that scans a project directory for accidentally
committed secrets — API keys, tokens, private keys — with an extra rule pack
for popular Thai services (LINE, Omise, GB Prime Pay, Thai bank open APIs).

- **No dependencies.** Node.js 20+ only.
- **CI-friendly.** Exit code `1` when secrets are found, `0` when clean.
- **Low noise.** Shannon-entropy filtering (threshold ~3.5) on generic rules,
  inline `leakhound:ignore` comments, and an allowlist config.

> Inspired by [gitleaks](https://github.com/gitleaks/gitleaks) and
> truffleHog concepts; this is a fully independent implementation. MIT licensed.

## Install / Usage

Run directly from GitHub — no install needed:

```bash
npx github:iindrajeet4/leakhound            # scan the current directory
npx github:iindrajeet4/leakhound ./my-project --json
```

```bash
# run directly
node leakhound.js [path] [--json] [--staged] [--ignore <pattern> ...]

# or install globally
npm install -g .
leakhound ./my-project
```

| Flag | Description |
|------|-------------|
| `path` | Directory **or single file** to scan (default: `.`) |
| `--json` | Machine-readable JSON array output |
| `--staged` | Scan only git staged files (`git diff --cached`) |
| `--ignore` | Glob-ish patterns to skip, e.g. `--ignore "*.min.js" "docs/**"` — consumes all following args until the next `--flag`, so put the path first |
| `-v`, `--version` | Print version |
| `-h`, `--help` | Show help |

Skipped automatically: `node_modules`, `.git`, `dist`, `build`, `vendor`,
`coverage`, `.next`, `__pycache__`, virtualenvs, lockfiles
(`package-lock.json`, `yarn.lock`, `go.sum`, …), binary files (null byte in
the first 8 KB), and files larger than 1 MB. Set `NO_COLOR=1` to disable
colored output.

### Example output

```
leakhound found 3 potential secret(s):

  ✖ config.js:3  aws-access-key-id
      AKIA************MPLE
  ✖ .env:2  generic-secret-assignment
      Zk9x************0Sg9
  ✖ notes.txt:7  private-key-block
      ----************----

Summary: 3 finding(s) in 3 file(s), 42 scanned.
```

Matches are always **redacted** (first/last 4 characters only) — leakhound
never prints the full secret.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | One or more potential secrets found |
| `2` | Usage or runtime error (bad flag, path not found) |

## Rules

| Rule | Detects | Notes |
|------|---------|-------|
| `aws-access-key-id` | `AKIA`/`ASIA`/… + 16 chars | |
| `google-api-key` | `AIza...` (39 chars) | |
| `private-key-block` | `-----BEGIN ... PRIVATE KEY-----` | RSA/EC/DSA/OpenSSH/PGP |
| `jwt` | `eyJ...` three-part tokens | entropy-filtered |
| `slack-token` | `xoxb-`, `xoxp-`, `xoxa-`, … | |
| `github-token` | `ghp_`, `gho_`, `ghs_`, `github_pat_` | |
| `stripe-live-secret-key` | `sk_live_...` | |
| `openai-api-key` | `sk-...` / `sk-proj-...` | entropy-filtered |
| `anthropic-api-key` | `sk-ant-...` | |
| `generic-secret-assignment` | `password/api_key/secret/token = "..."` incl. compound names (`DB_PASSWORD`) and unquoted `.env`-style values | entropy-filtered |
| `line-channel-access-token` | long base64 LINE Messaging API tokens | heuristic |
| `line-notify-token` | 43-char LINE Notify tokens | heuristic, needs LINE context on line |
| `omise-live-secret-key` | `skey_live_...` | |
| `omise-live-public-key` | `pkey_live_...` | |
| `gbprimepay-key` | 32–64 hex keys near GB Prime Pay context | heuristic |
| `thai-bank-api-bearer` | long tokens near SCB/KBank/consumer-key context | heuristic |

Rules marked **heuristic** rely on nearby context keywords and entropy —
review their findings manually before acting.

Suppress a single line by adding a `leakhound:ignore` comment on it.

## Configuration — `.leakhoundrc.json`

Place in the scan root:

```json
{
  "rules": [
    { "name": "my-internal-token", "regex": "\\bmyco_[A-Za-z0-9]{32}\\b" }
  ],
  "allowlist": ["EXAMPLE", "FAKE"],
  "ignore": ["test/fixtures/**", "*.snap"]
}
```

## Pre-commit hook

`.git/hooks/pre-commit` (make it executable):

```bash
#!/bin/sh
node ./leakhound.js --staged || {
  echo "leakhound: potential secret staged — commit blocked."
  exit 1
}
```

## GitHub Actions

```yaml
name: leakhound
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: node leakhound.js . --json
```

## Tests

```bash
node test/test.js
```

Fixtures contain **clearly fake** example secrets (e.g. the AWS docs key
`AKIAIOSFODNN7EXAMPLE`) — none are real credentials.

---

## การใช้งาน (Thai)

leakhound เป็นเครื่องมือสแกนหา secret (API key, token, private key)
ที่เผลอ commit ลงในโปรเจกต์ — ไม่ต้องติดตั้ง dependency ใด ๆ ใช้ Node.js 20 ขึ้นไป

```bash
node leakhound.js ./โฟลเดอร์โปรเจกต์          # สแกนทั้งโฟลเดอร์
node leakhound.js --staged                    # สแกนเฉพาะไฟล์ที่ git stage ไว้
node leakhound.js . --json                    # ผลลัพธ์แบบ JSON สำหรับ CI
```

มีชุดกฎสำหรับบริการไทยโดยเฉพาะ เช่น LINE channel access token,
LINE Notify token, Omise (`skey_live_` / `pkey_live_`), GB Prime Pay
และ token สไตล์ API ของธนาคาร (SCB/KBank) — กฎกลุ่มนี้เป็นแบบ heuristic
ควรตรวจสอบผลด้วยตนเองอีกครั้ง

ถ้าพบ secret โปรแกรมจะจบด้วย exit code `1` (ใช้บล็อก commit หรือ fail CI ได้)
ตั้งค่าเพิ่มเติมได้ที่ไฟล์ `.leakhoundrc.json`

## License

MIT © 2026 Indrajeet D. Inspired by gitleaks/truffleHog concepts;
independent implementation.

---

## 💼 Services & custom work

I take on freelance and contract work around this project — custom implementation,
new features, and integration with your stack.

**Contact:** [GitHub @iindrajeet4](https://github.com/iindrajeet4) (opening an issue on this repo works too) · [DubeGames](https://dubegames.indrajeetdubeyy.workers.dev/)
