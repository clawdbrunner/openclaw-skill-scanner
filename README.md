# 🔍 OpenClaw Skill Scanner

A security scanner for [OpenClaw](https://github.com/openclaw/openclaw) (formerly Clawdbot/Moltbot) skills that performs **defense-in-depth** verification using both remote (Clawdex) and local pattern analysis.

## What It Does

This tool scans skill folders for malicious patterns before you install or execute them. It combines:

1. **Remote Check (Clawdex)** — Queries the [Clawdex security database](https://clawdex.koi.security) for known malicious skills
2. **Local Scan** — Deep pattern analysis for:
   - Base64-encoded commands
   - Curl-to-bash pipes
   - Gatekeeper bypasses (`xattr -c`)
   - Raw IP downloads
   - Known malicious filenames
   - Suspicious ZIP/password patterns

## Installation

```bash
# Clone the repo
git clone https://github.com/chrisbrunner/openclaw-skill-scanner.git
cd openclaw-skill-scanner

# Make executable and move to your PATH
chmod +x scan-skill.sh
sudo mv scan-skill.sh /usr/local/bin/scan-skill
```

Or just download the script directly:

```bash
curl -O https://raw.githubusercontent.com/chrisbrunner/openclaw-skill-scanner/main/scan-skill.sh
chmod +x scan-skill.sh
```

## Usage

### Scan a single skill

```bash
scan-skill /path/to/skill/folder
```

Example:
```bash
scan-skill ~/clawd/skills/my-new-skill
```

### Scan all local skills

```bash
scan-skill --all
```

This scans both bundled skills (`/opt/homebrew/lib/node_modules/clawdbot/skills`) and custom skills (`~/clawd/skills`).

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ✅ Passed — Clawdex + local scan both clean |
| `1` | ⚠️ Failed — Critical issues found in local scan |
| `2` | 🚨 Blocked — Skill flagged as malicious by Clawdex |

## How It Works

### Scan Flow

```
1. Query Clawdex API (https://clawdex.koi.security/api/skill/{name})
   ├── "malicious" → EXIT 2 (blocked immediately)
   ├── "benign" → continue to step 2
   └── unknown/error → continue to step 2 (with warning)

2. Local deep scan (pattern matching)
   └── Exit 0 or 1 based on findings
```

### Defense in Depth

Even if Clawdex reports "benign", the local scan **always runs**. This catches:
- New threats not yet in Clawdex
- Supply chain attacks (skill updated after Clawdex review)
- False negatives from remote scanning

### Fail-Open Design

If Clawdex is down or returns an error, the script falls back to local scanning with a warning. This ensures skills can still be scanned even without internet connectivity.

## What Gets Flagged

### 🚨 Critical (Immediate Block)

| Pattern | Why It's Dangerous |
|---------|-------------------|
| `base64 -d` + execute | Obfuscated malicious code |
| `curl \| bash` | Remote code execution |
| `xattr -c` | Disables macOS security (Gatekeeper bypass) |
| Raw IP addresses | Bypasses DNS security |
| Known malicious IPs | Previously identified threats |
| Known malicious filenames | Documented malware |

### ⚠️ Warnings (Manual Review)

| Pattern | Why It's Suspicious |
|---------|-------------------|
| ZIP downloads | Common malware delivery |
| GitHub releases | Can host unsigned binaries |
| `chmod +x` on downloads | Making untrusted code executable |
| "CRITICAL" warnings | Social engineering tactics |
| Password-protected archives | Hides content from scanning |

## Background

This tool was created after [14 malicious skills were published to Clawdbot Hub](https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto) targeting cryptocurrency users in January 2026. These skills used social engineering to trick AI agents into executing malware.

## Contributing

Issues and PRs welcome! Particularly interested in:

- Additional malicious patterns
- Better output formatting
- Integration with CI/CD pipelines
- Support for other AI agent platforms

## License

MIT — Use at your own risk. This tool provides best-effort detection, not a guarantee of safety. Always review skills manually before use.

## Related

- [OpenClaw](https://github.com/openclaw/openclaw) — The AI agent platform
- [Clawdex](https://clawdex.koi.security) — Security database for AI agent skills
- [Open Source Malware blog post](https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto) — Details on the original attack
