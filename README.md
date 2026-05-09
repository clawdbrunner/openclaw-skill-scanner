# 🔍 OpenClaw Skill Scanner

A security scanner for AI agent skills that performs **5-layer defense-in-depth** verification — from remote threat databases to ML-powered prompt injection detection.

Designed for [OpenClaw](https://github.com/openclaw/openclaw) but works with any skill/plugin system — [Hermes Agent](https://github.com/HermesAgent), custom harnesses, or plain directories of scripts. If it's a folder of files an AI agent might execute, this scanner can check it.

## What It Does

Scans skill/plugin folders for malicious patterns before you install or execute them. Works with OpenClaw skills, Hermes Agent plugins, or any directory of agent-executable code.

| # | Layer | What It Catches |
|---|-------|----------------|
| 1 | **Clawdex Remote Check** | Known malicious skills via [Clawdex](https://clawdex.koi.security) database |
| 2 | **Local Pattern Scan** | Malware delivery patterns (base64, curl\|bash, gatekeeper bypass, etc.) |
| 3 | **VirusTotal** | 70+ AV engine scans via hash lookup |
| 4 | **ClamAV** | Local malware signature scanning |
| 5 | **ML Injection Scan** | Prompt injection detection via [Meta's Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) |

All layers gracefully skip if their dependencies aren't available. The scanner always completes.

## Installation

```bash
# Clone the repo
git clone https://github.com/clawdbrunner/openclaw-skill-scanner.git
cd openclaw-skill-scanner

# Make executable and link to PATH
chmod +x scan-skill.sh scan-llamafirewall.py
ln -s $(pwd)/scan-skill.sh /usr/local/bin/scan-skill
```

Or download directly:

```bash
curl -O https://raw.githubusercontent.com/clawdbrunner/openclaw-skill-scanner/main/scan-skill.sh
chmod +x scan-skill.sh
```

## Usage

### Scan a single skill

```bash
scan-skill /path/to/skill/folder
```

### Scan all local skills

```bash
scan-skill --all
```

Scans both bundled skills and custom skills (`~/clawd/skills`).

### Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanning: my-new-skill
Path: /path/to/my-new-skill
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Checking Clawdex database...
✅ Clawdex: Benign

🔍 VirusTotal: Scanning suspicious files...
   ✅ install.sh: Clean
   ✅ helper.py: Clean

🔍 ClamAV: Scanning for malware...
   ✅ No malware detected

🔍 ML Scan: Scanning text files for injection patterns...
   Scanned 8 text files
   ✅ No injection patterns detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ RESULT: PASSED
   Clawdex: Checked
   Local scan: No red flags detected
   VirusTotal: Checked (2 files)
   ClamAV: Clean
   ML Scan: Clean
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Optional Integrations

### VirusTotal

Checks file hashes against VirusTotal's database (70+ AV engines).

```bash
# Option 1: Environment variable
export VIRUSTOTAL_API_KEY="your-api-key-here"

# Option 2: Config file
mkdir -p ~/.config/openclaw-skill-scanner
echo "your-api-key-here" > ~/.config/openclaw-skill-scanner/virustotal.key
```

Get a free API key at https://www.virustotal.com/gui/join-us.

Rate limits: 4 requests/minute (free tier), max 10 files per scan. Skipped if no API key is configured.

### ClamAV

Local malware signature scanning via `clamscan`.

Install ClamAV:
```bash
# macOS
brew install clamav
# Update definitions
freshclam
```

Skipped if `clamscan` is not found.

### ML Injection Scan

Uses [Meta's Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) to detect prompt injection patterns in skill text files. Catches social engineering, instruction manipulation, and novel injection techniques that pattern matching misses.

Requirements:
- Python 3 with `transformers` and `torch` installed
- HuggingFace access to `meta-llama/Llama-Prompt-Guard-2-86M` (gated model — request access on HuggingFace)

Setup:
```bash
pip install transformers torch
# Save your HF token
mkdir -p ~/.config/huggingface
echo "your-hf-token" > ~/.config/huggingface/token
```

Skipped if Python, dependencies, or the helper script aren't available.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ✅ Passed — All layers clean |
| `1` | ⚠️ Failed — Critical or warning issues found |
| `2` | 🚨 Blocked — Skill flagged as malicious by Clawdex |

## Scan Flow

```
1. Clawdex Remote Check
   ├── "malicious" → EXIT 2 (blocked immediately)
   ├── "benign" → continue
   └── unknown/error → continue with warning

2. Local Pattern Scan
   └── Flags critical/warning patterns (malware delivery, obfuscation)

3. VirusTotal (if API key configured)
   ├── Hash lookup for suspicious files
   ├── Upload unknown files for analysis
   └── Report malicious/suspicious detections

4. ClamAV (if installed)
   ├── clamscan --infected --recursive
   └── Report infected files

5. ML Injection Scan (if dependencies available)
   ├── Scan text files with Llama-Prompt-Guard-2-86M
   └── Flag files with injection probability ≥ 0.7

6. Summary → Exit 0, 1, or 2
```

### Defense in Depth

Every layer runs independently. Even if Clawdex reports "benign", all subsequent layers still execute. This catches:
- New threats not yet in Clawdex
- Supply chain attacks (skill updated after Clawdex review)
- Novel prompt injections that pattern matching misses

### Fail-Open Design

Missing dependencies (ClamAV, Python, API keys) produce warnings, not errors. The scanner always completes with whatever layers are available.

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
| ML injection score ≥ 0.9 | Likely prompt injection attack |

### ⚠️ Warnings (Manual Review)

| Pattern | Why It's Suspicious |
|---------|-------------------|
| ZIP downloads | Common malware delivery |
| GitHub releases | Can host unsigned binaries |
| `chmod +x` on downloads | Making untrusted code executable |
| "CRITICAL" warnings | Social engineering tactics |
| Password-protected archives | Hides content from scanning |
| ML injection score ≥ 0.7 | Possible prompt injection |

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
- [Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) — Meta's prompt injection classifier
- [Open Source Malware blog post](https://opensourcemalware.com/blog/clawdbot-skills-ganked-your-crypto) — Details on the original attack
