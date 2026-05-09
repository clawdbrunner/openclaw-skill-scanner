#!/usr/bin/env python3
"""Scan skill text files for prompt injection patterns using PromptGuard."""

import sys
import os

# Add prompt-guard skill to path
sys.path.insert(0, os.path.expanduser("~/clawd/skills/prompt-guard/scripts"))

from detect import PromptGuard, Severity

TEXT_EXTENSIONS = {".md", ".txt", ".sh", ".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}

def scan_directory(directory):
    guard = PromptGuard()
    findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if not content.strip():
                    continue
                files_scanned += 1
                result = guard.analyze(content)
                if result.severity.value >= Severity.HIGH.value:
                    rel_path = os.path.relpath(fpath, directory)
                    findings.append({
                        "file": rel_path,
                        "severity": result.severity.name,
                        "reasons": result.reasons[:5],  # Top 5 reasons
                    })
            except Exception:
                continue

    # Output results
    print(f"FILES_SCANNED={files_scanned}")
    if findings:
        print(f"FINDINGS={len(findings)}")
        for f in findings:
            print(f"FINDING\t{f['severity']}\t{f['file']}\t{','.join(f['reasons'])}")
    else:
        print("FINDINGS=0")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: scan-prompt-injection.py <directory>", file=sys.stderr)
        sys.exit(1)
    scan_directory(sys.argv[1])
