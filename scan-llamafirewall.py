#!/usr/bin/env python3
"""Scan skill text files for prompt injection using DeBERTa classifier.

Uses protectai/deberta-v3-base-prompt-injection (public, no HF auth needed).
"""

import sys
import os

TEXT_EXTENSIONS = {".md", ".txt", ".sh", ".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml"}


def load_model():
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch

        model_name = "protectai/deberta-v3-base-prompt-injection"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        model.eval()
        return tokenizer, model
    except Exception as e:
        print(f"ERROR=model_load_failed: {e}")
        sys.exit(1)


def predict(text, tokenizer, model):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    import torch
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)
    return probs[0][1].item()  # injection probability


def scan_directory(directory):
    tokenizer, model = load_model()
    findings = []
    files_scanned = 0

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(65536)  # Cap at 64KB
                if not content.strip():
                    continue
                files_scanned += 1
                score = predict(content, tokenizer, model)
                if score >= 0.7:
                    rel_path = os.path.relpath(fpath, directory)
                    severity = "CRITICAL" if score >= 0.9 else "HIGH"
                    findings.append({
                        "file": rel_path,
                        "severity": severity,
                        "score": score,
                    })
            except Exception:
                continue

    # Output for bash parsing
    print(f"FILES_SCANNED={files_scanned}")
    if findings:
        print(f"FINDINGS={len(findings)}")
        for f in findings:
            print(f"FINDING\t{f['severity']}\t{f['file']}\tscore={f['score']:.4f}")
    else:
        print("FINDINGS=0")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: scan-llamafirewall.py <directory>", file=sys.stderr)
        sys.exit(1)
    scan_directory(sys.argv[1])
