# Phish-Guard (Starter)

Windows-first, Python-only (no Docker required to start). This starter lets you run a **dynamic URL analyzer** that:
- Opens a URL in headless Chromium (Playwright)
- Captures redirect chain, final URL, HTML hash
- Detects outbound POST with PII-like patterns
- Checks simple page signals (external form actions, favicon mismatch)
- Extracts TLS leaf certificate fingerprint
- Produces a **JSON report** with a simple rule-based score

## 0) Prereqs (Windows)
- Python 3.11+
- PowerShell: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` (if needed)

## 1) Install
```powershell
cd phish-guard
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m playwright install chromium
```

## 2) Run
```powershell
python -m analyzer.run https://example.com
```

Outputs a JSON like:
```json
{
  "evidence": { ... },
  "risk_score": 42,
  "label": "suspicious",
  "reasons": [{"feature": "...", "score": 12}]
}
```

## 3) Notes
- Downloads are **immediately cancelled** in the analyzer.
- Timeouts are short (20s) so extremely slow sites may be partial.
- This is a minimal MVP; next steps: server dual-path compare, USB token sign, reputation feeds.
