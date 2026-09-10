# Forensics Engine — Pro-Level Upgrade

This package adds five new modules that close the P0 gaps identified in review,
without replacing your existing `core/forensics_engine.py`, `database.py`,
`studio_app.py`, or `forensics.js` — it's designed to sit alongside them.

## What's new

| Module | Fixes |
|---|---|
| `core/scoring_engine.py` | Replaces undocumented additive scoring with a transparent, tunable weight table. Every point is traceable to a named signal + reason string. |
| `core/dns_verify.py` | **Closes the biggest gap**: your original Stage 3 trusted whatever `Authentication-Results` header showed up in the email. That header is attacker-forgeable unless you can prove it was stamped by your own MTA. This module independently re-derives SPF (DNS TXT + IP match), DKIM (via `dkimpy` if installed, else structural check), and DMARC (with strict/relaxed alignment) from scratch. |
| `core/domain_intel.py` | Adds WHOIS domain-age lookup (one of the single strongest phishing signals — freshly-registered domains are a huge tell) and fuzzy/homoglyph brand-impersonation detection to replace the static "15+ brand" exact-match dictionary, which misses `Micr0soft`, `PaypaI`, Cyrillic lookalikes, etc. |
| `core/url_safety.py` | SSRF-safe redirect-chain resolution. If you ever fetch attacker-controlled URLs (to follow redirects or feed a headless-browser detonation sandbox), your scanner itself becomes an SSRF vector against your own infrastructure (cloud metadata endpoint, internal services). This validates every IP in the chain, including DNS-rebinding attempts. Also catches "displayed domain ≠ final landing domain" after redirects. |
| `core/attachment_scanner.py` | Was completely absent from the original pipeline. Detects macro-enabled Office docs (by extension *and* by inspecting the ZIP for `vbaProject.bin`, catching mislabeled files), executables/scripts (by extension *and* magic-byte signature, catching renamed payloads), and nested/password-protected archives. Hashes every attachment (SHA256) for future VirusTotal/MalwareBazaar lookups. |
| `core/forensics_engine_v2.py` | Orchestrator — wires all of the above into a single `analyze_email()` call that outputs the same JSON schema as your Master Forensic AI Prompt. |

## Install

```bash
pip install dnspython python-whois requests
# optional, for full cryptographic DKIM verification instead of the structural fallback:
pip install dkimpy
# optional, for deep VBA macro extraction from legacy .doc/.xls (see TODO in attachment_scanner.py):
pip install oletools
```

## Integrate into `studio_app.py`

```python
from core.forensics_engine_v2 import analyze_email

@app.route("/api/forensics/analyze", methods=["POST"])
def analyze():
    raw = request.get_data()
    result = analyze_email(
        raw,
        our_authserv_id=app.config.get("AUTHSERV_ID"),   # set this to your MTA's authserv-id if you want to trust inbound A-R headers from it
        trust_inbound_auth_results=False,                # keep False unless you've configured our_authserv_id correctly — see dns_verify.py docstring
    )
    return jsonify(result)
```

The output schema matches what `static/js/forensics.js` already expects
(`risk_score_100`, `verdict`, `confidence_score`, `forensic_evidence`,
`authentication`, `primary_attack_vector`, `why_it_is_spam_explanation`,
`soc_recommended_actions`), plus a new `attachments_scanned` array.

## What still needs your environment / API keys (not included)

These were flagged in review as high-value but couldn't be meaningfully
implemented without your infrastructure:

- **AbuseIPDB / VirusTotal / URLhaus lookups** — need your own API keys and
  rate-limit-aware caching (Redis recommended). Wire these in as additional
  `scoring.add(...)` calls inside `forensics_engine_v2.py` once you have keys.
- **Sandboxed URL detonation with a headless browser** (Playwright) —
  `url_safety.py` does SSRF-safe redirect *resolution*, but a real
  screenshot/rendered-DOM capture needs an isolated container with no route
  to your internal network. Point it at the same `validate_url_safe()`
  gate before every navigation.
- **QR/quishing scanner** — needs `pyzbar` + `Pillow` and image attachments
  from Stage 6; not included here since it's a separate detection surface
  from email headers/body.
- **ML/Bayesian text scoring** — train against a labeled corpus (SpamAssassin
  public corpus + Nazario phishing corpus are good free starting points) and
  validate precision/recall before wiring a score into `WEIGHT_TABLE` — an
  uncalibrated model will hurt more than it helps.
- **BIMI/VMC verification** — straightforward DNS TXT lookup on
  `default._bimi.<domain>` plus certificate validation against a VMC CA;
  can be added to `dns_verify.py` following the same pattern as `evaluate_dmarc`.

## Testing

Both `dns_verify.py` and `domain_intel.py` need outbound DNS/WHOIS to fully
exercise — run `analyze_email(raw, do_live_lookups=False)` to test the
offline detectors (brand impersonation, attachment scanning, BEC language,
URL pattern checks) without network access, then flip `do_live_lookups=True`
in your real environment for the full pipeline.

Tune `WEIGHT_TABLE` in `scoring_engine.py` against your existing
`test_cyber_forensics.py` corpus, then extend that corpus with real labeled
samples (PhishTank, your own quarantine history) and track precision/recall
per release — "does it still flag these 5 known attacks" isn't the same as
"what's the false-positive rate on 10,000 real emails."
