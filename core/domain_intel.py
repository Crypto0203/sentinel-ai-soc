"""
domain_intel.py
----------------
Two P0 upgrades in one module:

1. Domain-age lookup via WHOIS. This is one of the single strongest
   phishing signals available and was entirely absent from the original
   pipeline. Freshly-registered domains (<30 days) sending credential or
   payment-related content should spike the risk score hard.

2. Fuzzy / homoglyph brand-impersonation detection, replacing a static
   "15+ protected brands" exact-match dictionary. A static list misses
   Micr0soft, PaypaI (capital i), Go0gle, etc. This uses:
     - Unicode confusable normalization (catches Cyrillic 'а' vs Latin 'a')
     - Levenshtein edit distance (pure-python, no C-extension dependency)
   against a configurable brand list you should keep updated.

Dependencies: python-whois (`pip install python-whois`)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

try:
    import whois as whois_lib
    _HAS_WHOIS = True
except ImportError:
    _HAS_WHOIS = False


# ---------------------------------------------------------------------------
# 1. Domain age
# ---------------------------------------------------------------------------

@dataclass
class DomainAgeResult:
    domain: str
    created: Optional[datetime]
    age_days: Optional[int]
    signal: str          # one of the scoring_engine WEIGHT_TABLE keys, or "domain_age_ok"
    note: str


def check_domain_age(domain: str) -> DomainAgeResult:
    if not _HAS_WHOIS:
        return DomainAgeResult(domain, None, None, "domain_age_lookup_failed",
                                "python-whois not installed")
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        if isinstance(created, list):  # some registrars return a list
            created = created[0]
        if created is None:
            return DomainAgeResult(domain, None, None, "domain_age_lookup_failed",
                                    "WHOIS returned no creation date (may be a privacy-shielded or new gTLD registry)")
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < 7:
            signal = "domain_age_lt_7d"
        elif age_days < 30:
            signal = "domain_age_lt_30d"
        elif age_days < 90:
            signal = "domain_age_lt_90d"
        else:
            signal = "domain_age_ok"

        return DomainAgeResult(domain, created, age_days, signal,
                                f"Domain registered {age_days} days ago ({created.date().isoformat()})")
    except Exception as exc:
        return DomainAgeResult(domain, None, None, "domain_age_lookup_failed", f"WHOIS lookup failed: {exc}")


# ---------------------------------------------------------------------------
# 2. Brand impersonation — homoglyph normalization + fuzzy match
# ---------------------------------------------------------------------------

PROTECTED_BRANDS = [
    "microsoft", "office365", "outlook", "paypal", "google", "gmail",
    "apple", "icloud", "amazon", "netflix", "chase", "bankofamerica",
    "wellsfargo", "dhl", "fedex", "docusign", "adobe", "linkedin",
    "facebook", "instagram", "hr", "payroll", "it support", "helpdesk",
]

# Common confusable-character map (extend as needed; full Unicode TR39
# confusables table is large — this covers the homoglyphs actually seen
# in the wild for Latin-script brand spoofing).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # Cyrillic
    "ı": "i", "І": "I",  # Turkish dotless / Cyrillic I
    "0": "o", "1": "l", "rn": "m",
}


def _normalize_confusables(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    for confusable, real in _CONFUSABLES.items():
        text = text.replace(confusable, real)
    return text.lower()


def _levenshtein(a: str, b: str) -> int:
    """Pure-python edit distance — avoids a C-extension dependency that
    frequently fails to build in locked-down environments."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current_row = [i]
        for j, cb in enumerate(b, 1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


@dataclass
class BrandImpersonationResult:
    matched_brand: Optional[str]
    signal: Optional[str]  # "brand_exact_display_mismatch" | "brand_fuzzy_match" | "homoglyph_domain" | None
    note: str


def check_brand_impersonation(display_name: str, sending_domain: str,
                               brands: list[str] = None,
                               fuzzy_threshold: int = 2) -> BrandImpersonationResult:
    """
    display_name: the friendly "From" name shown to the recipient
    sending_domain: the actual envelope/header domain the mail came from
    """
    brands = brands or PROTECTED_BRANDS
    normalized_display = _normalize_confusables(re.sub(r"[^a-zA-Z0-9 ]", "", display_name))
    normalized_domain = _normalize_confusables(sending_domain)

    # Homoglyph check on the DOMAIN itself (most dangerous case)
    raw_domain_lower = sending_domain.lower()
    if raw_domain_lower != normalized_domain and any(b in normalized_domain for b in brands):
        return BrandImpersonationResult(
            matched_brand=next(b for b in brands if b in normalized_domain),
            signal="homoglyph_domain",
            note=f"Sending domain '{sending_domain}' normalizes to '{normalized_domain}' after "
                 f"confusable-character folding — contains a protected brand name it does not legitimately own.",
        )

    for brand in brands:
        brand_norm = brand.replace(" ", "")
        # Exact/substring match in display name, but sending domain doesn't belong to that brand
        if brand_norm in normalized_display.replace(" ", "") and brand_norm not in normalized_domain:
            return BrandImpersonationResult(
                matched_brand=brand,
                signal="brand_exact_display_mismatch",
                note=f"Display name references '{brand}' but sends from unrelated domain "
                     f"'{sending_domain}'.",
            )

        # Fuzzy match: display name or domain is Levenshtein-close to the brand
        # but not an exact/legitimate match — catches Micr0soft, PaypaI, etc.
        for token in normalized_display.split():
            dist = _levenshtein(token, brand_norm)
            if 0 < dist <= fuzzy_threshold and token != brand_norm:
                return BrandImpersonationResult(
                    matched_brand=brand,
                    signal="brand_fuzzy_match",
                    note=f"Display-name token '{token}' is {dist} edit(s) from protected brand "
                         f"'{brand}' — likely lookalike impersonation.",
                )

    return BrandImpersonationResult(None, None, "No brand impersonation signal detected.")
