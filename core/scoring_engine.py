"""
scoring_engine.py
------------------
Replaces ad-hoc additive scoring with a documented, tunable weight matrix.

Why this exists (per senior-review feedback):
  - Undocumented additive scoring is undebuggable: nobody can explain why a
    given email scored 63 vs 71, so false positives can't be triaged.
  - This module makes every point auditable: each signal has a name, a
    weight, a max contribution cap, and a human-readable reason string that
    flows straight into `forensic_evidence` in the output JSON.
  - Weights live in one place (WEIGHT_TABLE) so they can be tuned against a
    labeled test corpus without touching pipeline code.

Usage:
    engine = ScoringEngine()
    engine.add("dmarc_fail", reason="DMARC alignment failed (p=reject)")
    engine.add("domain_age_lt_30d", reason="Sending domain registered 4 days ago")
    result = engine.finalize()
    # result -> {"risk_score_100": 87, "verdict": "MALICIOUS", "confidence_score": 0.91,
    #            "forensic_evidence": [...]}
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Weight table: single source of truth for scoring.
# severity is surfaced to the analyst; weight is the actual point contribution.
# Tune these against test_cyber_forensics.py + a labeled corpus (see README).
# ---------------------------------------------------------------------------
WEIGHT_TABLE = {
    # --- Authentication (Stage 3) ---
    "spf_fail":                 (25, "CRITICAL"),
    "spf_softfail":              (8, "MEDIUM"),
    "dkim_fail":                 (20, "HIGH"),
    "dkim_missing":              (10, "MEDIUM"),
    "dmarc_fail_reject":         (30, "CRITICAL"),
    "dmarc_fail_quarantine":     (18, "HIGH"),
    "dmarc_alignment_relaxed_only": (6, "MEDIUM"),
    "auth_results_untrusted":    (15, "HIGH"),  # A-R header present but not from our trust boundary

    # --- Identity / brand impersonation (Stage 2) ---
    "brand_exact_display_mismatch": (25, "CRITICAL"),
    "brand_fuzzy_match":          (18, "HIGH"),   # Levenshtein-close to a protected brand
    "subject_brand_impersonation":(22, "HIGH"),
    "homoglyph_domain":           (28, "CRITICAL"),
    "punycode_domain":            (15, "HIGH"),

    # --- Routing / reputation (Stage 4) ---
    "envelope_alignment_fail":    (20, "HIGH"),
    "suspicious_tld":             (15, "HIGH"),
    "reply_to_mismatch":          (12, "MEDIUM"),
    "hop_count_anomaly":           (6, "LOW"),
    "sender_ip_no_ptr":             (5, "LOW"),

    # --- Domain intelligence (new) ---
    "domain_age_lt_7d":           (30, "CRITICAL"),
    "domain_age_lt_30d":          (18, "HIGH"),
    "domain_age_lt_90d":           (8, "MEDIUM"),
    "domain_age_lookup_failed":     (2, "LOW"),

    # --- Payload / links (Stage 6) ---
    "url_raw_ip":                 (15, "HIGH"),
    "url_open_redirect":          (10, "MEDIUM"),
    "url_free_hosting":            (8, "MEDIUM"),
    "url_final_domain_mismatch":  (20, "HIGH"),  # redirect chain lands on a different domain than shown

    # --- BEC / financial fraud language ---
    "bec_urgency_language":        (10, "MEDIUM"),
    "bec_wire_transfer_request":  (22, "HIGH"),
    "bec_banking_detail_change":  (25, "CRITICAL"),

    # --- Bulk marketing / spam signals ---
    "unsolicited_bulk_marketing": (15, "MEDIUM"),

    # --- Obfuscation (Stage 0/7) ---
    "zero_width_chars":           (12, "HIGH"),
    "base64_body_evasion":         (8, "MEDIUM"),

    # --- Attachments (new) ---
    "attachment_macro_enabled":   (25, "CRITICAL"),
    "attachment_executable":      (30, "CRITICAL"),
    "attachment_archive_nested":  (12, "MEDIUM"),

    # --- QR / quishing (new) ---
    "qr_code_detected_url":       (15, "HIGH"),
}

VERDICT_THRESHOLDS = (
    (75, "MALICIOUS"),
    (40, "SUSPICIOUS"),
    (0, "CLEAN"),
)


@dataclass
class Evidence:
    category: str
    severity: str
    description: str
    weight: int


@dataclass
class ScoringEngine:
    _evidence: list = field(default_factory=list)
    _raw_total: int = 0

    def add(self, signal_key: str, reason: str, weight_override: Optional[int] = None) -> None:
        """Register a detected signal. Unknown keys raise — forces every new
        detector to register its weight in WEIGHT_TABLE instead of silently
        contributing zero (or an undocumented magic number) to the score."""
        if signal_key not in WEIGHT_TABLE and weight_override is None:
            raise KeyError(
                f"Unknown scoring signal '{signal_key}' — add it to WEIGHT_TABLE "
                "with an explicit weight before using it."
            )
        weight, severity = WEIGHT_TABLE.get(signal_key, (weight_override, "MEDIUM"))
        weight = weight_override if weight_override is not None else weight
        self._evidence.append(Evidence(signal_key, severity, reason, weight))
        self._raw_total += weight

    def finalize(self) -> dict:
        # Cap at 100. Confidence reflects how much evidence we actually have,
        # not just the score — a single CRITICAL signal scores high but
        # confidence stays moderate until corroborated by a second signal.
        risk_score = min(100, self._raw_total)
        verdict = next(v for threshold, v in VERDICT_THRESHOLDS if risk_score >= threshold)

        distinct_categories = len({e.category.split("_")[0] for e in self._evidence})
        confidence = min(1.0, 0.35 + 0.15 * distinct_categories) if self._evidence else 0.5

        return {
            "risk_score_100": risk_score,
            "verdict": verdict,
            "confidence_score": round(confidence, 2),
            "forensic_evidence": [
                {"category": e.category, "severity": e.severity, "description": e.description}
                for e in sorted(self._evidence, key=lambda e: -e.weight)
            ],
        }
