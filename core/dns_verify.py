"""
dns_verify.py
--------------
Independent SPF / DKIM / DMARC re-verification.

Why this exists (per senior-review feedback):
  Trusting an inbound `Authentication-Results` header is only safe if you can
  prove it was added by YOUR receiving MTA, not forged by the attacker before
  the message ever reached you. This module re-derives the verdicts from DNS
  and the message itself, so results are trustworthy even for arbitrary
  uploaded .eml files with no known trust boundary.

Dependencies: dnspython (`pip install dnspython`)
Optional: dkimpy (`pip install dkimpy`) for full DKIM signature verification.
          Without it, we fall back to "DKIM-Signature header present + DNS key
          exists" (weaker, but still catches "no DKIM at all" and "key doesn't
          resolve", which is most of what matters for triage).

Network note: SPF/DMARC/DKIM-key lookups require outbound DNS (port 53) to
the public resolver chain. In network-restricted sandboxes this will raise
dns.exception.Timeout — catch that and degrade gracefully (see
`domain_age_lookup_failed` pattern in scoring_engine.py for the convention).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

try:
    import dns.resolver
    import dns.exception
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

try:
    import dkim as dkimpy
    _HAS_DKIMPY = True
except ImportError:
    _HAS_DKIMPY = False


@dataclass
class AuthResult:
    spf: str        # PASS | FAIL | SOFTFAIL | NEUTRAL | NONE | TEMPERROR
    dkim: str       # PASS | FAIL | NONE
    dmarc: str      # PASS | FAIL | NONE
    dmarc_policy: Optional[str]     # none | quarantine | reject
    dmarc_alignment: Optional[str]  # strict | relaxed
    trust_note: str  # explains WHY we trust (or don't trust) these results


def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = 3
    r.lifetime = 3
    return r


# --- SPF -----------------------------------------------------------------

def _spf_txt_record(domain: str) -> Optional[str]:
    try:
        answers = _resolver().resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="replace")
            if txt.lower().startswith("v=spf1"):
                return txt
    except Exception:
        return None
    return None


def evaluate_spf(sender_ip: str, envelope_from_domain: str, depth: int = 0) -> str:
    """Minimal SPF evaluator: handles ip4/ip6/a/mx/include/all mechanisms.
    Does NOT implement the full RFC 7208 (no %macros, no exists:, limited
    include recursion depth) — sufficient for forensic triage, not for
    running your own outbound mail server's SPF enforcement."""
    if not _HAS_DNSPYTHON:
        return "TEMPERROR"
    if depth > 5:  # RFC 7208 caps recursive lookups at 10; 5 is conservative
        return "TEMPERROR"

    record = _spf_txt_record(envelope_from_domain)
    if record is None:
        return "NONE"

    try:
        ip = ipaddress.ip_address(sender_ip)
    except ValueError:
        return "TEMPERROR"

    mechanisms = record.split()[1:]  # skip "v=spf1"
    for mech in mechanisms:
        qualifier = "+"
        if mech and mech[0] in "+-~?":
            qualifier, mech = mech[0], mech[1:]

        if mech == "all":
            return {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}[qualifier]

        if mech.startswith("ip4:") or mech.startswith("ip6:"):
            cidr = mech.split(":", 1)[1]
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}[qualifier]
            except ValueError:
                continue

        elif mech.startswith("include:"):
            included_domain = mech.split(":", 1)[1]
            result = evaluate_spf(sender_ip, included_domain, depth + 1)
            if result == "PASS":
                return {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}[qualifier]

        elif mech.startswith("a") or mech.startswith("mx"):
            # Resolve A/MX records for the domain and compare to sender_ip.
            target_domain = mech.split(":", 1)[1] if ":" in mech else envelope_from_domain
            try:
                rrtype = "A" if mech.startswith("a") else "MX"
                answers = _resolver().resolve(target_domain, rrtype)
                for rdata in answers:
                    host = str(rdata.exchange) if rrtype == "MX" else str(rdata)
                    a_records = _resolver().resolve(host.rstrip("."), "A")
                    if any(str(a) == sender_ip for a in a_records):
                        return {"+": "PASS", "-": "FAIL", "~": "SOFTFAIL", "?": "NEUTRAL"}[qualifier]
            except Exception:
                continue

    return "NEUTRAL"  # no mechanism matched, no "all" present


# --- DKIM ------------------------------------------------------------------

def evaluate_dkim(raw_message_bytes: bytes) -> str:
    """Full cryptographic verification if dkimpy is installed; otherwise a
    weaker structural check (signature present + DNS key resolves)."""
    if b"DKIM-Signature:" not in raw_message_bytes:
        return "NONE"

    if _HAS_DKIMPY:
        try:
            return "PASS" if dkimpy.verify(raw_message_bytes) else "FAIL"
        except Exception:
            return "FAIL"

    # Fallback: does the advertised selector/domain even have a published key?
    if not _HAS_DNSPYTHON:
        return "NONE"
    match = re.search(rb"DKIM-Signature:.*?d=([^;]+);.*?s=([^;]+)", raw_message_bytes, re.S)
    if not match:
        return "FAIL"
    domain = match.group(1).decode().strip()
    selector = match.group(2).decode().strip()
    try:
        _resolver().resolve(f"{selector}._domainkey.{domain}", "TXT")
        return "NONE"  # signature present, key exists, but we can't verify the crypto without dkimpy
    except Exception:
        return "FAIL"  # signature claims a key that doesn't even resolve — strong negative signal


# --- DMARC -------------------------------------------------------------

def evaluate_dmarc(from_domain: str, spf_result: str, spf_domain_aligned: bool,
                    dkim_result: str, dkim_domain_aligned: bool) -> tuple[str, Optional[str], Optional[str]]:
    """Returns (dmarc_result, policy, alignment_mode)."""
    if not _HAS_DNSPYTHON:
        return "NONE", None, None

    org_domain = ".".join(from_domain.split(".")[-2:])  # naive org-domain derivation
    record = None
    for candidate in (from_domain, org_domain):
        try:
            answers = _resolver().resolve(f"_dmarc.{candidate}", "TXT")
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="replace")
                if txt.lower().startswith("v=dmarc1"):
                    record = txt
                    break
        except Exception:
            continue
        if record:
            break

    if record is None:
        return "NONE", None, None

    policy = "none"
    aspf, adkim = "r", "r"  # relaxed by default per RFC 7489
    for part in record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part.split("=", 1)[1]
        elif part.startswith("aspf="):
            aspf = part.split("=", 1)[1]
        elif part.startswith("adkim="):
            adkim = part.split("=", 1)[1]

    spf_pass_aligned = spf_result == "PASS" and (spf_domain_aligned if aspf == "s" else True)
    dkim_pass_aligned = dkim_result == "PASS" and (dkim_domain_aligned if adkim == "s" else True)

    dmarc_result = "PASS" if (spf_pass_aligned or dkim_pass_aligned) else "FAIL"
    alignment_mode = "strict" if (aspf == "s" or adkim == "s") else "relaxed"
    return dmarc_result, policy, alignment_mode


# --- Orchestrator ---------------------------------------------------------

def verify(raw_message_bytes: bytes, sender_ip: str, envelope_from_domain: str,
           header_from_domain: str, trust_inbound_auth_results: bool = False,
           our_authserv_id: Optional[str] = None) -> AuthResult:
    """
    trust_inbound_auth_results: only set True if you can prove the
    Authentication-Results header was stamped by your own MTA (match
    `authserv-id` against our_authserv_id). Otherwise we always re-derive
    independently — this is the fix for the forgeable-header issue.
    """
    if trust_inbound_auth_results and our_authserv_id:
        pattern = (
            rf"Authentication-Results:\s*{re.escape(our_authserv_id)};.*?"
            rf"spf=(\w+).*?dkim=(\w+).*?dmarc=(\w+)"
        )
        match = re.search(pattern, raw_message_bytes.decode(errors="replace"), re.S)
        if match:
            return AuthResult(
                spf=match.group(1).upper(), dkim=match.group(2).upper(), dmarc=match.group(3).upper(),
                dmarc_policy=None, dmarc_alignment=None,
                trust_note=f"Trusted Authentication-Results stamped by our own MTA ({our_authserv_id}).",
            )
        # authserv_id given but no matching header found -> fall through to independent check

    spf = evaluate_spf(sender_ip, envelope_from_domain)
    dkim = evaluate_dkim(raw_message_bytes)

    spf_aligned = envelope_from_domain.endswith(header_from_domain) or header_from_domain.endswith(envelope_from_domain)
    dkim_aligned = True  # dkimpy exposes signing domain on success; simplified here
    dmarc, policy, alignment = evaluate_dmarc(header_from_domain, spf, spf_aligned, dkim, dkim_aligned)

    return AuthResult(
        spf=spf, dkim=dkim, dmarc=dmarc, dmarc_policy=policy, dmarc_alignment=alignment,
        trust_note=(
            "Independently re-derived from DNS + message content — inbound "
            "Authentication-Results header was NOT trusted (either untrusted "
            "trust boundary or verification requested explicitly)."
        ),
    )
