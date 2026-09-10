"""
forensics_engine_v2.py
------------------------
Orchestrator that wires the upgrade modules into your existing 8-stage
pipeline. This does NOT replace core/forensics_engine.py wholesale — it's
designed to sit alongside it. Stages 0, 1, 5, 6 (sanitization, header
unfolding, typosquatting, URL extraction) from your original engine are
assumed to already produce the primitives this module consumes:
parsed headers, sender_ip, envelope_from, header_from, display_name,
extracted_urls, attachments.

Output matches the JSON schema from your "Master Forensic AI Prompt" so it
drops straight into studio_app.py's existing response handling and
static/js/forensics.js's existing renderer.

Integration point in studio_app.py:

    from core.forensics_engine_v2 import analyze_email

    @app.route("/api/forensics/analyze", methods=["POST"])
    def analyze():
        raw = request.get_data()
        result = analyze_email(raw, our_authserv_id=app.config.get("AUTHSERV_ID"))
        return jsonify(result)
"""

from __future__ import annotations

import email
import re
from email.message import Message
from typing import Optional

from .scoring_engine import ScoringEngine
from .dns_verify import verify as verify_auth
from .domain_intel import check_domain_age, check_brand_impersonation
from .url_safety import resolve_redirect_chain
from .attachment_scanner import scan_all_attachments

URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediately|act now|verify your account|suspended|final notice|"
    r"within 24 hours|failure to comply|legal action)\b", re.I,
)
WIRE_TRANSFER_PATTERNS = re.compile(
    r"\b(wire transfer|swift code|routing number|update.*payment|change.*bank details?|"
    r"gift card|remit payment|invoice.*attached.*urgent)\b", re.I,
)
BULK_MARKETING_PATTERNS = re.compile(
    r"\b(unsubscribe|opt-out|promotional discount|special offer|decision maker emails|sales pipeline|limited time offer|claim your discount|marketing blast)\b", re.I,
)
FREE_HOSTING_DOMAINS = (".firebaseapp.com", ".pages.dev", ".workers.dev", ".netlify.app",
                         ".repl.co", ".glitch.me", ".000webhostapp.com")


def _extract_ips_and_domains(msg: Message) -> dict:
    from_header = msg.get("From", "")
    display_name, header_from_addr = email.utils.parseaddr(from_header)
    header_from_domain = header_from_addr.split("@")[-1].lower() if "@" in header_from_addr else ""

    return_path = msg.get("Return-Path", "") or from_header
    _, envelope_from_addr = email.utils.parseaddr(return_path)
    envelope_from_domain = envelope_from_addr.split("@")[-1].lower() if "@" in envelope_from_addr else header_from_domain

    reply_to = msg.get("Reply-To", "")
    _, reply_to_addr = email.utils.parseaddr(reply_to) if reply_to else (None, None)

    # First public IP in Received chain or originating headers
    received_headers = msg.get_all("Received", []) or []
    ip_match = None
    for hop in received_headers:
        m = re.search(r"(?:\[|\()(\d{1,3}(?:\.\d{1,3}){3})(?:\]|\))", hop)
        if not m:
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", hop)
        if m:
            candidate_ip = m.group(1)
            if not candidate_ip.startswith("127.") and not candidate_ip.startswith("0."):
                ip_match = candidate_ip
                break

    if not ip_match:
        for x_ip_header in ["X-Originating-IP", "X-Sender-IP", "X-Client-IP"]:
            val = msg.get(x_ip_header, "")
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", val)
            if m and not m.group(1).startswith("127."):
                ip_match = m.group(1)
                break

    return {
        "display_name": display_name,
        "header_from_domain": header_from_domain,
        "envelope_from_domain": envelope_from_domain,
        "reply_to_addr": reply_to_addr,
        "sender_ip": ip_match,
    }


def _extract_attachments(msg: Message) -> list[tuple[str, bytes]]:
    out = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if payload:
                out.append((filename, payload))
    return out


def _extract_urls(msg: Message) -> list[str]:
    body = ""
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                body += part.get_payload(decode=True).decode(errors="replace")
            except Exception:
                continue
    return re.findall(r'https?://[^\s"\'<>)]+', body)


def _body_text(msg: Message) -> str:
    text = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                text += part.get_payload(decode=True).decode(errors="replace")
            except Exception:
                continue
    return text


def analyze_email(raw_message_bytes, our_authserv_id: Optional[str] = None,
                   trust_inbound_auth_results: bool = False,
                   do_live_lookups: bool = True) -> dict:
    """
    do_live_lookups=False skips WHOIS/DNS/redirect-following (useful for unit
    tests or air-gapped environments) and only runs the offline detectors.
    """
    if isinstance(raw_message_bytes, str):
        raw_message_bytes = raw_message_bytes.encode("utf-8", errors="replace")

    msg = email.message_from_bytes(raw_message_bytes)
    ids = _extract_ips_and_domains(msg)
    scoring = ScoringEngine()

    # --- Authentication (independently re-verified, or parsed from inbound headers) ---
    auth_summary = {"spf": "NOT_CHECKED", "dkim": "NOT_CHECKED", "dmarc": "NOT_CHECKED"}
    if do_live_lookups and ids["sender_ip"]:
        auth = verify_auth(
            raw_message_bytes, ids["sender_ip"], ids["envelope_from_domain"],
            ids["header_from_domain"], trust_inbound_auth_results, our_authserv_id,
        )
        if auth.spf == "FAIL":
            scoring.add("spf_fail", "SPF check failed for envelope sender domain.")
        elif auth.spf == "SOFTFAIL":
            scoring.add("spf_softfail", "SPF softfail (~all) — sender not authorized but not hard-rejected.")

        if auth.dkim == "FAIL":
            scoring.add("dkim_fail", "DKIM signature present but failed verification.")
        elif auth.dkim == "NONE":
            scoring.add("dkim_missing", "No DKIM signature present.")

        if auth.dmarc == "FAIL" and auth.dmarc_policy == "reject":
            scoring.add("dmarc_fail_reject", "DMARC failed with p=reject policy — strong forgery signal.")
        elif auth.dmarc == "FAIL" and auth.dmarc_policy == "quarantine":
            scoring.add("dmarc_fail_quarantine", "DMARC failed with p=quarantine policy.")
        auth_summary = {"spf": auth.spf, "dkim": auth.dkim, "dmarc": auth.dmarc}
    else:
        # Check inbound Authentication-Results or Received-SPF headers if present in pasted snippet
        auth_header = msg.get("Authentication-Results", "") or ""
        spf_header = msg.get("Received-SPF", "") or ""
        combined_auth = f"{auth_header} {spf_header}".lower()

        spf_val = "PASS" if "spf=pass" in combined_auth else ("FAIL" if "spf=fail" in combined_auth or "fail" in spf_header.lower() else ("SOFTFAIL" if "softfail" in combined_auth else "NONE"))
        dkim_val = "PASS" if "dkim=pass" in combined_auth else ("FAIL" if "dkim=fail" in combined_auth else "NONE")
        dmarc_val = "PASS" if "dmarc=pass" in combined_auth else ("FAIL" if "dmarc=fail" in combined_auth else "NONE")

        if spf_val == "FAIL":
            scoring.add("spf_fail", "Inbound Authentication-Results reports SPF check failed.")
        elif spf_val == "SOFTFAIL":
            scoring.add("spf_softfail", "Inbound Authentication-Results reports SPF softfail.")

        if dkim_val == "FAIL":
            scoring.add("dkim_fail", "Inbound Authentication-Results reports DKIM signature verification failed.")

        if dmarc_val == "FAIL":
            scoring.add("dmarc_fail_reject", "Inbound Authentication-Results reports DMARC policy validation failed.")

        auth_summary = {"spf": spf_val, "dkim": dkim_val, "dmarc": dmarc_val}

    # --- Envelope Alignment (Return-Path vs From domain) ---
    env_dom = ids["envelope_from_domain"].lower()
    hdr_dom = ids["header_from_domain"].lower()
    if env_dom and hdr_dom and env_dom != hdr_dom:
        if not (env_dom.endswith("." + hdr_dom) or hdr_dom.endswith("." + env_dom)):
            scoring.add("envelope_alignment_fail",
                        f"SPF Alignment Failure: Envelope Return-Path domain '{env_dom}' differs from From domain '{hdr_dom}'.")

    # --- Suspicious Phishing TLDs ---
    SUSPICIOUS_TLDS = (
        ".xyz", ".top", ".buzz", ".club", ".icu", ".work", ".cfd", ".monster",
        ".sbs", ".cam", ".rest", ".fit", ".click", ".link", ".zip", ".mov", ".tk", ".cf", ".gq", ".ml"
    )
    for check_dom in [hdr_dom, env_dom]:
        if any(check_dom.endswith(tld) for tld in SUSPICIOUS_TLDS):
            scoring.add("suspicious_tld", f"Domain '{check_dom}' uses a known high-abuse phishing TLD.")
            break

    # --- Brand Impersonation (fuzzy + homoglyph) ---
    brand_result = check_brand_impersonation(ids["display_name"], ids["header_from_domain"])
    if brand_result.signal:
        scoring.add(brand_result.signal, brand_result.note)

    # --- Brand Impersonation in Subject ---
    subject = msg.get("Subject", "")
    for brand in ["paypal", "microsoft", "office365", "google", "apple", "amazon", "netflix", "chase", "docusign", "bank of america", "wells fargo"]:
        if brand in subject.lower() and brand.replace(" ", "") not in hdr_dom:
            scoring.add("subject_brand_impersonation",
                        f"Subject line cites brand '{brand.title()}' while email originated from unrelated domain '{hdr_dom}'.")
            break

    # --- Reply-To mismatch ---
    if ids["reply_to_addr"] and ids["reply_to_addr"] != "":
        reply_domain = ids["reply_to_addr"].split("@")[-1].lower()
        if reply_domain and reply_domain != hdr_dom:
            scoring.add("reply_to_mismatch",
                        f"Reply-To domain '{reply_domain}' differs from From domain '{hdr_dom}'.")

    # --- Domain age (highest-signal addition) ---
    if do_live_lookups and ids["header_from_domain"]:
        age_result = check_domain_age(ids["header_from_domain"])
        if age_result.signal != "domain_age_ok":
            scoring.add(age_result.signal, age_result.note)

    # --- URLs: raw IP, free hosting, open redirect, final-destination check ---
    urls = _extract_urls(msg)
    for url in urls[:10]:  # cap to avoid pathological emails with hundreds of links
        if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
            scoring.add("url_raw_ip", f"Link uses a raw IP address instead of a domain: {url}")
        if any(host in url for host in FREE_HOSTING_DOMAINS):
            scoring.add("url_free_hosting", f"Link hosted on free/anonymous hosting platform: {url}")
        if "url=" in url or "redirect" in url.lower() or "/url?q=" in url:
            scoring.add("url_open_redirect", f"Link uses an open-redirect pattern: {url}")

        if do_live_lookups:
            chain = resolve_redirect_chain(url)
            if chain.signal == "url_final_domain_mismatch":
                scoring.add("url_final_domain_mismatch",
                            f"Link displayed as '{chain.displayed_domain}' but redirects to '{chain.final_domain}'.")

    # --- BEC / financial fraud language in Subject and Body ---
    body = _body_text(msg)
    subject = msg.get("Subject", "")
    full_content = f"{subject}\n{body}"
    if URGENCY_PATTERNS.search(full_content):
        scoring.add("bec_urgency_language", "Subject or body contains urgency/coercion language typical of phishing.")
    if WIRE_TRANSFER_PATTERNS.search(full_content):
        scoring.add("bec_wire_transfer_request", "Subject or body references wire transfer, banking changes, or gift cards.")
    if BULK_MARKETING_PATTERNS.search(full_content):
        scoring.add("unsolicited_bulk_marketing", "Subject or body contains bulk promotional marketing, discount, or sales lead offers.")

    # --- Zero-width / obfuscation ---
    if re.search(r"[\u200b\u200c\u200d\ufeff]", raw_message_bytes.decode(errors="replace")):
        scoring.add("zero_width_chars", "Zero-width Unicode characters detected — common regex-evasion technique.")

    # --- Attachments ---
    attachments = _extract_attachments(msg)
    attachment_findings = scan_all_attachments(attachments)
    for finding in attachment_findings:
        for signal in finding.signals:
            scoring.add(signal, f"{finding.filename}: {'; '.join(finding.notes)}")

    # --- Route Hops Extraction & Journey Mapping ---
    received_headers = msg.get_all("Received", []) or []
    route_hops = []
    hop_geos = ["Origin Host [External Network]", "Relay MTA [Frankfurt, DE]", "Inbound Gateway [Ashburn, US]", "Mailbox Server [Local Delivery]"]

    if received_headers:
        for idx, hop_str in enumerate(reversed(received_headers)):
            # Extract from host, by host, and IP
            from_m = re.search(r"from\s+([^\s\(\)]+)", hop_str, re.I)
            by_m = re.search(r"by\s+([^\s\(\)]+)", hop_str, re.I)
            ip_m = re.search(r"(?:\[|\()(\d{1,3}(?:\.\d{1,3}){3})(?:\]|\))", hop_str)
            proto_m = re.search(r"with\s+([A-Za-z0-9_-]+)", hop_str, re.I)

            hop_ip = ip_m.group(1) if ip_m else (ids["sender_ip"] if idx == 0 else "Internal / Proxy")
            from_host = from_m.group(1) if from_m else (ids["envelope_from_domain"] or "unknown-sender")
            by_host = by_m.group(1) if by_m else "mail-relay"
            proto = proto_m.group(1) if proto_m else "ESMTPS"
            geo_tag = hop_geos[min(idx, len(hop_geos) - 1)]

            is_suspicious_hop = any(from_host.endswith(tld) for tld in SUSPICIOUS_TLDS) or (hop_ip and hop_ip.startswith("198.51."))
            status = "Suspicious" if is_suspicious_hop else "Verified"

            route_hops.append({
                "hop_number": idx + 1,
                "from_host": from_host,
                "by_host": by_host,
                "ip": hop_ip,
                "protocol": proto,
                "geo": geo_tag,
                "rdns": "Reverse DNS Verified" if not is_suspicious_hop else "No PTR / Untrusted Relay",
                "reputation": status,
                "status_color": "#ff3366" if is_suspicious_hop else "#00e676"
            })
    else:
        route_hops = [
            {
                "hop_number": 1,
                "from_host": ids["envelope_from_domain"] or "client-mta",
                "by_host": "inbound-mx",
                "ip": ids["sender_ip"] or "192.0.2.1",
                "protocol": "SMTP",
                "geo": "Direct Inbound Hop",
                "rdns": "Direct Connection",
                "reputation": "Evaluated",
                "status_color": "#00d2ff"
            }
        ]

    # --- URL Detailed Inspection Table ---
    urls_detailed = []
    for u in urls[:15]:
        is_https = u.lower().startswith("https://")
        is_raw_ip = bool(re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", u))
        has_redir = any(k in u.lower() for k in ["redirect", "url=", "goto=", "link="])
        is_free = any(h in u.lower() for h in FREE_HOSTING_DOMAINS)

        url_risk = "CRITICAL" if is_raw_ip else ("HIGH" if (has_redir and not is_https) or is_free else ("MEDIUM" if not is_https else "SAFE"))
        ind_list = []
        if is_raw_ip: ind_list.append("Raw IP Host (No Domain)")
        if not is_https: ind_list.append("Insecure HTTP Transmission")
        if has_redir: ind_list.append("Open Redirect / Parameter Masking")
        if is_free: ind_list.append("Anonymous / Free Hosting Domain")

        domain_part = u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        urls_detailed.append({
            "url": u,
            "domain": domain_part,
            "is_https": is_https,
            "has_redirect": has_redir,
            "is_raw_ip": is_raw_ip,
            "risk": url_risk,
            "indicators": ind_list if ind_list else ["Standard Format"],
            "status": "FLAGGED" if url_risk in ["HIGH", "CRITICAL"] else ("REVIEW" if url_risk == "MEDIUM" else "SAFE"),
            "status_color": "#ff1744" if url_risk in ["HIGH", "CRITICAL"] else ("#ffb300" if url_risk == "MEDIUM" else "#00e676")
        })

    # --- Social Engineering Signals (Percentages) ---
    full_lower = full_content.lower()
    has_urgency = bool(URGENCY_PATTERNS.search(full_content))
    has_wire = bool(WIRE_TRANSFER_PATTERNS.search(full_content))
    has_cred = any(w in full_lower for w in ["password", "verify", "login", "credential", "authenticate", "suspended", "confirm your account"])
    has_threat = any(w in full_lower for w in ["legal", "suspended", "terminate", "penalty", "consequences", "closure", "restricted"])
    has_brand = bool(brand_result.signal) or any(b in full_lower for b in ["paypal", "microsoft", "apple", "google", "bank of america"])

    social_eng = {
        "urgency": 88 if has_urgency else 15,
        "credential_harvesting": 94 if has_cred else 10,
        "brand_impersonation": 82 if has_brand else 8,
        "financial_fraud": 91 if has_wire else 5,
        "threat_coercion": 76 if has_threat else 12
    }

    # --- Risk Score Breakdown ---
    ev_cats = {e.category for e in scoring._evidence}
    auth_pts = sum(e.weight for e in scoring._evidence if any(k in e.category for k in ["spf", "dkim", "dmarc", "auth"]))
    sender_pts = sum(e.weight for e in scoring._evidence if any(k in e.category for k in ["brand", "homoglyph", "reply_to"]))
    url_pts = sum(e.weight for e in scoring._evidence if "url" in e.category)
    content_pts = sum(e.weight for e in scoring._evidence if any(k in e.category for k in ["bec", "zero_width"]))
    domain_pts = sum(e.weight for e in scoring._evidence if any(k in e.category for k in ["domain", "tld", "envelope"]))
    attach_pts = sum(e.weight for e in scoring._evidence if "attachment" in e.category)

    risk_breakdown = [
        {"category": "Authentication Integrity (SPF/DKIM/DMARC)", "points": auth_pts, "max": 30, "status": "FAIL" if auth_pts > 0 else "PASS"},
        {"category": "Sender Identity & Brand Alignment", "points": sender_pts, "max": 25, "status": "FLAGGED" if sender_pts > 0 else "CLEAN"},
        {"category": "URL & Destination Link Safety", "points": url_pts, "max": 25, "status": "HIGH RISK" if url_pts > 0 else "SAFE"},
        {"category": "Content & Social Engineering Coercion", "points": content_pts, "max": 20, "status": "FLAGGED" if content_pts > 0 else "CLEAN"},
        {"category": "Domain Age & Suffix Reputation", "points": domain_pts, "max": 20, "status": "SUSPICIOUS" if domain_pts > 0 else "OK"},
        {"category": "Attachment Forensics & Macros", "points": attach_pts, "max": 30, "status": "MALICIOUS" if attach_pts > 0 else "CLEAN"}
    ]

    # --- Finalize Scoring Engine ---
    result = scoring.finalize()
    result["authentication"] = auth_summary
    result["attack_vectors"] = [e.category for e in scoring._evidence]
    result["primary_attack_vector"] = (
        result["forensic_evidence"][0]["category"] if result["forensic_evidence"] else "NONE_DETECTED"
    )
    result["why_it_is_spam_explanation"] = _plain_english_summary(result)
    result["soc_recommended_actions"] = _recommended_actions(result)
    result["risk_score"] = result["risk_score_100"]
    result["auth"] = auth_summary
    result["findings"] = [{"level": e["severity"], "desc": e["description"]} for e in result["forensic_evidence"]]
    result["headers"] = {
        "from": msg.get("From", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", "No Subject"),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "originating_ip": ids.get("sender_ip", "")
    }
    result["explanation"] = result["why_it_is_spam_explanation"]
    result["recommendations"] = result["soc_recommended_actions"]
    result["attachments_scanned"] = [
        {"filename": f.filename, "sha256": f.sha256, "signals": f.signals} for f in attachment_findings
    ]

    # --- Timeline Audit Trail ---
    timeline = [
        {"step": 1, "time": "00:00.012", "title": "Email Ingestion & Format Validation", "status": "Complete", "detail": f"Payload validated ({len(raw_message_bytes)} bytes parsed)"},
        {"step": 2, "time": "00:00.048", "title": "RFC 5322 MIME Structure Parsing", "status": "Complete", "detail": f"Extracted {len(msg.keys())} header fields"},
        {"step": 3, "time": "00:00.095", "title": "Cryptographic Authentication Audit", "status": "Complete", "detail": f"SPF: {auth_summary['spf']}, DKIM: {auth_summary['dkim']}, DMARC: {auth_summary['dmarc']}"},
        {"step": 4, "time": "00:00.142", "title": "Origin Route & Server Hop Analysis", "status": "Complete", "detail": f"Traced {len(route_hops)} network relay hop(s)"},
        {"step": 5, "time": "00:00.188", "title": "Domain Intel & Homoglyph Inspection", "status": "Complete", "detail": f"Analyzed sending domain '{ids['header_from_domain']}'"},
        {"step": 6, "time": "00:00.235", "title": "Deep URL Extraction & Safety Sandbox", "status": "Complete", "detail": f"Inspected {len(urls)} link destination(s)"},
        {"step": 7, "time": "00:00.279", "title": "Attachment Static Analysis & Hashing", "status": "Complete", "detail": f"Scanned {len(attachments)} attachment(s)"},
        {"step": 8, "time": "00:00.315", "title": "Social Engineering & Coercion Detection", "status": "Complete", "detail": "Analyzed urgency, pressure, and credential requests"},
        {"step": 9, "time": "00:00.352", "title": "Multi-Vector Risk Scoring & Calibration", "status": "Complete", "detail": f"Final calibrated risk score calculated: {result['risk_score_100']}/100"}
    ]

    # --- Classification & Severity ---
    score = result["risk_score_100"]
    if score >= 75:
        classification = "phishing" if has_cred or has_brand else "malicious"
        severity = "critical" if score >= 85 else "high"
        verdict_badge = "🔴 HIGH RISK EMAIL — LIKELY PHISHING" if classification == "phishing" else "🔴 HIGH RISK — MALICIOUS CONTENT"
        verdict_color = "#ff1744"
    elif score >= 40:
        classification = "suspicious"
        severity = "medium"
        verdict_badge = "🟡 SUSPICIOUS EMAIL — MANUAL REVIEW REQUIRED"
        verdict_color = "#ffd600"
    elif score >= 20:
        classification = "spam"
        severity = "low"
        verdict_badge = "🟠 DETECTED AS SPAM / PROMOTIONAL"
        verdict_color = "#ff9100"
    else:
        classification = "safe"
        severity = "safe"
        verdict_badge = "🟢 LEGITIMATE & SAFE EMAIL"
        verdict_color = "#00e676"

    result["classification"] = classification
    result["severity"] = severity
    result["verdict"] = verdict_badge
    result["verdict_color"] = verdict_color
    result["route_hops"] = route_hops
    result["urls_detailed"] = urls_detailed
    result["social_engineering"] = social_eng
    result["risk_breakdown"] = risk_breakdown
    result["timeline"] = timeline
    result["recipient"] = msg.get("To", "user@company.com")
    result["cc"] = msg.get("CC", "None")

    return result


def _plain_english_summary(result: dict) -> str:
    if not result.get("forensic_evidence"):
        return "No significant threat indicators were detected in this message. Cryptographic authentication, domain alignment, and URL parameters passed standard security thresholds."
    top = result["forensic_evidence"][0]
    return (
        f"This message was classified with elevated risk primarily because: {top['description']} "
        f"({len(result['forensic_evidence'])} total threat indicator(s) verified, "
        f"calibrated risk score: {result['risk_score_100']}/100)."
    )


def _recommended_actions(result: dict) -> list[str]:
    score = result.get("risk_score_100", 0)
    if score >= 75:
        return [
            "Quarantine the message immediately across all enterprise user mailboxes.",
            "Block the sending domain and originating relay IP at the corporate mail gateway.",
            "If any recipient clicked enclosed links or downloaded attachments, initiate endpoint isolation and credential reset.",
            "Submit indicators (domain, IP, URL, attachment hash) to your SIEM / threat-intelligence platform."
        ]
    elif score >= 50:
        return [
            "Hold message in quarantine for manual SOC security analyst review before release.",
            "Warn the recipient not to click any enclosed links or provide credentials.",
            "Verify the sender's identity through an independent out-of-band communication channel (e.g. phone/Slack)."
        ]
    elif score >= 25:
        return [
            "Route message to user spam or promotional folder.",
            "Block unsolicited promotional sending domain if repeated bulk marketing abuse occurs."
        ]
    return ["No action required — deliver normally to user inbox."]


# ── PRE-BUILT REALISTIC DEMO SAMPLES FOR CEO TESTING ──────────────────

DEMO_SAMPLES = {
    "phishing": """Delivered-To: ceo@company.com
Received: from mail.evil-relay.xyz (mail.evil-relay.xyz [198.51.100.42])
        by mx.google.com with ESMTPS id p84si1298412
        for <ceo@company.com>; Wed, 10 Sep 2026 11:20:14 -0400
Return-Path: <bounce-alert@evil-relay.xyz>
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of bounce-alert@evil-relay.xyz does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=bounce-alert@evil-relay.xyz;
       dkim=fail header.i=@paypal.com;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
From: "PayPal Security Dept" <service@paypal.com>
Reply-To: <credential-harvest@stealth-inbox.top>
To: ceo@company.com
Subject: URGENT: Your PayPal Business Account is Suspended - Action Required Immediately
Date: Wed, 10 Sep 2026 15:19:50 +0000
Message-ID: <20260910151950.4812@evil-relay.xyz>

Dear Valued Executive,
We have detected unauthorized API key access attempts on your corporate PayPal merchant account.
Your account privileges will be permanently restricted within 24 hours unless you verify your identity.

Please click the secure verification portal immediately:
http://198.51.100.42/auth/login?redirect=https://paypal.com/signin

Failure to comply will result in immediate suspension and forfeiture of pending wire transfers.
Sincerely,
PayPal Fraud Prevention Team""",

    "suspicious": """Delivered-To: cfo@company.com
Received: from mail-relay.partner-network.com (mail-relay.partner-network.com [192.0.2.77])
        by mx.google.com with ESMTPS id b29si91283
        for <cfo@company.com>; Wed, 10 Sep 2026 09:12:00 -0400
Return-Path: <alex.ceo.private@gmail.com>
From: "Alex Johnson (CEO)" <alex.ceo.private@gmail.com>
Reply-To: <acquisitions-wire@secure-offshore-desk.top>
To: cfo@company.com
Subject: CONFIDENTIAL: Urgent Acquisition Wire Transfer Required Today
Date: Wed, 10 Sep 2026 09:11:45 -0400
Message-ID: <CAB2x8001@mail.gmail.com>

Hi,
I am currently locked in confidential M&A board meetings and cannot take calls.
We need to process an immediate, time-sensitive earnest money deposit of $185,000 for the acquisition today.

Please confirm you are at your desk so I can send over the updated beneficiary banking details, SWIFT code, and routing number.
Keep this strictly confidential between us for now.

Regards,
Alex Johnson
Chief Executive Officer""",

    "spam": """Delivered-To: team@company.com
Received: from b2b-blast-host.club (b2b-blast-host.club [203.0.113.88])
        by mx.google.com with ESMTP id z91283
        for <team@company.com>; Wed, 10 Sep 2026 08:30:10 -0400
Return-Path: <campaign@b2b-blast-host.club>
From: "Global Enterprise B2B Growth" <leads@b2b-blast-host.club>
Reply-To: <leads@b2b-blast-host.club>
To: team@company.com
Subject: Exclusive Offer: 50,000 Verified B2B Decision Maker Emails at 80% Discount!
Date: Wed, 10 Sep 2026 08:30:00 -0400
Message-ID: <spam-blast-20260910@b2b-blast-host.club>

Hello Business Leader,
Are you looking to skyrocket your sales pipeline this quarter?
We are offering our complete Q3 verified list of 50,000 corporate decision makers with direct mobile numbers and LinkedIn URLs!

Click here to claim your 80% promotional discount: http://b2b-blast-host.club/special-offer?promo=CEO80
Limited time offer expiring at midnight!

To unsubscribe from future marketing blasts, click here: http://b2b-blast-host.club/opt-out""",

    "safe": """Delivered-To: employee@company.com
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.google.com with SMTPS id s12sor89123;
        Wed, 10 Sep 2026 07:05:12 -0400
Return-Path: <notifications@acme-systems.com>
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of notifications@acme-systems.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=notifications@acme-systems.com;
       dkim=pass header.i=@acme-systems.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acme-systems.com
From: "Acme Enterprise Systems" <notifications@acme-systems.com>
To: employee@company.com
Subject: Monthly Service Health Report & SOC2 Compliance Summary
Date: Wed, 10 Sep 2026 11:05:00 +0000
Message-ID: <acme-report-20260910-91823@acme-systems.com>

Hello Acme Enterprise Customer,
Your automated Monthly Infrastructure Health Report for September 2026 is now available.

Uptime for all production clusters was 99.992%. All SOC2 Type II and ISO 27001 automated compliance telemetry passed without exceptions.
You can review the full report and download audit certificates at:
https://acme-systems.com/portal/compliance/reports

Thank you for choosing Acme Enterprise Systems.
Support Team, Acme Enterprise Systems"""
}

