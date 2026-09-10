import re
import socket
import json
import unicodedata
from datetime import datetime

# ── CYBERSECURITY THREAT CONSTANTS ──────────────────────────────────────

HIGH_VALUE_BRANDS = {
    "paypal": ["paypal.com", "paypal.co.uk"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "quickbooks": ["intuit.com", "quickbooks.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "geek squad": ["bestbuy.com"]
}

BEC_FINANCIAL_PATTERNS = [
    r"new\s*bank\s*(?:account|details|info)",
    r"updated?\s*banking\s*details?",
    r"routing\s*number",
    r"swift\s*code",
    r"wire\s*transfer\s*(?:instructions?|request|payment)",
    r"overdue\s*invoice",
    r"payment\s*method\s*changed?",
    r"remittance\s*advice",
    r"urgent\s*payment"
]

PHISHING_URGENCY_KEYWORDS = [
    "account suspended", "password reset", "verify your account", "action required immediately",
    "unauthorized access", "immediate attention", "security compromise", "confirm identity",
    "payment overdue", "tax refund", "gift card", "login attempt detected", "payroll update",
    "restricted access", "security notice", "unusual sign-in activity"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".buzz", ".club", ".icu", ".work", ".cfd", ".monster",
    ".sbs", ".cam", ".rest", ".fit", ".click", ".link", ".zip", ".mov"
]

FREE_HOSTING_PHISH_PATTERNS = [
    r"\.firebaseapp\.com", r"\.web\.app", r"\.weebly\.com", r"\.webflow\.io",
    r"\.pages\.dev", r"\.workers\.dev", r"\.glitch\.me", r"\.wixsite\.com",
    r"\.surge\.sh", r"\.appspot\.com"
]

OPEN_REDIRECT_HOSTS = [
    "google.com/url", "www.google.com/url", "bing.com/ck/a", "duckduckgo.com/l/",
    "linkedin.com/safety/go", "t.co/", "bit.ly/", "cutt.ly/", "tinyurl.com/"
]

# ── HELPER FUNCTIONS ───────────────────────────────────────────────────

def strip_zero_width_chars(text):
    """
    Detects and strips zero-width non-printable characters used by attackers
    to evade keyword-based spam filters (e.g. p\u200ba\u200bs\u200bs\u200bw\u200bo\u200br\u200bd).
    """
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
    found_obfuscation = any(c in text for c in zero_width_chars)
    cleaned = text
    for c in zero_width_chars:
        cleaned = cleaned.replace(c, '')
    return cleaned, found_obfuscation

def parse_email_headers(raw_text):
    """
    RFC 5322 header parser supporting folded lines.
    """
    lines = raw_text.splitlines()
    headers = {}
    received_chain = []
    current_key = None
    current_val = []

    for line in lines:
        if line.startswith((" ", "\t")):
            if current_key:
                current_val.append(line.strip())
        else:
            if current_key:
                full_val = " ".join(current_val).strip()
                if current_key.lower() == "received":
                    received_chain.append(full_val)
                else:
                    headers[current_key.lower()] = full_val
            match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)", line)
            if match:
                current_key = match.group(1)
                current_val = [match.group(2).strip()]
            else:
                current_key = None
                current_val = []

    if current_key:
        full_val = " ".join(current_val).strip()
        if current_key.lower() == "received":
            received_chain.append(full_val)
        else:
            headers[current_key.lower()] = full_val

    return headers, received_chain

def parse_sender_info(from_header):
    """
    Splits 'Display Name <user@domain.com>' into display name and email address.
    """
    if not from_header:
        return "", "", ""
    match = re.search(r"^(.*?)(?:<([^>]+)>)?$", from_header.strip())
    if match:
        display_name = match.group(1).strip(' "\'')
        email_addr = match.group(2).strip() if match.group(2) else ""
        if not email_addr and "@" in display_name:
            email_addr = display_name
            display_name = ""
        domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
        return display_name, email_addr, domain
    return from_header, "", ""

def extract_domain(email_str):
    if not email_str:
        return ""
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", email_str)
    return match.group(1).lower() if match else ""

def extract_ips(text):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates = re.findall(ip_pattern, text)
    valid_ips = []
    for ip in candidates:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            if not (parts[0] in ["10", "127"] or (parts[0] == "192" and parts[1] == "168") or (parts[0] == "172" and 16 <= int(parts[1]) <= 31)):
                valid_ips.append(ip)
    return list(dict.fromkeys(valid_ips))

def extract_urls(text):
    """
    Extracts all HTTP/HTTPS links from headers and body.
    """
    url_pattern = r"https?://[^\s<>\"'{}|\\^`]+"
    return re.findall(url_pattern, text)

def detect_homoglyphs_and_punycode(domain):
    """
    Detects Punycode (IDN) or mixed Latin/Cyrillic homoglyphs.
    """
    if not domain:
        return False, None

    # 1. Punycode check
    if "xn--" in domain.lower():
        try:
            decoded = domain.encode('ascii').decode('idna')
            return True, f"Punycode (IDN) Spoofing Detected: '{domain}' decodes visually to '{decoded}'."
        except Exception:
            return True, f"Suspicious Punycode Prefix 'xn--' found in domain '{domain}'."

    # 2. Mixed script homoglyph check
    scripts = set()
    for ch in domain:
        if ch.isalpha():
            name = unicodedata.name(ch, '')
            if 'CYRILLIC' in name:
                scripts.add('Cyrillic')
            elif 'LATIN' in name:
                scripts.add('Latin')
            elif 'GREEK' in name:
                scripts.add('Greek')

    if len(scripts) > 1:
        return True, f"Mixed Unicode Script Homoglyph: Domain '{domain}' combines {', '.join(scripts)} characters to visually mimic standard text."

    return False, None

def check_typosquatting(domain):
    """
    Checks for lookalike typosquatting and cousin domains (e.g. rnicrosoft, paypa1, google-security).
    """
    if not domain:
        return None

    domain_clean = domain.lower().split('.')[0]
    
    # Check for visual letter substitutions
    if "rn" in domain_clean:
        potential_sub = domain_clean.replace("rn", "m")
        for brand in HIGH_VALUE_BRANDS:
            if brand in potential_sub:
                return f"Lookalike Typosquatting: '{domain}' uses 'rn' to visually mimic 'm' in brand '{brand}'."

    if "vv" in domain_clean:
        potential_sub = domain_clean.replace("vv", "w")
        for brand in HIGH_VALUE_BRANDS:
            if brand in potential_sub:
                return f"Lookalike Typosquatting: '{domain}' uses 'vv' to visually mimic 'w' in brand '{brand}'."

    # Check for number substitutions: 0 for o, 1 for l/i
    subbed = domain_clean.replace("0", "o").replace("1", "l")
    for brand in HIGH_VALUE_BRANDS:
        if brand in subbed and brand not in domain_clean:
            return f"Number-for-Letter Substitution: '{domain}' uses 0/1 to mimic brand '{brand}'."

    # Check for cousin domain brand hijacking (e.g. paypal-security-portal.com)
    for brand, legit_domains in HIGH_VALUE_BRANDS.items():
        if brand in domain.lower() and not any(domain.lower().endswith(legit) for legit in legit_domains):
            return f"Cousin Domain Hijacking: Domain '{domain}' contains protected brand name '{brand}', but is NOT hosted on official infrastructure ({', '.join(legit_domains)})."

    return None

def check_live_dns(domain):
    if not domain:
        return {"has_dns": False, "ip": None}
    try:
        ip = socket.gethostbyname(domain)
        return {"has_dns": True, "ip": ip}
    except Exception:
        return {"has_dns": False, "ip": None}

def reverse_dns_lookup(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

# ── MASTER FORENSIC ANALYSIS ENGINE ────────────────────────────────────

def analyze_threat(raw_data):
    """
    State-of-the-Art 2026 Cybersecurity Email Threat Hunting Engine.
    Detects:
    1. Display Name / Executive Impersonation
    2. Homoglyphs & Punycode (IDN Spoofing)
    3. Typosquatting & Cousin Domains
    4. SPF, DKIM, DMARC, ARC cryptographic failures
    5. Envelope Return-Path & Reply-To Hijacking
    6. BEC (Business Email Compromise) / Wire Fraud
    7. Zero-Width Unicode Evasion
    8. Open Redirects, Unmasked IPs & Evasive Links
    """
    # 0. Zero-Width Obfuscation Detection
    sanitized_text, has_zero_width = strip_zero_width_chars(raw_data)
    
    headers, received = parse_email_headers(sanitized_text)

    from_header = headers.get("from", "")
    return_path = headers.get("return-path", "")
    reply_to = headers.get("reply-to", "")
    subject = headers.get("subject", "No Subject Provided")
    auth_results = headers.get("authentication-results", "")
    arc_auth = headers.get("arc-authentication-results", "")
    msg_id = headers.get("message-id", "")
    date_header = headers.get("date", "")

    display_name, sender_email, from_domain = parse_sender_info(from_header)
    return_domain = extract_domain(return_path)
    reply_domain = extract_domain(reply_to)

    findings = []
    attack_vectors = []
    risk_score = 0

    # ── VECTOR 1: Zero-Width Unicode Evasion ──
    if has_zero_width:
        findings.append({
            "vector": "ZERO_WIDTH_OBFUSCATION",
            "level": "CRITICAL",
            "title": "Hidden Zero-Width Unicode Injected",
            "desc": "The sender injected invisible zero-width spaces into words to bypass traditional spam filters."
        })
        attack_vectors.append("ZERO_WIDTH_EVASION")
        risk_score += 35

    # ── VECTOR 2: Homoglyph & Punycode (IDN) Attacks ──
    is_homoglyph, homoglyph_msg = detect_homoglyphs_and_punycode(from_domain)
    if is_homoglyph:
        findings.append({
            "vector": "HOMOGLYPH_PUNYCODE",
            "level": "CRITICAL",
            "title": "Internationalized Domain (IDN) Spoofing",
            "desc": homoglyph_msg
        })
        attack_vectors.append("HOMOGLYPH_PUNYCODE")
        risk_score += 50

    # ── VECTOR 3: Typosquatting & Cousin Domain Detection ──
    typo_result = check_typosquatting(from_domain)
    if typo_result:
        findings.append({
            "vector": "TYPOSQUATTING",
            "level": "CRITICAL",
            "title": "Typosquatting / Brand Mimicry Detected",
            "desc": typo_result
        })
        attack_vectors.append("TYPOSQUATTING")
        risk_score += 45

    # ── VECTOR 4: Display Name / VIP Brand Impersonation ──
    disp_lower = display_name.lower()
    for brand, legit_domains in HIGH_VALUE_BRANDS.items():
        if brand in disp_lower:
            # Check if actual domain matches legit brand domain
            if not any(from_domain.endswith(d) for d in legit_domains):
                findings.append({
                    "vector": "DISPLAY_NAME_IMPERSONATION",
                    "level": "CRITICAL",
                    "title": f"Brand / VIP Impersonation: Display Name '{display_name}'",
                    "desc": f"The friendly display name claims to be '{display_name}' ({brand.title()}), but the actual RFC 5322 sending domain is '@{from_domain}'. On mobile devices, victims only see the display name."
                })
                attack_vectors.append("DISPLAY_NAME_IMPERSONATION")
                risk_score += 45
                break

    # ── VECTOR 5: Cryptographic Authentication (SPF, DKIM, DMARC) ──
    auth_combined = (auth_results + " " + arc_auth).lower()
    auth_summary = {"spf": "UNKNOWN", "dkim": "UNKNOWN", "dmarc": "UNKNOWN"}

    # SPF Inspection
    if "spf=pass" in auth_combined:
        auth_summary["spf"] = "PASS"
    elif any(k in auth_combined for k in ["spf=fail", "spf=softfail"]):
        auth_summary["spf"] = "FAIL"
        findings.append({
            "vector": "SPF_AUTH_FAILURE",
            "level": "CRITICAL",
            "title": "SPF Authentication Failed",
            "desc": f"The IP address of the sending server is not authorized by the DNS records of '@{from_domain}'."
        })
        attack_vectors.append("SPF_FAIL")
        risk_score += 35
    elif any(k in auth_combined for k in ["spf=neutral", "spf=none"]):
        auth_summary["spf"] = "NEUTRAL"
        findings.append({
            "vector": "SPF_NEUTRAL",
            "level": "WARN",
            "title": "SPF Policy Neutral / Unenforced",
            "desc": "The domain publishes a permissive SPF record (+all or ?all), allowing arbitrary mail servers to send emails."
        })
        risk_score += 15

    # DKIM Inspection
    if "dkim=pass" in auth_combined:
        auth_summary["dkim"] = "PASS"
    elif any(k in auth_combined for k in ["dkim=fail", "dkim=temperror"]):
        auth_summary["dkim"] = "FAIL"
        findings.append({
            "vector": "DKIM_AUTH_FAILURE",
            "level": "CRITICAL",
            "title": "DKIM Cryptographic Signature Check Failed",
            "desc": "The email body or headers were modified in transit, or the cryptographic public key signature did not verify."
        })
        attack_vectors.append("DKIM_FAIL")
        risk_score += 35
    elif "dkim=" not in auth_combined:
        auth_summary["dkim"] = "NONE"
        findings.append({
            "vector": "DKIM_MISSING",
            "level": "WARN",
            "title": "Missing DKIM Cryptographic Signature",
            "desc": "Email lacks a DKIM cryptographic signature, preventing proof of message integrity."
        })
        risk_score += 10

    # DMARC Inspection
    if "dmarc=pass" in auth_combined:
        auth_summary["dmarc"] = "PASS"
    elif any(k in auth_combined for k in ["dmarc=fail", "action=quarantine", "action=reject"]):
        auth_summary["dmarc"] = "FAIL"
        findings.append({
            "vector": "DMARC_POLICY_FAILURE",
            "level": "CRITICAL",
            "title": "DMARC Policy Violation",
            "desc": f"The email fails domain alignment under DMARC policy for '{from_domain}'."
        })
        attack_vectors.append("DMARC_FAIL")
        risk_score += 40
    elif "dmarc=" not in auth_combined:
        auth_summary["dmarc"] = "NONE"

    # ── VECTOR 6: Envelope Return-Path & Reply-To Hijacking ──
    if from_domain and return_domain and from_domain != return_domain:
        findings.append({
            "vector": "RETURN_PATH_HIJACK",
            "level": "CRITICAL",
            "title": "Envelope Sender (Return-Path) Mismatch",
            "desc": f"Display From domain ('{from_domain}') differs from the server delivery Return-Path ('{return_domain}')."
        })
        attack_vectors.append("RETURN_PATH_MISMATCH")
        risk_score += 30

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({
            "vector": "REPLY_TO_REDIRECTION",
            "level": "CRITICAL",
            "title": "Reply-To Address Redirection",
            "desc": f"Replies to this email will NOT go to '{from_domain}', but will secretly redirect to '@{reply_domain}'."
        })
        attack_vectors.append("REPLY_TO_HIJACK")
        risk_score += 30

    # ── VECTOR 7: BEC & Financial Wire Fraud Patterns ──
    combined_body = (subject + " " + sanitized_text).lower()
    bec_triggers = []
    for pat in BEC_FINANCIAL_PATTERNS:
        if re.search(pat, combined_body):
            bec_triggers.append(pat.replace(r"\s*", " ").replace(r"\b", "").replace("?", ""))

    if bec_triggers:
        findings.append({
            "vector": "BEC_FINANCIAL_FRAUD",
            "level": "CRITICAL",
            "title": "Business Email Compromise (BEC) Wire Fraud Markers",
            "desc": f"Detected wire transfer / banking redirection language: {', '.join(bec_triggers[:3])}."
        })
        attack_vectors.append("BEC_WIRE_FRAUD")
        risk_score += 35

    # ── VECTOR 8: Phishing Urgency Keywords ──
    found_urgency = [kw for kw in PHISHING_URGENCY_KEYWORDS if kw in combined_body]
    if found_urgency:
        findings.append({
            "vector": "URGENCY_HEURISTICS",
            "level": "WARN",
            "title": "Psychological Coercion & Urgency Triggers",
            "desc": f"High-pressure psychological triggers detected: {', '.join(found_urgency[:4])}."
        })
        risk_score += min(len(found_urgency) * 8, 24)

    # ── VECTOR 9: Suspicious TLD & Evasive Links / Open Redirects ──
    if any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        findings.append({
            "vector": "SUSPICIOUS_TLD",
            "level": "WARN",
            "title": "High-Risk Top Level Domain (TLD)",
            "desc": f"Sender domain uses a TLD with known high spam abuse rates: '{from_domain}'."
        })
        risk_score += 20

    # Extract URLs from message
    all_urls = extract_urls(sanitized_text)
    url_threats = []
    for u in all_urls:
        u_lower = u.lower()
        # Raw IP host
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower):
            url_threats.append(f"Direct Raw IP URL: {u[:60]}")
        # Open redirect
        if any(red in u_lower for red in OPEN_REDIRECT_HOSTS):
            url_threats.append(f"Open Redirect Link: {u[:60]}")
        # Free hosting abuse
        if any(re.search(fh, u_lower) for fh in FREE_HOSTING_PHISH_PATTERNS):
            url_threats.append(f"Free Hosting Credential Harvester: {u[:60]}")

    if url_threats:
        findings.append({
            "vector": "MALICIOUS_LINKS",
            "level": "CRITICAL",
            "title": "Evasive Link / Open Redirect Detected",
            "desc": "; ".join(url_threats[:3])
        })
        attack_vectors.append("EVASIVE_LINKS")
        risk_score += 35

    # ── VECTOR 10: Hop Route Tracing & Originating Server ──
    hop_details = []
    originating_ip = None

    for i, r in enumerate(reversed(received)):
        ips = extract_ips(r)
        ptr = reverse_dns_lookup(ips[0]) if ips else None
        hop_info = {
            "hop": i + 1,
            "raw": r[:120] + ("..." if len(r) > 120 else ""),
            "ips": ips,
            "ptr": ptr
        }
        hop_details.append(hop_info)
        if not originating_ip and ips:
            originating_ip = ips[0]

    # Live DNS Check
    if from_domain:
        dns_res = check_live_dns(from_domain)
        if not dns_res["has_dns"]:
            findings.append({
                "vector": "NON_EXISTENT_DOMAIN",
                "level": "CRITICAL",
                "title": "Non-Existent Sender Domain",
                "desc": f"The domain '{from_domain}' does not exist on global public DNS servers (Dead / Burner Domain)."
            })
            attack_vectors.append("DEAD_DOMAIN")
            risk_score += 50

    # Score Normalization
    risk_score = min(100, max(0, risk_score))

    # Verdict Determination
    if risk_score >= 60:
        verdict = "MALICIOUS / SPOOFED"
        verdict_color = "#ff3366"
        summary_text = "CRITICAL THREAT: High probability of targeted phishing, brand impersonation, or credential harvesting."
    elif risk_score >= 25:
        verdict = "SUSPICIOUS / HIGH RISK"
        verdict_color = "#ff9900"
        summary_text = "SUSPICIOUS: Inconsistencies detected in authentication, routing, or content heuristics."
    else:
        verdict = "LEGITIMATE / CLEAN"
        verdict_color = "#00ff9d"
        summary_text = "PASS: Email headers conform to authentication standards without obvious red flags."

    # Forensic Explanation: WHY THIS IS SPAM / PHISHING
    why_it_is_spam = generate_why_explanation(
        verdict, risk_score, display_name, from_domain, return_domain, reply_domain,
        auth_summary, attack_vectors, findings
    )

    recommendations = generate_soc_recommendations(risk_score, attack_vectors, from_domain, originating_ip)

    return {
        "verdict": verdict,
        "verdict_color": verdict_color,
        "risk_score": risk_score,
        "summary": summary_text,
        "attack_vectors": attack_vectors,
        "headers": {
            "from": from_header,
            "display_name": display_name,
            "sender_email": sender_email,
            "from_domain": from_domain,
            "return_path": return_path,
            "return_domain": return_domain,
            "reply_to": reply_to,
            "reply_domain": reply_domain,
            "subject": subject,
            "date": date_header,
            "message_id": msg_id,
            "originating_ip": originating_ip
        },
        "auth": auth_summary,
        "findings": findings,
        "hops": hop_details,
        "detected_urls": all_urls[:10],
        "explanation": why_it_is_spam,
        "recommendations": recommendations,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def generate_why_explanation(verdict, score, display_name, from_domain, return_domain, reply_domain, auth, vectors, findings):
    """
    Produces a crystal-clear, plain English SOC analyst explanation of WHY this email is fraudulent.
    """
    if score < 25:
        return (
            f"This email from '{from_domain}' passed all security integrity checks. "
            f"Cryptographic signatures (SPF: {auth['spf']}, DKIM: {auth['dkim']}) verified that the sender "
            "is legally authorized to deliver on behalf of this domain. No spoofing or tampering was detected."
        )

    points = []
    points.append(f"This email was classified as **{verdict} (Risk Score: {score}/100)** for the following concrete reasons:")

    if "DISPLAY_NAME_IMPERSONATION" in vectors:
        points.append(f"• **Visual Identity Fraud**: The email tricks the recipient by setting the display name to '{display_name}', but the real sending address is actually from '@{from_domain}'. Attackers rely on mail apps (especially on smartphones) only showing the name and hiding the real email address.")

    if "HOMOGLYPH_PUNYCODE" in vectors:
        points.append(f"• **Cyrillic/Punycode Deception**: The domain '@{from_domain}' looks identical to a trusted brand, but uses non-Latin characters (IDN) to fool your eyes.")

    if "TYPOSQUATTING" in vectors:
        points.append(f"• **Lookalike Typosquatting**: The sender domain '@{from_domain}' intentionally mimics a legitimate service using letter swaps or extra hyphenated words.")

    if "RETURN_PATH_MISMATCH" in vectors:
        points.append(f"• **Sender Identity Mismatch**: The visible 'From' address claims to be from '{from_domain}', but the server delivery envelope ('Return-Path') points to a completely different domain ('{return_domain}'). This proves sender forgery.")

    if "REPLY_TO_HIJACK" in vectors:
        points.append(f"• **Secret Reply Redirection**: If a victim replies to this email, the reply will be redirected to '@{reply_domain}', enabling the attacker to intercept communications.")

    if "SPF_FAIL" in vectors or "DKIM_FAIL" in vectors or "DMARC_FAIL" in vectors:
        points.append(f"• **Cryptographic Authentication Failure**: The email failed domain authentication (SPF: {auth['spf']}, DKIM: {auth['dkim']}, DMARC: {auth['dmarc']}). The sending server does not possess the legitimate cryptographic keys of the genuine domain.")

    if "BEC_WIRE_FRAUD" in vectors:
        points.append("• **Wire Transfer / BEC Attack**: The message contains urgent requests to modify banking details or initiate immediate wire payments, a hallmark of Business Email Compromise.")

    if "EVASIVE_LINKS" in vectors:
        points.append("• **Malicious Links & Open Redirects**: Links in the message abuse open redirect services or free cloud hosting to stealthily bypass gateway URL scanners.")

    points.append("\n**Conclusion:** This is a fraudulent email. Do NOT click any links, open attachments, or reply.")
    return "\n\n".join(points)

def generate_soc_recommendations(score, vectors, domain, ip):
    actions = []
    if score >= 60:
        actions.append(f"🛑 Immediately quarantine or delete this message across the email gateway.")
        if ip:
            actions.append(f"🚫 Block originating IP '{ip}' on firewall and mail filtering rules.")
        if domain:
            actions.append(f"🛡️ Add domain '{domain}' to company-wide blacklists.")
        actions.append("⚠️ If user entered credentials, initiate immediate password resets and revoke active OAuth tokens.")
        actions.append("🔍 Search mail logs (M365 / Google Workspace) to see if other employees received messages from this sender.")
    elif score >= 25:
        actions.append("📞 Verify sender validity via a secondary channel (e.g. phone call or internal chat).")
        actions.append("🔎 Inspect all links with a URL sandbox before interacting.")
        actions.append("📎 Detonate any attachments in an isolated sandbox.")
    else:
        actions.append("✅ Email appears legitimate. Standard corporate email security practices apply.")
    return actions
