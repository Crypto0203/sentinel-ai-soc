import json
from core.forensics_engine import analyze_threat

def test_attack_positions():
    print("=================================================================")
    print("  CYBERSECURITY THREAT HUNTING ENGINE — MULTI-VECTOR TEST SUITE  ")
    print("=================================================================\n")

    # ── POSITION 1: Display Name Spoofing (VIP / Brand Impersonation) ──
    print(">>> [TEST POSITION 1]: Display Name VIP Spoofing (Microsoft Account Team)")
    raw_1 = """From: "Microsoft Security Team" <admin-notify849@freemail-service.xyz>
Return-Path: <admin-notify849@freemail-service.xyz>
Authentication-Results: mx.google.com; spf=pass; dkim=none
Subject: Security Alert: Your Microsoft 365 Password Expires Today
Date: Thu, 10 Sep 2026 14:00:00 +0000

Dear Employee,
Your Microsoft password has expired. Click here to retain your credentials."""
    
    res_1 = analyze_threat(raw_1)
    print(f"Verdict: {res_1['verdict']} | Score: {res_1['risk_score']}/100")
    print(f"Vectors: {res_1['attack_vectors']}")
    assert "DISPLAY_NAME_IMPERSONATION" in res_1["attack_vectors"]
    print("  --> PASSED: Successfully caught Display Name Impersonation!\n")

    # ── POSITION 2: Business Email Compromise (BEC) Wire Fraud ──
    print(">>> [TEST POSITION 2]: Business Email Compromise (BEC) & Wire Transfer")
    raw_2 = """From: "CFO Robert Vance" <robert.vance@company-legit.com>
Return-Path: <attacker-relay@hacker-server.top>
Reply-To: <exec-finance@collector-box.net>
Authentication-Results: mx.company.com; spf=fail; dmarc=fail
Subject: URGENT: Updated Banking Details for Overdue Invoice Payment

Please find our updated banking details and routing number attached.
Process this wire transfer request immediately before end of day."""

    res_2 = analyze_threat(raw_2)
    print(f"Verdict: {res_2['verdict']} | Score: {res_2['risk_score']}/100")
    print(f"Vectors: {res_2['attack_vectors']}")
    assert "BEC_WIRE_FRAUD" in res_2["attack_vectors"]
    assert "REPLY_TO_HIJACK" in res_2["attack_vectors"]
    print("  --> PASSED: Successfully caught BEC Wire Transfer & Reply-To Hijack!\n")

    # ── POSITION 3: Lookalike Typosquatting / Cousin Domain ──
    print(">>> [TEST POSITION 3]: Lookalike Typosquatting ('rnicrosoft-cloud.com')")
    raw_3 = """From: "Office Support" <billing@rnicrosoft-cloud.com>
Return-Path: <billing@rnicrosoft-cloud.com>
Subject: Action Required: Renew Office Subscription
Authentication-Results: mx.google.com; spf=pass; dkim=pass

Your subscription is overdue. Please log in."""

    res_3 = analyze_threat(raw_3)
    print(f"Verdict: {res_3['verdict']} | Score: {res_3['risk_score']}/100")
    print(f"Vectors: {res_3['attack_vectors']}")
    assert "TYPOSQUATTING" in res_3["attack_vectors"]
    print("  --> PASSED: Successfully caught Typosquatting letter swap ('rn' for 'm')!\n")

    # ── POSITION 4: Zero-Width Unicode Evasion ──
    print(">>> [TEST POSITION 4]: Zero-Width Unicode Character Evasion")
    # Injected with \u200b inside "password" and "verify"
    raw_4 = "From: <alert@banking-notify.xyz>\nSubject: Please p\u200ba\u200bs\u200bs\u200bw\u200bo\u200br\u200bd reset\n\nYour account has unauthorized access."
    res_4 = analyze_threat(raw_4)
    print(f"Verdict: {res_4['verdict']} | Score: {res_4['risk_score']}/100")
    print(f"Vectors: {res_4['attack_vectors']}")
    assert "ZERO_WIDTH_EVASION" in res_4["attack_vectors"]
    print("  --> PASSED: Successfully uncovered hidden Zero-Width Unicode characters!\n")

    # ── POSITION 5: Open Redirect & Free Hosting Link ──
    print(">>> [TEST POSITION 5]: Open Redirect & Free Hosting Credential Harvester")
    raw_5 = """From: "DocuSign Service" <docusign@external-signer.com>
Subject: Complete Document Signing
Authentication-Results: mx.google.com; dkim=none

Please view and sign document here: https://www.google.com/url?q=https://phish-login.firebaseapp.com/login"""

    res_5 = analyze_threat(raw_5)
    print(f"Verdict: {res_5['verdict']} | Score: {res_5['risk_score']}/100")
    print(f"Vectors: {res_5['attack_vectors']}")
    assert "EVASIVE_LINKS" in res_5["attack_vectors"]
    print("  --> PASSED: Successfully flagged Google Open Redirect & Firebase Harvester!\n")

    print("=================================================================")
    print("  ALL 5 ATTACK VECTORS CAUGHT & VALIDATED WITH 100% SUCCESS!     ")
    print("=================================================================")

if __name__ == "__main__":
    test_attack_positions()
