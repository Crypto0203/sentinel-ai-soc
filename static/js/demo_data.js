window.DEMO_FALLBACK_DATA = {
  "phishing": {
    "risk_score_100": 100,
    "verdict": "\ud83d\udd34 HIGH RISK EMAIL \u2014 LIKELY PHISHING",
    "confidence_score": 1.0,
    "forensic_evidence": [
      {
        "category": "dmarc_fail_reject",
        "severity": "CRITICAL",
        "description": "Inbound Authentication-Results reports DMARC policy validation failed."
      },
      {
        "category": "spf_fail",
        "severity": "CRITICAL",
        "description": "Inbound Authentication-Results reports SPF check failed."
      },
      {
        "category": "dkim_fail",
        "severity": "HIGH",
        "description": "Inbound Authentication-Results reports DKIM signature verification failed."
      },
      {
        "category": "envelope_alignment_fail",
        "severity": "HIGH",
        "description": "SPF Alignment Failure: Envelope Return-Path domain 'evil-relay.xyz' differs from From domain 'paypal.com'."
      },
      {
        "category": "suspicious_tld",
        "severity": "HIGH",
        "description": "Domain 'evil-relay.xyz' uses a known high-abuse phishing TLD."
      },
      {
        "category": "url_raw_ip",
        "severity": "HIGH",
        "description": "Link uses a raw IP address instead of a domain: http://198.51.100.42/auth/login?redirect=https://paypal.com/signin"
      },
      {
        "category": "reply_to_mismatch",
        "severity": "MEDIUM",
        "description": "Reply-To domain 'stealth-inbox.top' differs from From domain 'paypal.com'."
      },
      {
        "category": "url_open_redirect",
        "severity": "MEDIUM",
        "description": "Link uses an open-redirect pattern: http://198.51.100.42/auth/login?redirect=https://paypal.com/signin"
      },
      {
        "category": "bec_urgency_language",
        "severity": "MEDIUM",
        "description": "Subject or body contains urgency/coercion language typical of phishing."
      }
    ],
    "authentication": {
      "spf": "FAIL",
      "dkim": "FAIL",
      "dmarc": "FAIL"
    },
    "attack_vectors": [
      "spf_fail",
      "dkim_fail",
      "dmarc_fail_reject",
      "envelope_alignment_fail",
      "suspicious_tld",
      "reply_to_mismatch",
      "url_raw_ip",
      "url_open_redirect",
      "bec_urgency_language"
    ],
    "primary_attack_vector": "dmarc_fail_reject",
    "why_it_is_spam_explanation": "This message was classified with elevated risk primarily because: Inbound Authentication-Results reports DMARC policy validation failed. (9 total threat indicator(s) verified, calibrated risk score: 100/100).",
    "soc_recommended_actions": [
      "Quarantine the message immediately across all enterprise user mailboxes.",
      "Block the sending domain and originating relay IP at the corporate mail gateway.",
      "If any recipient clicked enclosed links or downloaded attachments, initiate endpoint isolation and credential reset.",
      "Submit indicators (domain, IP, URL, attachment hash) to your SIEM / threat-intelligence platform."
    ],
    "risk_score": 100,
    "auth": {
      "spf": "FAIL",
      "dkim": "FAIL",
      "dmarc": "FAIL"
    },
    "findings": [
      {
        "level": "CRITICAL",
        "desc": "Inbound Authentication-Results reports DMARC policy validation failed."
      },
      {
        "level": "CRITICAL",
        "desc": "Inbound Authentication-Results reports SPF check failed."
      },
      {
        "level": "HIGH",
        "desc": "Inbound Authentication-Results reports DKIM signature verification failed."
      },
      {
        "level": "HIGH",
        "desc": "SPF Alignment Failure: Envelope Return-Path domain 'evil-relay.xyz' differs from From domain 'paypal.com'."
      },
      {
        "level": "HIGH",
        "desc": "Domain 'evil-relay.xyz' uses a known high-abuse phishing TLD."
      },
      {
        "level": "HIGH",
        "desc": "Link uses a raw IP address instead of a domain: http://198.51.100.42/auth/login?redirect=https://paypal.com/signin"
      },
      {
        "level": "MEDIUM",
        "desc": "Reply-To domain 'stealth-inbox.top' differs from From domain 'paypal.com'."
      },
      {
        "level": "MEDIUM",
        "desc": "Link uses an open-redirect pattern: http://198.51.100.42/auth/login?redirect=https://paypal.com/signin"
      },
      {
        "level": "MEDIUM",
        "desc": "Subject or body contains urgency/coercion language typical of phishing."
      }
    ],
    "headers": {
      "from": "\"PayPal Security Dept\" <service@paypal.com>",
      "return_path": "<bounce-alert@evil-relay.xyz>",
      "reply_to": "<credential-harvest@stealth-inbox.top>",
      "subject": "URGENT: Your PayPal Business Account is Suspended - Action Required Immediately",
      "date": "Wed, 10 Sep 2026 15:19:50 +0000",
      "message_id": "<20260910151950.4812@evil-relay.xyz>",
      "originating_ip": "198.51.100.42"
    },
    "explanation": "This message was classified with elevated risk primarily because: Inbound Authentication-Results reports DMARC policy validation failed. (9 total threat indicator(s) verified, calibrated risk score: 100/100).",
    "recommendations": [
      "Quarantine the message immediately across all enterprise user mailboxes.",
      "Block the sending domain and originating relay IP at the corporate mail gateway.",
      "If any recipient clicked enclosed links or downloaded attachments, initiate endpoint isolation and credential reset.",
      "Submit indicators (domain, IP, URL, attachment hash) to your SIEM / threat-intelligence platform."
    ],
    "attachments_scanned": [],
    "classification": "phishing",
    "severity": "critical",
    "verdict_color": "#ff1744",
    "route_hops": [
      {
        "hop_number": 1,
        "from_host": "mail.evil-relay.xyz",
        "by_host": "mx.google.com",
        "ip": "198.51.100.42",
        "protocol": "ESMTPS",
        "geo": "Origin Host [External Network]",
        "rdns": "No PTR / Untrusted Relay",
        "reputation": "Suspicious",
        "status_color": "#ff3366"
      }
    ],
    "urls_detailed": [
      {
        "url": "http://198.51.100.42/auth/login?redirect=https://paypal.com/signin",
        "domain": "198.51.100.42",
        "is_https": false,
        "has_redirect": true,
        "is_raw_ip": true,
        "risk": "CRITICAL",
        "indicators": [
          "Raw IP Host (No Domain)",
          "Insecure HTTP Transmission",
          "Open Redirect / Parameter Masking"
        ],
        "status": "FLAGGED",
        "status_color": "#ff1744"
      }
    ],
    "social_engineering": {
      "urgency": 88,
      "credential_harvesting": 94,
      "brand_impersonation": 82,
      "financial_fraud": 5,
      "threat_coercion": 76
    },
    "risk_breakdown": [
      {
        "category": "Authentication Integrity (SPF/DKIM/DMARC)",
        "points": 75,
        "max": 30,
        "status": "FAIL"
      },
      {
        "category": "Sender Identity & Brand Alignment",
        "points": 12,
        "max": 25,
        "status": "FLAGGED"
      },
      {
        "category": "URL & Destination Link Safety",
        "points": 25,
        "max": 25,
        "status": "HIGH RISK"
      },
      {
        "category": "Content & Social Engineering Coercion",
        "points": 10,
        "max": 20,
        "status": "FLAGGED"
      },
      {
        "category": "Domain Age & Suffix Reputation",
        "points": 35,
        "max": 20,
        "status": "SUSPICIOUS"
      },
      {
        "category": "Attachment Forensics & Macros",
        "points": 0,
        "max": 30,
        "status": "CLEAN"
      }
    ],
    "timeline": [
      {
        "step": 1,
        "time": "00:00.012",
        "title": "Email Ingestion & Format Validation",
        "status": "Complete",
        "detail": "Payload validated (1356 bytes parsed)"
      },
      {
        "step": 2,
        "time": "00:00.048",
        "title": "RFC 5322 MIME Structure Parsing",
        "status": "Complete",
        "detail": "Extracted 10 header fields"
      },
      {
        "step": 3,
        "time": "00:00.095",
        "title": "Cryptographic Authentication Audit",
        "status": "Complete",
        "detail": "SPF: FAIL, DKIM: FAIL, DMARC: FAIL"
      },
      {
        "step": 4,
        "time": "00:00.142",
        "title": "Origin Route & Server Hop Analysis",
        "status": "Complete",
        "detail": "Traced 1 network relay hop(s)"
      },
      {
        "step": 5,
        "time": "00:00.188",
        "title": "Domain Intel & Homoglyph Inspection",
        "status": "Complete",
        "detail": "Analyzed sending domain 'paypal.com'"
      },
      {
        "step": 6,
        "time": "00:00.235",
        "title": "Deep URL Extraction & Safety Sandbox",
        "status": "Complete",
        "detail": "Inspected 1 link destination(s)"
      },
      {
        "step": 7,
        "time": "00:00.279",
        "title": "Attachment Static Analysis & Hashing",
        "status": "Complete",
        "detail": "Scanned 0 attachment(s)"
      },
      {
        "step": 8,
        "time": "00:00.315",
        "title": "Social Engineering & Coercion Detection",
        "status": "Complete",
        "detail": "Analyzed urgency, pressure, and credential requests"
      },
      {
        "step": 9,
        "time": "00:00.352",
        "title": "Multi-Vector Risk Scoring & Calibration",
        "status": "Complete",
        "detail": "Final calibrated risk score calculated: 100/100"
      }
    ],
    "recipient": "ceo@company.com",
    "cc": "None",
    "raw_sample": "Delivered-To: ceo@company.com\nReceived: from mail.evil-relay.xyz (mail.evil-relay.xyz [198.51.100.42])\n        by mx.google.com with ESMTPS id p84si1298412\n        for <ceo@company.com>; Wed, 10 Sep 2026 11:20:14 -0400\nReturn-Path: <bounce-alert@evil-relay.xyz>\nAuthentication-Results: mx.google.com;\n       spf=fail (google.com: domain of bounce-alert@evil-relay.xyz does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=bounce-alert@evil-relay.xyz;\n       dkim=fail header.i=@paypal.com;\n       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com\nFrom: \"PayPal Security Dept\" <service@paypal.com>\nReply-To: <credential-harvest@stealth-inbox.top>\nTo: ceo@company.com\nSubject: URGENT: Your PayPal Business Account is Suspended - Action Required Immediately\nDate: Wed, 10 Sep 2026 15:19:50 +0000\nMessage-ID: <20260910151950.4812@evil-relay.xyz>\n\nDear Valued Executive,\nWe have detected unauthorized API key access attempts on your corporate PayPal merchant account.\nYour account privileges will be permanently restricted within 24 hours unless you verify your identity.\n\nPlease click the secure verification portal immediately:\nhttp://198.51.100.42/auth/login?redirect=https://paypal.com/signin\n\nFailure to comply will result in immediate suspension and forfeiture of pending wire transfers.\nSincerely,\nPayPal Fraud Prevention Team"
  },
  "suspicious": {
    "risk_score_100": 44,
    "verdict": "\ud83d\udfe1 SUSPICIOUS EMAIL \u2014 MANUAL REVIEW REQUIRED",
    "confidence_score": 0.65,
    "forensic_evidence": [
      {
        "category": "bec_wire_transfer_request",
        "severity": "HIGH",
        "description": "Subject or body references wire transfer, banking changes, or gift cards."
      },
      {
        "category": "reply_to_mismatch",
        "severity": "MEDIUM",
        "description": "Reply-To domain 'secure-offshore-desk.top' differs from From domain 'gmail.com'."
      },
      {
        "category": "bec_urgency_language",
        "severity": "MEDIUM",
        "description": "Subject or body contains urgency/coercion language typical of phishing."
      }
    ],
    "authentication": {
      "spf": "NONE",
      "dkim": "NONE",
      "dmarc": "NONE"
    },
    "attack_vectors": [
      "reply_to_mismatch",
      "bec_urgency_language",
      "bec_wire_transfer_request"
    ],
    "primary_attack_vector": "bec_wire_transfer_request",
    "why_it_is_spam_explanation": "This message was classified with elevated risk primarily because: Subject or body references wire transfer, banking changes, or gift cards. (3 total threat indicator(s) verified, calibrated risk score: 44/100).",
    "soc_recommended_actions": [
      "Route message to user spam or promotional folder.",
      "Block unsolicited promotional sending domain if repeated bulk marketing abuse occurs."
    ],
    "risk_score": 44,
    "auth": {
      "spf": "NONE",
      "dkim": "NONE",
      "dmarc": "NONE"
    },
    "findings": [
      {
        "level": "HIGH",
        "desc": "Subject or body references wire transfer, banking changes, or gift cards."
      },
      {
        "level": "MEDIUM",
        "desc": "Reply-To domain 'secure-offshore-desk.top' differs from From domain 'gmail.com'."
      },
      {
        "level": "MEDIUM",
        "desc": "Subject or body contains urgency/coercion language typical of phishing."
      }
    ],
    "headers": {
      "from": "\"Alex Johnson (CEO)\" <alex.ceo.private@gmail.com>",
      "return_path": "<alex.ceo.private@gmail.com>",
      "reply_to": "<acquisitions-wire@secure-offshore-desk.top>",
      "subject": "CONFIDENTIAL: Urgent Acquisition Wire Transfer Required Today",
      "date": "Wed, 10 Sep 2026 09:11:45 -0400",
      "message_id": "<CAB2x8001@mail.gmail.com>",
      "originating_ip": "192.0.2.77"
    },
    "explanation": "This message was classified with elevated risk primarily because: Subject or body references wire transfer, banking changes, or gift cards. (3 total threat indicator(s) verified, calibrated risk score: 44/100).",
    "recommendations": [
      "Route message to user spam or promotional folder.",
      "Block unsolicited promotional sending domain if repeated bulk marketing abuse occurs."
    ],
    "attachments_scanned": [],
    "classification": "suspicious",
    "severity": "medium",
    "verdict_color": "#ffd600",
    "route_hops": [
      {
        "hop_number": 1,
        "from_host": "mail-relay.partner-network.com",
        "by_host": "mx.google.com",
        "ip": "192.0.2.77",
        "protocol": "ESMTPS",
        "geo": "Origin Host [External Network]",
        "rdns": "Reverse DNS Verified",
        "reputation": "Verified",
        "status_color": "#00e676"
      }
    ],
    "urls_detailed": [],
    "social_engineering": {
      "urgency": 88,
      "credential_harvesting": 10,
      "brand_impersonation": 8,
      "financial_fraud": 91,
      "threat_coercion": 12
    },
    "risk_breakdown": [
      {
        "category": "Authentication Integrity (SPF/DKIM/DMARC)",
        "points": 0,
        "max": 30,
        "status": "PASS"
      },
      {
        "category": "Sender Identity & Brand Alignment",
        "points": 12,
        "max": 25,
        "status": "FLAGGED"
      },
      {
        "category": "URL & Destination Link Safety",
        "points": 0,
        "max": 25,
        "status": "SAFE"
      },
      {
        "category": "Content & Social Engineering Coercion",
        "points": 32,
        "max": 20,
        "status": "FLAGGED"
      },
      {
        "category": "Domain Age & Suffix Reputation",
        "points": 0,
        "max": 20,
        "status": "OK"
      },
      {
        "category": "Attachment Forensics & Macros",
        "points": 0,
        "max": 30,
        "status": "CLEAN"
      }
    ],
    "timeline": [
      {
        "step": 1,
        "time": "00:00.012",
        "title": "Email Ingestion & Format Validation",
        "status": "Complete",
        "detail": "Payload validated (978 bytes parsed)"
      },
      {
        "step": 2,
        "time": "00:00.048",
        "title": "RFC 5322 MIME Structure Parsing",
        "status": "Complete",
        "detail": "Extracted 9 header fields"
      },
      {
        "step": 3,
        "time": "00:00.095",
        "title": "Cryptographic Authentication Audit",
        "status": "Complete",
        "detail": "SPF: NONE, DKIM: NONE, DMARC: NONE"
      },
      {
        "step": 4,
        "time": "00:00.142",
        "title": "Origin Route & Server Hop Analysis",
        "status": "Complete",
        "detail": "Traced 1 network relay hop(s)"
      },
      {
        "step": 5,
        "time": "00:00.188",
        "title": "Domain Intel & Homoglyph Inspection",
        "status": "Complete",
        "detail": "Analyzed sending domain 'gmail.com'"
      },
      {
        "step": 6,
        "time": "00:00.235",
        "title": "Deep URL Extraction & Safety Sandbox",
        "status": "Complete",
        "detail": "Inspected 0 link destination(s)"
      },
      {
        "step": 7,
        "time": "00:00.279",
        "title": "Attachment Static Analysis & Hashing",
        "status": "Complete",
        "detail": "Scanned 0 attachment(s)"
      },
      {
        "step": 8,
        "time": "00:00.315",
        "title": "Social Engineering & Coercion Detection",
        "status": "Complete",
        "detail": "Analyzed urgency, pressure, and credential requests"
      },
      {
        "step": 9,
        "time": "00:00.352",
        "title": "Multi-Vector Risk Scoring & Calibration",
        "status": "Complete",
        "detail": "Final calibrated risk score calculated: 44/100"
      }
    ],
    "recipient": "cfo@company.com",
    "cc": "None",
    "raw_sample": "Delivered-To: cfo@company.com\nReceived: from mail-relay.partner-network.com (mail-relay.partner-network.com [192.0.2.77])\n        by mx.google.com with ESMTPS id b29si91283\n        for <cfo@company.com>; Wed, 10 Sep 2026 09:12:00 -0400\nReturn-Path: <alex.ceo.private@gmail.com>\nFrom: \"Alex Johnson (CEO)\" <alex.ceo.private@gmail.com>\nReply-To: <acquisitions-wire@secure-offshore-desk.top>\nTo: cfo@company.com\nSubject: CONFIDENTIAL: Urgent Acquisition Wire Transfer Required Today\nDate: Wed, 10 Sep 2026 09:11:45 -0400\nMessage-ID: <CAB2x8001@mail.gmail.com>\n\nHi,\nI am currently locked in confidential M&A board meetings and cannot take calls.\nWe need to process an immediate, time-sensitive earnest money deposit of $185,000 for the acquisition today.\n\nPlease confirm you are at your desk so I can send over the updated beneficiary banking details, SWIFT code, and routing number.\nKeep this strictly confidential between us for now.\n\nRegards,\nAlex Johnson\nChief Executive Officer"
  },
  "spam": {
    "risk_score_100": 30,
    "verdict": "\ud83d\udfe0 DETECTED AS SPAM / PROMOTIONAL",
    "confidence_score": 0.65,
    "forensic_evidence": [
      {
        "category": "suspicious_tld",
        "severity": "HIGH",
        "description": "Domain 'b2b-blast-host.club' uses a known high-abuse phishing TLD."
      },
      {
        "category": "unsolicited_bulk_marketing",
        "severity": "MEDIUM",
        "description": "Subject or body contains bulk promotional marketing, discount, or sales lead offers."
      }
    ],
    "authentication": {
      "spf": "NONE",
      "dkim": "NONE",
      "dmarc": "NONE"
    },
    "attack_vectors": [
      "suspicious_tld",
      "unsolicited_bulk_marketing"
    ],
    "primary_attack_vector": "suspicious_tld",
    "why_it_is_spam_explanation": "This message was classified with elevated risk primarily because: Domain 'b2b-blast-host.club' uses a known high-abuse phishing TLD. (2 total threat indicator(s) verified, calibrated risk score: 30/100).",
    "soc_recommended_actions": [
      "Route message to user spam or promotional folder.",
      "Block unsolicited promotional sending domain if repeated bulk marketing abuse occurs."
    ],
    "risk_score": 30,
    "auth": {
      "spf": "NONE",
      "dkim": "NONE",
      "dmarc": "NONE"
    },
    "findings": [
      {
        "level": "HIGH",
        "desc": "Domain 'b2b-blast-host.club' uses a known high-abuse phishing TLD."
      },
      {
        "level": "MEDIUM",
        "desc": "Subject or body contains bulk promotional marketing, discount, or sales lead offers."
      }
    ],
    "headers": {
      "from": "\"Global Enterprise B2B Growth\" <leads@b2b-blast-host.club>",
      "return_path": "<campaign@b2b-blast-host.club>",
      "reply_to": "<leads@b2b-blast-host.club>",
      "subject": "Exclusive Offer: 50,000 Verified B2B Decision Maker Emails at 80% Discount!",
      "date": "Wed, 10 Sep 2026 08:30:00 -0400",
      "message_id": "<spam-blast-20260910@b2b-blast-host.club>",
      "originating_ip": "203.0.113.88"
    },
    "explanation": "This message was classified with elevated risk primarily because: Domain 'b2b-blast-host.club' uses a known high-abuse phishing TLD. (2 total threat indicator(s) verified, calibrated risk score: 30/100).",
    "recommendations": [
      "Route message to user spam or promotional folder.",
      "Block unsolicited promotional sending domain if repeated bulk marketing abuse occurs."
    ],
    "attachments_scanned": [],
    "classification": "spam",
    "severity": "low",
    "verdict_color": "#ff9100",
    "route_hops": [
      {
        "hop_number": 1,
        "from_host": "b2b-blast-host.club",
        "by_host": "mx.google.com",
        "ip": "203.0.113.88",
        "protocol": "ESMTP",
        "geo": "Origin Host [External Network]",
        "rdns": "No PTR / Untrusted Relay",
        "reputation": "Suspicious",
        "status_color": "#ff3366"
      }
    ],
    "urls_detailed": [
      {
        "url": "http://b2b-blast-host.club/special-offer?promo=CEO80",
        "domain": "b2b-blast-host.club",
        "is_https": false,
        "has_redirect": false,
        "is_raw_ip": false,
        "risk": "MEDIUM",
        "indicators": [
          "Insecure HTTP Transmission"
        ],
        "status": "REVIEW",
        "status_color": "#ffb300"
      },
      {
        "url": "http://b2b-blast-host.club/opt-out",
        "domain": "b2b-blast-host.club",
        "is_https": false,
        "has_redirect": false,
        "is_raw_ip": false,
        "risk": "MEDIUM",
        "indicators": [
          "Insecure HTTP Transmission"
        ],
        "status": "REVIEW",
        "status_color": "#ffb300"
      }
    ],
    "social_engineering": {
      "urgency": 15,
      "credential_harvesting": 10,
      "brand_impersonation": 8,
      "financial_fraud": 5,
      "threat_coercion": 12
    },
    "risk_breakdown": [
      {
        "category": "Authentication Integrity (SPF/DKIM/DMARC)",
        "points": 0,
        "max": 30,
        "status": "PASS"
      },
      {
        "category": "Sender Identity & Brand Alignment",
        "points": 0,
        "max": 25,
        "status": "CLEAN"
      },
      {
        "category": "URL & Destination Link Safety",
        "points": 0,
        "max": 25,
        "status": "SAFE"
      },
      {
        "category": "Content & Social Engineering Coercion",
        "points": 0,
        "max": 20,
        "status": "CLEAN"
      },
      {
        "category": "Domain Age & Suffix Reputation",
        "points": 15,
        "max": 20,
        "status": "SUSPICIOUS"
      },
      {
        "category": "Attachment Forensics & Macros",
        "points": 0,
        "max": 30,
        "status": "CLEAN"
      }
    ],
    "timeline": [
      {
        "step": 1,
        "time": "00:00.012",
        "title": "Email Ingestion & Format Validation",
        "status": "Complete",
        "detail": "Payload validated (1011 bytes parsed)"
      },
      {
        "step": 2,
        "time": "00:00.048",
        "title": "RFC 5322 MIME Structure Parsing",
        "status": "Complete",
        "detail": "Extracted 9 header fields"
      },
      {
        "step": 3,
        "time": "00:00.095",
        "title": "Cryptographic Authentication Audit",
        "status": "Complete",
        "detail": "SPF: NONE, DKIM: NONE, DMARC: NONE"
      },
      {
        "step": 4,
        "time": "00:00.142",
        "title": "Origin Route & Server Hop Analysis",
        "status": "Complete",
        "detail": "Traced 1 network relay hop(s)"
      },
      {
        "step": 5,
        "time": "00:00.188",
        "title": "Domain Intel & Homoglyph Inspection",
        "status": "Complete",
        "detail": "Analyzed sending domain 'b2b-blast-host.club'"
      },
      {
        "step": 6,
        "time": "00:00.235",
        "title": "Deep URL Extraction & Safety Sandbox",
        "status": "Complete",
        "detail": "Inspected 2 link destination(s)"
      },
      {
        "step": 7,
        "time": "00:00.279",
        "title": "Attachment Static Analysis & Hashing",
        "status": "Complete",
        "detail": "Scanned 0 attachment(s)"
      },
      {
        "step": 8,
        "time": "00:00.315",
        "title": "Social Engineering & Coercion Detection",
        "status": "Complete",
        "detail": "Analyzed urgency, pressure, and credential requests"
      },
      {
        "step": 9,
        "time": "00:00.352",
        "title": "Multi-Vector Risk Scoring & Calibration",
        "status": "Complete",
        "detail": "Final calibrated risk score calculated: 30/100"
      }
    ],
    "recipient": "team@company.com",
    "cc": "None",
    "raw_sample": "Delivered-To: team@company.com\nReceived: from b2b-blast-host.club (b2b-blast-host.club [203.0.113.88])\n        by mx.google.com with ESMTP id z91283\n        for <team@company.com>; Wed, 10 Sep 2026 08:30:10 -0400\nReturn-Path: <campaign@b2b-blast-host.club>\nFrom: \"Global Enterprise B2B Growth\" <leads@b2b-blast-host.club>\nReply-To: <leads@b2b-blast-host.club>\nTo: team@company.com\nSubject: Exclusive Offer: 50,000 Verified B2B Decision Maker Emails at 80% Discount!\nDate: Wed, 10 Sep 2026 08:30:00 -0400\nMessage-ID: <spam-blast-20260910@b2b-blast-host.club>\n\nHello Business Leader,\nAre you looking to skyrocket your sales pipeline this quarter?\nWe are offering our complete Q3 verified list of 50,000 corporate decision makers with direct mobile numbers and LinkedIn URLs!\n\nClick here to claim your 80% promotional discount: http://b2b-blast-host.club/special-offer?promo=CEO80\nLimited time offer expiring at midnight!\n\nTo unsubscribe from future marketing blasts, click here: http://b2b-blast-host.club/opt-out"
  },
  "safe": {
    "risk_score_100": 0,
    "verdict": "\ud83d\udfe2 LEGITIMATE & SAFE EMAIL",
    "confidence_score": 0.5,
    "forensic_evidence": [],
    "authentication": {
      "spf": "PASS",
      "dkim": "PASS",
      "dmarc": "PASS"
    },
    "attack_vectors": [],
    "primary_attack_vector": "NONE_DETECTED",
    "why_it_is_spam_explanation": "No significant threat indicators were detected in this message. Cryptographic authentication, domain alignment, and URL parameters passed standard security thresholds.",
    "soc_recommended_actions": [
      "No action required \u2014 deliver normally to user inbox."
    ],
    "risk_score": 0,
    "auth": {
      "spf": "PASS",
      "dkim": "PASS",
      "dmarc": "PASS"
    },
    "findings": [],
    "headers": {
      "from": "\"Acme Enterprise Systems\" <notifications@acme-systems.com>",
      "return_path": "<notifications@acme-systems.com>",
      "reply_to": "",
      "subject": "Monthly Service Health Report & SOC2 Compliance Summary",
      "date": "Wed, 10 Sep 2026 11:05:00 +0000",
      "message_id": "<acme-report-20260910-91823@acme-systems.com>",
      "originating_ip": "209.85.220.41"
    },
    "explanation": "No significant threat indicators were detected in this message. Cryptographic authentication, domain alignment, and URL parameters passed standard security thresholds.",
    "recommendations": [
      "No action required \u2014 deliver normally to user inbox."
    ],
    "attachments_scanned": [],
    "classification": "safe",
    "severity": "safe",
    "verdict_color": "#00e676",
    "route_hops": [
      {
        "hop_number": 1,
        "from_host": "mail-sor-f41.google.com",
        "by_host": "mx.google.com",
        "ip": "209.85.220.41",
        "protocol": "SMTPS",
        "geo": "Origin Host [External Network]",
        "rdns": "Reverse DNS Verified",
        "reputation": "Verified",
        "status_color": "#00e676"
      }
    ],
    "urls_detailed": [
      {
        "url": "https://acme-systems.com/portal/compliance/reports",
        "domain": "acme-systems.com",
        "is_https": true,
        "has_redirect": false,
        "is_raw_ip": false,
        "risk": "SAFE",
        "indicators": [
          "Standard Format"
        ],
        "status": "SAFE",
        "status_color": "#00e676"
      }
    ],
    "social_engineering": {
      "urgency": 15,
      "credential_harvesting": 10,
      "brand_impersonation": 8,
      "financial_fraud": 5,
      "threat_coercion": 12
    },
    "risk_breakdown": [
      {
        "category": "Authentication Integrity (SPF/DKIM/DMARC)",
        "points": 0,
        "max": 30,
        "status": "PASS"
      },
      {
        "category": "Sender Identity & Brand Alignment",
        "points": 0,
        "max": 25,
        "status": "CLEAN"
      },
      {
        "category": "URL & Destination Link Safety",
        "points": 0,
        "max": 25,
        "status": "SAFE"
      },
      {
        "category": "Content & Social Engineering Coercion",
        "points": 0,
        "max": 20,
        "status": "CLEAN"
      },
      {
        "category": "Domain Age & Suffix Reputation",
        "points": 0,
        "max": 20,
        "status": "OK"
      },
      {
        "category": "Attachment Forensics & Macros",
        "points": 0,
        "max": 30,
        "status": "CLEAN"
      }
    ],
    "timeline": [
      {
        "step": 1,
        "time": "00:00.012",
        "title": "Email Ingestion & Format Validation",
        "status": "Complete",
        "detail": "Payload validated (1292 bytes parsed)"
      },
      {
        "step": 2,
        "time": "00:00.048",
        "title": "RFC 5322 MIME Structure Parsing",
        "status": "Complete",
        "detail": "Extracted 9 header fields"
      },
      {
        "step": 3,
        "time": "00:00.095",
        "title": "Cryptographic Authentication Audit",
        "status": "Complete",
        "detail": "SPF: PASS, DKIM: PASS, DMARC: PASS"
      },
      {
        "step": 4,
        "time": "00:00.142",
        "title": "Origin Route & Server Hop Analysis",
        "status": "Complete",
        "detail": "Traced 1 network relay hop(s)"
      },
      {
        "step": 5,
        "time": "00:00.188",
        "title": "Domain Intel & Homoglyph Inspection",
        "status": "Complete",
        "detail": "Analyzed sending domain 'acme-systems.com'"
      },
      {
        "step": 6,
        "time": "00:00.235",
        "title": "Deep URL Extraction & Safety Sandbox",
        "status": "Complete",
        "detail": "Inspected 1 link destination(s)"
      },
      {
        "step": 7,
        "time": "00:00.279",
        "title": "Attachment Static Analysis & Hashing",
        "status": "Complete",
        "detail": "Scanned 0 attachment(s)"
      },
      {
        "step": 8,
        "time": "00:00.315",
        "title": "Social Engineering & Coercion Detection",
        "status": "Complete",
        "detail": "Analyzed urgency, pressure, and credential requests"
      },
      {
        "step": 9,
        "time": "00:00.352",
        "title": "Multi-Vector Risk Scoring & Calibration",
        "status": "Complete",
        "detail": "Final calibrated risk score calculated: 0/100"
      }
    ],
    "recipient": "employee@company.com",
    "cc": "None",
    "raw_sample": "Delivered-To: employee@company.com\nReceived: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])\n        by mx.google.com with SMTPS id s12sor89123;\n        Wed, 10 Sep 2026 07:05:12 -0400\nReturn-Path: <notifications@acme-systems.com>\nAuthentication-Results: mx.google.com;\n       spf=pass (google.com: domain of notifications@acme-systems.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=notifications@acme-systems.com;\n       dkim=pass header.i=@acme-systems.com;\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acme-systems.com\nFrom: \"Acme Enterprise Systems\" <notifications@acme-systems.com>\nTo: employee@company.com\nSubject: Monthly Service Health Report & SOC2 Compliance Summary\nDate: Wed, 10 Sep 2026 11:05:00 +0000\nMessage-ID: <acme-report-20260910-91823@acme-systems.com>\n\nHello Acme Enterprise Customer,\nYour automated Monthly Infrastructure Health Report for September 2026 is now available.\n\nUptime for all production clusters was 99.992%. All SOC2 Type II and ISO 27001 automated compliance telemetry passed without exceptions.\nYou can review the full report and download audit certificates at:\nhttps://acme-systems.com/portal/compliance/reports\n\nThank you for choosing Acme Enterprise Systems.\nSupport Team, Acme Enterprise Systems"
  }
};
