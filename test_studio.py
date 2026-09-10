import json
from studio_app import app

def run_tests():
    client = app.test_client()

    print("--- TEST 1: System Status ---")
    res = client.get("/api/system/status")
    print("Status code:", res.status_code)
    print("Data:", res.json)
    assert res.status_code == 200

    print("\n--- TEST 2: Forensics Analysis ---")
    headers = """From: Security <service@paypal.com>
Return-Path: <spoof@attacker.xyz>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Subject: URGENT: Verify your account immediately!"""
    res = client.post("/api/forensics/analyze", json={"headers": headers})
    print("Status code:", res.status_code)
    data = res.json
    print("Verdict:", data.get("verdict"))
    print("Risk score:", data.get("risk_score"))
    print("Auth:", data.get("auth"))
    assert res.status_code == 200
    assert "HIGH RISK" in data.get("verdict") or "PHISHING" in data.get("verdict")

    print("\n--- TEST 3: Demo Endpoints ---")
    for d_type in ["phishing", "suspicious", "spam", "safe"]:
        res_d = client.get(f"/api/forensics/demo/{d_type}")
        assert res_d.status_code == 200
        d_json = res_d.json
        print(f"Demo '{d_type}': Classification={d_json.get('classification')}, Risk={d_json.get('risk_score')}, Hops={len(d_json.get('route_hops', []))}")

    print("\n--- TEST 4: Stats & KPI Overview ---")
    res_s = client.get("/api/forensics/stats")
    assert res_s.status_code == 200
    s_json = res_s.json
    print("KPIs:", s_json.get("emails_analyzed"), "analyzed, accuracy:", s_json.get("detection_accuracy"), "%")

    print("\n==========================================")
    print("  ALL CORE BACKEND ENGINE TESTS PASSED!   ")
    print("==========================================")

if __name__ == "__main__":
    run_tests()
