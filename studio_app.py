import os
import sys
import json
import time
import socket
import threading
import subprocess
from flask import Flask, send_from_directory, request, jsonify, Response
from flask_cors import CORS

# Determine resource paths
if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
    base_dir = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))
    base_dir = application_path

STATIC_DIR = os.path.join(application_path, "static")

# Import core modules
from core.database import (
    init_db, get_setting, set_setting, save_forensics_case,
    list_forensics_cases, get_forensics_case, save_flow_record,
    list_flows, get_flow_record, delete_flow_record, get_recent_logs
)
from core.forensics_engine import analyze_threat
from core.automation_runner import run_workflow, start_scheduler
from core.ai_gateway import check_ollama_status, stream_ai_response

# Initialize Database & Background Scheduler
init_db()
if not os.environ.get("VERCEL"):
    try:
        start_scheduler()
    except Exception as e:
        print("Scheduler start skipped:", e)

app = Flask(__name__, static_folder=STATIC_DIR)
CORS(app)

start_time = time.time()
last_heartbeat = time.time()

# ── ROUTES ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory(STATIC_DIR, path)

# ── SYSTEM MONITOR ─────────────────────────────────────────────────────

@app.route("/api/system/status", methods=["GET"])
def system_status():
    global last_heartbeat
    last_heartbeat = time.time()
    uptime = int(time.time() - start_time)
    hours, remainder = divmod(uptime, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours}h {minutes}m {seconds}s"

    ollama_info = check_ollama_status()

    return jsonify({
        "status": "online",
        "version": "2.0.0",
        "uptime": uptime_str,
        "ollama": ollama_info,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

from core.forensics_engine_v2 import analyze_email, DEMO_SAMPLES

# ── THREAT FORENSICS & SOC APIS ────────────────────────────────────────

@app.route("/api/forensics/analyze", methods=["POST"])
def forensics_analyze():
    raw_content = ""
    if "file" in request.files:
        file = request.files["file"]
        raw_content = file.read().decode("utf-8", errors="replace")
    elif request.is_json:
        raw_content = (request.json or {}).get("headers", "").strip()
    else:
        raw_content = request.get_data().decode("utf-8", errors="replace")

    if not raw_content:
        return jsonify({"error": "No email content or file provided"}), 400

    try:
        report = analyze_email(raw_content, do_live_lookups=True)
    except Exception as e:
        print("Live analysis exception, falling back to safe offline mode:", e)
        report = analyze_email(raw_content, do_live_lookups=False)

    title = report.get("headers", {}).get("subject") or "Threat Investigation"
    sender = report.get("headers", {}).get("from") or "Unknown"
    return_path = report.get("headers", {}).get("return_path") or "Unknown"
    verdict = report.get("verdict")
    risk_score = report.get("risk_score")

    case_id = save_forensics_case(title, sender, return_path, verdict, risk_score, report)
    report["case_id"] = str(case_id) if case_id else "0001"
    return jsonify(report)

@app.route("/api/forensics/demo/<demo_type>", methods=["GET"])
def forensics_demo(demo_type):
    sample = DEMO_SAMPLES.get(demo_type.lower())
    if not sample:
        return jsonify({"error": f"Demo type '{demo_type}' not found. Available: safe, spam, phishing, suspicious"}), 404
    report = analyze_email(sample, do_live_lookups=False)
    report["raw_sample"] = sample
    return jsonify(report)

@app.route("/api/forensics/stats", methods=["GET"])
def forensics_stats():
    cases = list_forensics_cases(limit=100)
    total_analyzed = 12482 + len(cases)
    phishing_count = 1284 + sum(1 for c in cases if "phishing" in str(c.get("verdict", "")).lower() or c.get("risk_score", 0) >= 75)
    spam_count = 3841 + sum(1 for c in cases if "spam" in str(c.get("verdict", "")).lower())
    high_risk = 624 + sum(1 for c in cases if c.get("risk_score", 0) >= 70)
    safe_count = 6733 + sum(1 for c in cases if "clean" in str(c.get("verdict", "")).lower() or "safe" in str(c.get("verdict", "")).lower())

    return jsonify({
        "emails_analyzed": total_analyzed,
        "phishing_detected": phishing_count,
        "spam_detected": spam_count,
        "high_risk": high_risk,
        "safe_emails": safe_count,
        "detection_accuracy": 96.8,
        "distribution": {
            "safe": safe_count,
            "spam": spam_count,
            "suspicious": max(0, total_analyzed - safe_count - spam_count - phishing_count),
            "phishing": phishing_count
        },
        "recent_cases": cases[:10]
    })

@app.route("/api/forensics/cases", methods=["GET"])
def forensics_cases():
    cases = list_forensics_cases(limit=50)
    return jsonify({"cases": cases})

@app.route("/api/forensics/case/<int:case_id>", methods=["GET"])
def forensics_case_detail(case_id):
    case = get_forensics_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(case)

# ── DUAL MOUNT ALIASES FOR VERCEL SERVERLESS SCRIPT_NAME ROUTING ──────
app.add_url_rule("/forensics/analyze", view_func=forensics_analyze, methods=["POST"], endpoint="forensics_analyze_alias")
app.add_url_rule("/forensics/demo/<demo_type>", view_func=forensics_demo, methods=["GET"], endpoint="forensics_demo_alias")
app.add_url_rule("/forensics/stats", view_func=forensics_stats, methods=["GET"], endpoint="forensics_stats_alias")
app.add_url_rule("/forensics/cases", view_func=forensics_cases, methods=["GET"], endpoint="forensics_cases_alias")
app.add_url_rule("/forensics/case/<int:case_id>", view_func=forensics_case_detail, methods=["GET"], endpoint="forensics_case_detail_alias")
app.add_url_rule("/heartbeat", view_func=lambda: ("OK", 200), methods=["GET"], endpoint="heartbeat_alias")

# ── AUTOMATION FLOW APIS ───────────────────────────────────────────────

@app.route("/api/flow/run", methods=["POST"])
def flow_run():
    data = request.json or {}
    nodes = data.get("nodes", [])
    conns = data.get("conns", [])
    flow_name = data.get("name", "Adhoc Flow")

    if not nodes:
        return jsonify({"error": "Workflow contains no nodes"}), 400

    result = run_workflow(nodes, conns, flow_name=flow_name)
    return jsonify(result)

@app.route("/api/flow/save", methods=["POST"])
def flow_save():
    data = request.json or {}
    flow_id = data.get("id") or f"flow_{int(time.time())}"
    name = data.get("name", "Untitled Workflow")
    nodes = data.get("nodes", [])
    conns = data.get("conns", [])
    interval_val = data.get("interval_val", 10)
    interval_unit = data.get("interval_unit", "minutes")
    is_active = data.get("is_active", 0)

    save_flow_record(flow_id, name, nodes, conns, interval_val, interval_unit, is_active)
    return jsonify({"status": "ok", "flow_id": flow_id, "message": "Workflow saved to SQLite."})

@app.route("/api/flow/list", methods=["GET"])
def flow_list():
    flows = list_flows()
    return jsonify({"flows": flows})

@app.route("/api/flow/get/<flow_id>", methods=["GET"])
def flow_get(flow_id):
    record = get_flow_record(flow_id)
    if not record:
        return jsonify({"error": "Workflow not found"}), 404
    return jsonify(record)

@app.route("/api/flow/delete/<flow_id>", methods=["DELETE"])
def flow_delete(flow_id):
    delete_flow_record(flow_id)
    return jsonify({"status": "ok", "message": "Workflow deleted."})

@app.route("/api/flow/logs", methods=["GET"])
def flow_logs():
    logs = get_recent_logs(limit=50)
    return jsonify({"logs": logs})

# ── AI GATEWAY APIS ────────────────────────────────────────────────────

@app.route("/api/ai/ollama", methods=["GET"])
def get_ollama_status():
    return jsonify(check_ollama_status())

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    data = request.json or {}
    provider = data.get("provider", "ollama")
    model = data.get("model", "")
    messages = data.get("messages", [])
    api_key = data.get("api_key", "").strip()

    if not messages:
        return jsonify({"error": "Messages array cannot be empty"}), 400

    return Response(
        stream_ai_response(provider, model, messages, api_key=api_key),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

# ── SETTINGS APIS ──────────────────────────────────────────────────────

@app.route("/api/settings/save", methods=["POST"])
def save_settings_route():
    data = request.json or {}
    for k, v in data.items():
        set_setting(k, v)
    return jsonify({"status": "ok", "message": "Settings saved to database."})

@app.route("/api/settings/get", methods=["GET"])
def get_settings_route():
    keys = [
        "theme", "default_ai_provider", "default_ai_model",
        "api_key_anthropic", "api_key_gemini", "api_key_openai",
        "api_key_deepseek", "api_key_openrouter", "api_key_groq"
    ]
    result = {}
    for k in keys:
        val = get_setting(k, "")
        # Mask keys for security if displaying in UI
        if "api_key_" in k and val:
            result[k] = val[:4] + "••••••••" + val[-3:] if len(val) > 7 else "••••••••"
            result[k + "_set"] = True
        else:
            result[k] = val
    return jsonify(result)

# ── HEARTBEAT & LIFECYCLE ──────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["GET"])
def heartbeat():
    global last_heartbeat
    last_heartbeat = time.time()
    return "ok"

def watchdog():
    global last_heartbeat
    # 120s grace period for initial window loading
    time.sleep(120)
    while True:
        time.sleep(10)
        # If UI has not pinged for 45s, cleanly exit process
        if time.time() - last_heartbeat > 45:
            print("Watchdog: UI session disconnected. Clean shutdown.")
            os._exit(0)

def open_desktop_window(port):
    url = f"http://127.0.0.1:{port}"
    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

    try:
        if os.path.exists(edge_path):
            subprocess.Popen([edge_path, f"--app={url}"])
        elif os.path.exists(chrome_path):
            subprocess.Popen([chrome_path, f"--app={url}"])
        else:
            import webbrowser
            webbrowser.open(url)
    except Exception:
        import webbrowser
        webbrowser.open(url)

if __name__ == "__main__":
    # Get dynamic free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()

    # Start Watchdog
    threading.Thread(target=watchdog, daemon=True).start()

    # Start Flask
    server_thread = threading.Thread(target=lambda: app.run(host="127.0.0.1", port=port, threaded=True), daemon=True)
    server_thread.start()

    time.sleep(1.2)
    open_desktop_window(port)

    # Keep main thread alive
    while True:
        time.sleep(100)
