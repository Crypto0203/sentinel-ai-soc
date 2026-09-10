import sqlite3
import os
import json
import time

if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    DB_PATH = "/tmp/studio_data.db"
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "studio_data.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    
    # Threat forensics cases
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forensics_cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        sender TEXT,
        return_path TEXT,
        verdict TEXT,
        risk_score INTEGER,
        report_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Automation flows
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS automation_flows (
        id TEXT PRIMARY KEY,
        name TEXT,
        nodes_json TEXT,
        conns_json TEXT,
        interval_val INTEGER,
        interval_unit TEXT,
        is_active INTEGER DEFAULT 0,
        last_run TIMESTAMP,
        last_status TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Flow execution logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS flow_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id TEXT,
        flow_name TEXT,
        status TEXT,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # AI Chat history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        role TEXT,
        content TEXT,
        model TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    conn.commit()
    conn.close()

# Helper accessors
def get_setting(key, default=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def save_forensics_case(title, sender, return_path, verdict, risk_score, report_data):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO forensics_cases (title, sender, return_path, verdict, risk_score, report_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (title, sender, return_path, verdict, risk_score, json.dumps(report_data)))
    conn.commit()
    case_id = cur.lastrowid
    conn.close()
    return case_id

def list_forensics_cases(limit=30):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, title, sender, return_path, verdict, risk_score, created_at FROM forensics_cases ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_forensics_case(case_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM forensics_cases WHERE id = ?", (case_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["report_json"] = json.loads(d["report_json"])
        return d
    return None

def save_flow_record(flow_id, name, nodes, conns, interval_val, interval_unit, is_active=0):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO automation_flows (id, name, nodes_json, conns_json, interval_val, interval_unit, is_active, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (flow_id, name, json.dumps(nodes), json.dumps(conns), interval_val, interval_unit, is_active))
    conn.commit()
    conn.close()

def list_flows():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, interval_val, interval_unit, is_active, last_run, last_status, updated_at FROM automation_flows ORDER BY updated_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_flow_record(flow_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM automation_flows WHERE id = ?", (flow_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["nodes"] = json.loads(d["nodes_json"])
        d["conns"] = json.loads(d["conns_json"])
        return d
    return None

def delete_flow_record(flow_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM automation_flows WHERE id = ?", (flow_id,))
    conn.commit()
    conn.close()

def log_flow_event(flow_id, flow_name, status, message):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO flow_logs (flow_id, flow_name, status, message) VALUES (?, ?, ?, ?)", (flow_id, flow_name, status, message))
    conn.commit()
    conn.close()

def get_recent_logs(limit=50):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM flow_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
