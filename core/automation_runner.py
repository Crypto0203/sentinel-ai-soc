import csv
import json
import os
import re
import threading
import time
import requests
import schedule
from datetime import datetime
from core.database import log_flow_event, save_flow_record, get_flow_record

class FlowContext:
    def __init__(self, flow_name="Anonymous Flow"):
        self.flow_name = flow_name
        self.vars = {
            "timestamp": datetime.now().isoformat(),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "time": datetime.now().strftime("%H:%M:%S"),
            "run_id": int(time.time())
        }
        self.logs = []

    def log(self, message, level="info"):
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message
        }
        self.logs.append(entry)

    def interpolate(self, text):
        if not isinstance(text, str):
            return text
        result = text
        for k, v in self.vars.items():
            result = result.replace(f"{{{{{k}}}}}", str(v))
        return result

def execute_node(node, ctx):
    ntype = node.get("type")
    cfg = node.get("cfg", {})
    nid = node.get("id")

    ctx.log(f"Executing node [{nid}] ({ntype})...", "info")

    if ntype == "manual_trigger":
        ctx.log("Flow manually triggered.", "ok")
        return {"status": "success"}

    elif ntype == "http_request":
        url = ctx.interpolate(cfg.get("url", "https://httpbin.org/get"))
        method = cfg.get("method", "GET").upper()
        headers_raw = ctx.interpolate(cfg.get("headers", "{}"))
        body_raw = ctx.interpolate(cfg.get("body", ""))

        try:
            headers = json.loads(headers_raw) if headers_raw.strip() else {}
        except Exception:
            headers = {}

        try:
            ctx.log(f"HTTP {method} -> {url}", "info")
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body_raw if body_raw else None,
                timeout=15
            )
            ctx.vars["http_status"] = resp.status_code
            ctx.vars["http_ok"] = resp.ok
            
            try:
                data = resp.json()
                ctx.vars["http_data"] = json.dumps(data)
                ctx.vars["http_json"] = data
            except Exception:
                ctx.vars["http_data"] = resp.text
            
            ctx.log(f"HTTP Response: {resp.status_code} ({'OK' if resp.ok else 'Error'})", "ok" if resp.ok else "warn")
            return {"status": "success", "code": resp.status_code}
        except Exception as e:
            ctx.log(f"HTTP Request failed: {str(e)}", "err")
            ctx.vars["http_error"] = str(e)
            return {"status": "error", "error": str(e)}

    elif ntype == "read_csv":
        path = ctx.interpolate(cfg.get("path", "")).strip()
        if not path or not os.path.exists(path):
            ctx.log(f"CSV path not found: {path}", "err")
            return {"status": "error", "error": "File not found"}
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            ctx.vars["csv_rows"] = json.dumps(rows)
            ctx.vars["csv_count"] = len(rows)
            ctx.log(f"Successfully read {len(rows)} rows from {os.path.basename(path)}", "ok")
            return {"status": "success", "count": len(rows)}
        except Exception as e:
            ctx.log(f"CSV read error: {str(e)}", "err")
            return {"status": "error", "error": str(e)}

    elif ntype == "write_file":
        filename = ctx.interpolate(cfg.get("filename", "output.txt"))
        content = ctx.interpolate(cfg.get("content", "Automation run completed."))
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            ctx.log(f"Saved {len(content)} bytes to {filename}", "ok")
            return {"status": "success", "file": filename}
        except Exception as e:
            ctx.log(f"File write error: {str(e)}", "err")
            return {"status": "error", "error": str(e)}

    elif ntype == "set_variable":
        name = cfg.get("name", "custom_var").strip()
        val = ctx.interpolate(cfg.get("value", ""))
        ctx.vars[name] = val
        ctx.log(f"Variable set: {name} = {val}", "ok")
        return {"status": "success"}

    elif ntype == "delay":
        secs = float(cfg.get("seconds", 1))
        ctx.log(f"Waiting {secs}s...", "info")
        time.sleep(secs)
        ctx.log("Wait finished.", "ok")
        return {"status": "success"}

    elif ntype == "if_condition":
        left = ctx.interpolate(str(cfg.get("left", "")))
        op = cfg.get("op", "==")
        right = ctx.interpolate(str(cfg.get("right", "")))

        res = False
        try:
            if op == "==":
                res = str(left) == str(right)
            elif op == "!=":
                res = str(left) != str(right)
            elif op == ">":
                res = float(left) > float(right)
            elif op == "<":
                res = float(left) < float(right)
            elif op == ">=":
                res = float(left) >= float(right)
            elif op == "<=":
                res = float(left) <= float(right)
            elif op == "contains":
                res = right in left
        except Exception:
            res = str(left) == str(right)

        ctx.vars["condition_result"] = res
        ctx.log(f"Condition [{left} {op} {right}] evaluated to: {res}", "ok" if res else "warn")
        return {"status": "success", "branch": "true" if res else "false"}

    elif ntype == "log_message":
        msg = ctx.interpolate(cfg.get("message", "Status log"))
        level = cfg.get("level", "ok")
        ctx.log(msg, level)
        return {"status": "success"}

    return {"status": "unknown_node"}

def run_workflow(nodes, conns, flow_name="Adhoc Flow"):
    """
    Executes a node graph sequentially or following connections.
    """
    ctx = FlowContext(flow_name)
    ctx.log(f"--- Starting execution of '{flow_name}' ({len(nodes)} nodes) ---", "info")

    node_dict = {n["id"]: n for n in nodes}
    
    # Simple linear / topological pass
    for node in nodes:
        res = execute_node(node, ctx)
        if res.get("status") == "error":
            ctx.log(f"Halting flow due to error in node {node.get('id')}", "err")
            break

    ctx.log("--- Workflow execution completed ---", "ok")
    log_flow_event(flow_name, flow_name, "SUCCESS", f"Executed {len(nodes)} nodes.")
    return {
        "success": True,
        "logs": ctx.logs,
        "vars": {k: (v if len(str(v)) < 1000 else str(v)[:1000] + "...") for k, v in ctx.vars.items()}
    }

# Background Scheduler Thread
_scheduler_running = False

def scheduler_worker():
    while _scheduler_running:
        try:
            schedule.run_pending()
        except Exception as e:
            print("Scheduler error:", e)
        time.sleep(1)

def start_scheduler():
    global _scheduler_running
    if not _scheduler_running:
        _scheduler_running = True
        t = threading.Thread(target=scheduler_worker, daemon=True)
        t.start()
