// ═══════════════════════════════════════════════════════════════════
//   AUTOMATION FLOW ENGINE CONTROLLER
// ═══════════════════════════════════════════════════════════════════

let flowNodes = [
  {
    id: "node_1",
    type: "manual_trigger",
    label: "Manual Trigger",
    cfg: {}
  },
  {
    id: "node_2",
    type: "http_request",
    label: "HTTP Health Check",
    cfg: {
      url: "https://httpbin.org/get",
      method: "GET",
      headers: '{"User-Agent": "SureshProStudio/2.0"}',
      body: ""
    }
  },
  {
    id: "node_3",
    type: "if_condition",
    label: "Verify Response Status",
    cfg: {
      left: "{{http_status}}",
      op: "==",
      right: "200"
    }
  },
  {
    id: "node_4",
    type: "write_file",
    label: "Log to Local File",
    cfg: {
      filename: "suresh_api_report.txt",
      content: "Automation Check Succeeded!\nHTTP Status: {{http_status}}\nTimestamp: {{timestamp}}"
    }
  }
];

function renderFlowNodes() {
  const container = document.getElementById('flow-nodes-container');
  if (!container) return;

  container.innerHTML = flowNodes.map((node, index) => `
    <div class="glass-card" style="border-left: 4px solid var(--accent); padding: 18px 20px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <span style="font-family:var(--font-mono); font-size:0.8rem; background:rgba(0,240,255,0.1); padding:2px 8px; border-radius:4px; color:var(--accent);">#${index + 1}</span>
          <strong>${node.label}</strong>
          <span style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">(${node.type})</span>
        </div>
        ${index > 0 ? `<button class="btn btn-danger" style="padding:3px 10px; font-size:0.75rem;" onclick="removeNode(${index})">Remove</button>` : ''}
      </div>

      <!-- Node Specific Config Fields -->
      ${getNodeConfigHtml(node, index)}
    </div>
  `).join('');
}

function getNodeConfigHtml(node, index) {
  if (node.type === "http_request") {
    return `
      <div style="display:grid; grid-template-columns:100px 1fr; gap:10px; margin-bottom:8px;">
        <select onchange="updateNodeCfg(${index}, 'method', this.value)">
          <option value="GET" ${node.cfg.method === 'GET' ? 'selected' : ''}>GET</option>
          <option value="POST" ${node.cfg.method === 'POST' ? 'selected' : ''}>POST</option>
          <option value="PUT" ${node.cfg.method === 'PUT' ? 'selected' : ''}>PUT</option>
        </select>
        <input type="text" value="${node.cfg.url || ''}" placeholder="https://api.example.com/data" onchange="updateNodeCfg(${index}, 'url', this.value)">
      </div>
    `;
  } else if (node.type === "read_csv") {
    return `
      <div>
        <label style="font-size:0.75rem; color:var(--text-dim);">Absolute CSV File Path</label>
        <input type="text" value="${node.cfg.path || ''}" placeholder="C:\\Users\\Suresh\\Desktop\\leads.csv" onchange="updateNodeCfg(${index}, 'path', this.value)">
      </div>
    `;
  } else if (node.type === "if_condition") {
    return `
      <div style="display:grid; grid-template-columns:1fr 80px 1fr; gap:8px;">
        <input type="text" value="${node.cfg.left || ''}" placeholder="{{http_status}}" onchange="updateNodeCfg(${index}, 'left', this.value)">
        <select onchange="updateNodeCfg(${index}, 'op', this.value)">
          <option value="==" ${node.cfg.op === '==' ? 'selected' : ''}>==</option>
          <option value="!=" ${node.cfg.op === '!=' ? 'selected' : ''}>!=</option>
          <option value=">" ${node.cfg.op === '>' ? 'selected' : ''}>&gt;</option>
          <option value="<" ${node.cfg.op === '<' ? 'selected' : ''}>&lt;</option>
          <option value="contains" ${node.cfg.op === 'contains' ? 'selected' : ''}>contains</option>
        </select>
        <input type="text" value="${node.cfg.right || ''}" placeholder="200" onchange="updateNodeCfg(${index}, 'right', this.value)">
      </div>
    `;
  } else if (node.type === "write_file") {
    return `
      <div style="display:flex; flex-direction:column; gap:8px;">
        <input type="text" value="${node.cfg.filename || ''}" placeholder="output.txt" onchange="updateNodeCfg(${index}, 'filename', this.value)">
        <textarea style="height:60px; font-size:0.8rem;" placeholder="File content with {{variables}}" onchange="updateNodeCfg(${index}, 'content', this.value)">${node.cfg.content || ''}</textarea>
      </div>
    `;
  }
  return `<div style="font-size:0.8rem; color:var(--text-dim);">Ready to trigger pipeline.</div>`;
}

function updateNodeCfg(index, key, value) {
  if (flowNodes[index]) {
    if (!flowNodes[index].cfg) flowNodes[index].cfg = {};
    flowNodes[index].cfg[key] = value;
  }
}

function addNodeToCanvas(type) {
  const labels = {
    http_request: "HTTP API Call",
    read_csv: "Read Local CSV",
    if_condition: "Conditional Filter",
    write_file: "Save Local File"
  };

  flowNodes.push({
    id: `node_${Date.now()}`,
    type,
    label: labels[type] || "Custom Step",
    cfg: type === "http_request" ? { method: "GET", url: "https://httpbin.org/get" } :
         type === "read_csv" ? { path: "" } :
         type === "if_condition" ? { left: "{{http_status}}", op: "==", right: "200" } :
         type === "write_file" ? { filename: "output.txt", content: "Result: {{timestamp}}" } : {}
  });

  renderFlowNodes();
  showToast(`Added ${labels[type]} node`);
}

function removeNode(index) {
  flowNodes.splice(index, 1);
  renderFlowNodes();
}

function clearFlowConsole() {
  document.getElementById('flow-console').innerHTML = `<div style="color:var(--text-muted);">Console cleared.</div>`;
}

function logToConsole(message, level = "info") {
  const consoleEl = document.getElementById('flow-console');
  const div = document.createElement('div');
  const colors = {
    info: "var(--text-dim)",
    ok: "var(--green)",
    warn: "var(--orange)",
    err: "var(--red)"
  };
  div.style.color = colors[level] || "var(--text)";
  div.innerHTML = `<span style="color:var(--text-muted); font-size:0.75rem;">[${new Date().toLocaleTimeString()}]</span> ${message}`;
  consoleEl.appendChild(div);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

async function executeCurrentFlow() {
  const name = document.getElementById('flow-name-input').value.trim() || "Suresh Automation";
  logToConsole(`🚀 Triggering Native Python Engine for '${name}'...`, "info");
  showToast("Executing flow in background Python...");

  try {
    const res = await fetch(`${API_BASE}/api/flow/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        nodes: flowNodes,
        conns: []
      })
    });

    const data = await res.json();
    if (res.ok && data.logs) {
      data.logs.forEach(l => {
        logToConsole(`[${l.level.toUpperCase()}] ${l.message}`, l.level);
      });
      logToConsole("✅ Execution Finished Successfully.", "ok");
      showToast("Workflow completed!");
    } else {
      logToConsole(`❌ Flow Error: ${data.error || 'Execution failed'}`, "err");
      showToast("Flow failed", true);
    }
  } catch (e) {
    logToConsole(`❌ Network Error: ${e.message}`, "err");
    showToast("Could not reach Python engine", true);
  }
}

async function saveCurrentFlow() {
  const name = document.getElementById('flow-name-input').value.trim() || "Untitled Flow";
  try {
    const res = await fetch(`${API_BASE}/api/flow/save`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        nodes: flowNodes,
        conns: []
      })
    });
    if (res.ok) {
      showToast("Workflow saved to SQLite!");
    }
  } catch (e) {
    showToast("Failed to save workflow", true);
  }
}

// Initial render
window.addEventListener('DOMContentLoaded', () => {
  renderFlowNodes();
});
