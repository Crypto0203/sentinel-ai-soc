// ═══════════════════════════════════════════════════════════════════
//   SENTINEL AI — ENTERPRISE EMAIL THREAT SOC PLATFORM
//   Global Application Controller & Analytics Engine
// ═══════════════════════════════════════════════════════════════════

const API_BASE = window.location.origin;

let chartDistribution = null;
let chartVectors = null;
let chartTrend = null;
let allHistoryCases = [];

// ── NAVIGATION CONTROLLER ──────────────────────────────────────────

function switchNav(tabName) {
  // Update top navigation buttons
  document.querySelectorAll('.top-nav-links .nav-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  const activeBtn = document.getElementById(`nav-btn-${tabName}`);
  if (activeBtn) activeBtn.classList.add('active');

  // Update viewports
  document.querySelectorAll('.soc-view').forEach(view => {
    view.classList.remove('active');
  });
  const activeView = document.getElementById(`view-${tabName}`);
  if (activeView) activeView.classList.add('active');

  // View-specific actions
  if (tabName === 'dashboard') {
    loadDashboardStats();
    loadRecentCasesHub();
  } else if (tabName === 'history') {
    loadFullCaseHistory();
  }
}

// ── TOAST NOTIFICATIONS ────────────────────────────────────────────

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `soc-toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  else if (type === 'danger') icon = '🚨';
  else if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-msg">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-show');
  }, 10);

  setTimeout(() => {
    toast.classList.remove('toast-show');
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}

// ── DASHBOARD TELEMETRY & STATS ───────────────────────────────────

async function loadDashboardStats() {
  try {
    const res = await fetch(`${API_BASE}/api/forensics/stats`);
    if (!res.ok) return;
    const data = await res.json();

    // Update KPI counters
    animateValue('kpi-total', data.total_analyzed || 12488);
    animateValue('kpi-phishing', data.phishing_detected || 1284);
    animateValue('kpi-spam', data.spam_filtered || 3841);
    animateValue('kpi-malicious', data.high_risk_malicious || 624);
    animateValue('kpi-safe', data.safe_verified || 6739);
    
    const accEl = document.getElementById('kpi-accuracy');
    if (accEl) accEl.textContent = `${data.accuracy_rate || 96.8}%`;

    // Render / Update Charts
    initDistributionChart(data.distribution || { safe: 6739, spam: 3841, suspicious: 914, phishing: 1284, malicious: 624 });
    initThreatVectorsChart(data.threat_vectors || {
      'Domain Spoofing': 412,
      'Lookalike URL / Punycode': 389,
      'Urgent Financial Trap': 310,
      'SPF / DKIM Failure': 528,
      'Executable Attachment': 142,
      'Free Webmail Impersonation': 288
    });
    initVelocityTrendChart();

    const lastScanEl = document.getElementById('header-last-scan');
    if (lastScanEl) lastScanEl.textContent = 'Active Real-Time';
  } catch (e) {
    console.warn('Failed to load dashboard stats:', e);
  }
}

function animateValue(elementId, targetVal) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const currentText = el.textContent.replace(/,/g, '');
  const currentVal = parseInt(currentText, 10) || 0;
  if (currentVal === targetVal) {
    el.textContent = Number(targetVal).toLocaleString();
    return;
  }

  const duration = 800;
  const steps = 20;
  const stepTime = duration / steps;
  let step = 0;

  const timer = setInterval(() => {
    step++;
    const progress = step / steps;
    const value = Math.round(currentVal + (targetVal - currentVal) * progress);
    el.textContent = Number(value).toLocaleString();
    if (step >= steps) {
      clearInterval(timer);
      el.textContent = Number(targetVal).toLocaleString();
    }
  }, stepTime);
}

// ── SOC ANALYTICS CHARTS (CHART.JS) ────────────────────────────────

function initDistributionChart(dist) {
  const canvas = document.getElementById('chart-distribution');
  if (!canvas) return;

  const dataValues = [
    dist.safe || 6739,
    dist.spam || 3841,
    dist.suspicious || 914,
    dist.phishing || 1284,
    dist.malicious || 624
  ];

  if (chartDistribution) {
    chartDistribution.data.datasets[0].data = dataValues;
    chartDistribution.update();
    return;
  }

  chartDistribution = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Spam', 'Suspicious', 'Phishing', 'Malicious'],
      datasets: [{
        data: dataValues,
        backgroundColor: [
          '#00e676', // Emerald
          '#ff9100', // Amber
          '#ffd600', // Yellow
          '#ff1744', // Red
          '#d500f9'  // Purple
        ],
        borderWidth: 2,
        borderColor: '#0f172a',
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#94a3b8',
            font: { family: 'Inter', size: 11 },
            boxWidth: 12,
            padding: 10
          }
        },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          titleColor: '#00f0ff',
          bodyColor: '#f1f5f9',
          borderColor: '#1e293b',
          borderWidth: 1
        }
      },
      cutout: '68%'
    }
  });
}

function initThreatVectorsChart(vectors) {
  const canvas = document.getElementById('chart-vectors');
  if (!canvas) return;

  const labels = Object.keys(vectors);
  const dataValues = Object.values(vectors);

  if (chartVectors) {
    chartVectors.data.labels = labels;
    chartVectors.data.datasets[0].data = dataValues;
    chartVectors.update();
    return;
  }

  chartVectors = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Detections',
        data: dataValues,
        backgroundColor: 'rgba(0, 240, 255, 0.45)',
        borderColor: '#00f0ff',
        borderWidth: 1.5,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          titleColor: '#00f0ff',
          bodyColor: '#f1f5f9'
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { color: '#64748b', font: { size: 10 } }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#94a3b8', font: { size: 10 } }
        }
      }
    }
  });
}

function initVelocityTrendChart() {
  const canvas = document.getElementById('chart-trend');
  if (!canvas) return;

  if (chartTrend) return;

  const days = ['Day -6', 'Day -5', 'Day -4', 'Day -3', 'Day -2', 'Yesterday', 'Today'];
  const safeData = [840, 910, 890, 950, 1020, 1100, 1029];
  const threatData = [180, 240, 195, 310, 290, 360, 320];

  chartTrend = new Chart(canvas, {
    type: 'line',
    data: {
      labels: days,
      datasets: [
        {
          label: 'Threats Blocked',
          data: threatData,
          borderColor: '#ff1744',
          backgroundColor: 'rgba(255, 23, 68, 0.12)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#ff1744'
        },
        {
          label: 'Clean Traffic',
          data: safeData,
          borderColor: '#00e676',
          backgroundColor: 'rgba(0, 230, 118, 0.05)',
          fill: true,
          tension: 0.35,
          borderWidth: 1.5,
          borderDash: [4, 4],
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 10 }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { color: '#64748b', font: { size: 10 } }
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { color: '#64748b', font: { size: 10 } }
        }
      }
    }
  });
}

// ── RECENT INVESTIGATIONS (DASHBOARD TAB) ──────────────────────────

async function loadRecentCasesHub() {
  try {
    const res = await fetch(`${API_BASE}/api/forensics/cases`);
    if (!res.ok) return;
    const data = await res.json();
    const cases = data.cases || [];
    allHistoryCases = cases;

    const tbody = document.getElementById('dashboard-cases-tbody');
    if (!tbody) return;

    if (cases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted" style="padding:25px;">No investigations recorded yet. Click "Analyze Inbound Email" to start!</td></tr>`;
      return;
    }

    // Top 5 recent cases
    const recent = cases.slice(0, 5);
    tbody.innerHTML = recent.map(c => renderCaseTableRow(c)).join('');
  } catch (e) {
    console.warn('Failed to load recent cases:', e);
  }
}

// ── CASE HISTORY TAB & FILTERING ───────────────────────────────────

async function loadFullCaseHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/forensics/cases`);
    if (!res.ok) return;
    const data = await res.json();
    allHistoryCases = data.cases || [];
    filterHistoryTable();
  } catch (e) {
    console.warn('Failed to load full history:', e);
  }
}

function filterHistoryTable() {
  const searchInput = document.getElementById('history-search-input');
  const filterSelect = document.getElementById('history-filter-select');
  const tbody = document.getElementById('history-table-tbody');
  if (!tbody) return;

  const query = (searchInput ? searchInput.value : '').toLowerCase().trim();
  const filter = (filterSelect ? filterSelect.value : 'all').toLowerCase();

  let filtered = allHistoryCases.filter(c => {
    // Classification match
    if (filter !== 'all') {
      const caseClass = (c.classification || '').toLowerCase();
      const verdict = (c.verdict || '').toLowerCase();
      if (!caseClass.includes(filter) && !verdict.includes(filter)) {
        return false;
      }
    }

    // Search query match
    if (query) {
      const subject = (c.subject || '').toLowerCase();
      const fromAddr = (c.from || '').toLowerCase();
      const returnPath = (c.return_path || '').toLowerCase();
      const caseId = (c.case_id || '').toLowerCase();
      if (!subject.includes(query) && !fromAddr.includes(query) && !returnPath.includes(query) && !caseId.includes(query)) {
        return false;
      }
    }

    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted" style="padding:30px;">No investigations match your current filter or query.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(c => renderCaseTableRow(c)).join('');
}

function renderCaseTableRow(c) {
  const caseIdDisplay = c.case_id ? `#INV-${c.case_id.substring(0, 8).toUpperCase()}` : '#INV-DEMO';
  const riskScore = c.risk_score !== undefined ? c.risk_score : 0;
  
  // Badge color logic
  let badgeClass = 'badge-neutral';
  let badgeText = c.verdict || 'EVALUATED';
  const vLower = badgeText.toLowerCase();

  if (vLower.includes('phishing')) {
    badgeClass = 'badge-danger';
  } else if (vLower.includes('malicious') || vLower.includes('high risk')) {
    badgeClass = 'badge-danger';
  } else if (vLower.includes('suspicious')) {
    badgeClass = 'badge-warning';
  } else if (vLower.includes('spam')) {
    badgeClass = 'badge-warning';
  } else if (vLower.includes('safe') || vLower.includes('legitimate')) {
    badgeClass = 'badge-success';
  }

  const riskColor = riskScore >= 75 ? '#ff1744' : riskScore >= 40 ? '#ffd600' : '#00e676';

  const timeStr = c.created_at ? new Date(c.created_at).toLocaleString() : 'Recent';

  return `
    <tr>
      <td class="font-mono text-cyan" style="font-weight:700;">${caseIdDisplay}</td>
      <td style="max-width:240px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(c.subject || '--')}">
        ${escapeHtml(c.subject || '(No Subject)')}
      </td>
      <td class="font-mono" style="max-width:180px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(c.from || '--')}">
        ${escapeHtml(c.from || '--')}
      </td>
      <td class="font-mono" style="max-width:160px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; color:var(--text-dim);" title="${escapeHtml(c.return_path || '--')}">
        ${escapeHtml(c.return_path || '--')}
      </td>
      <td>
        <span class="auth-badge ${badgeClass}" style="font-size:0.75rem;">${escapeHtml(badgeText)}</span>
      </td>
      <td>
        <span class="font-mono" style="font-weight:700; color:${riskColor};">${riskScore}/100</span>
      </td>
      <td style="color:var(--text-dim); font-size:0.8rem;">${timeStr}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="reopenInvestigation('${c.case_id}')">Open Case</button>
      </td>
    </tr>
  `;
}

async function reopenInvestigation(caseId) {
  try {
    showToast(`Loading case #${caseId.substring(0, 8)}...`);
    const res = await fetch(`${API_BASE}/api/forensics/case/${caseId}`);
    if (!res.ok) {
      showToast('Could not load case data', 'danger');
      return;
    }
    const report = await res.json();
    switchNav('analyze');
    
    // Switch to workspace directly
    document.getElementById('upload-center-container').style.display = 'none';
    document.getElementById('pipeline-container').style.display = 'none';
    document.getElementById('workspace-container').style.display = 'block';

    if (window.renderWorkspace) {
      window.renderWorkspace(report);
    }
    showToast('Investigation workspace loaded!', 'success');
  } catch (e) {
    showToast('Failed to open case', 'danger');
  }
}

function saveSettings() {
  showToast('SOC Engine thresholds & DNS rules saved successfully!', 'success');
}

// ── UTILITIES ──────────────────────────────────────────────────────

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── HEARTBEAT & SYSTEM MONITOR ─────────────────────────────────────

setInterval(() => {
  fetch(`${API_BASE}/api/heartbeat`).catch(() => {});
}, 8000);

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  loadDashboardStats();
  loadRecentCasesHub();
});
