const state = {
  charts: { risk: null, scans: null, tools: null },
  refreshTimer: null,
  currentSection: 'overview'
};

function badgeClass(value = '') {
  const v = String(value).toLowerCase();
  if (v.includes('high') || v.includes('failed')) return 'badge high';
  if (v.includes('medium')) return 'badge medium';
  if (v.includes('low')) return 'badge low';
  if (v.includes('safe')) return 'badge safe';
  if (v.includes('success') || v.includes('sent')) return 'badge success';
  return 'badge';
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? '-';
}

function rowsHtml(rows, columns) {
  if (!Array.isArray(rows) || !rows.length) {
    return `<tr><td colspan="${columns}">No data available.</td></tr>`;
  }
  return rows.join('');
}

function createOrUpdateChart(key, canvasId, config) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  if (state.charts[key]) {
    state.charts[key].data = config.data;
    state.charts[key].options = config.options;
    state.charts[key].update();
    return;
  }
  state.charts[key] = new Chart(ctx, config);
}

async function fetchJson(url) {
  const res = await fetch(url, { credentials: 'same-origin' });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

async function loadStats() {
  const data = await fetchJson('/api/admin/stats');
  const stats = data.stats || {};
  setText('statUsers', stats.total_users || 0);
  setText('statActive', stats.active_users_today || 0);
  setText('statScans', stats.total_scans || 0);
  setText('statHigh', stats.high_risk_threats || 0);
  setText('statEmails', stats.emails_sent || 0);
  setText('adminEmail', (data.admin || {}).email || 'admin@example.com');

  const risk = data.risk_distribution || {};
  createOrUpdateChart('risk', 'riskChart', {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Low', 'Medium', 'High'],
      datasets: [{
        data: [risk.SAFE || 0, risk.LOW || 0, risk.MEDIUM || 0, risk.HIGH || 0],
        backgroundColor: ['#38f2a6', '#2db6ff', '#ffb348', '#ff5f6d'],
        borderWidth: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#ecf6ff' }}}}
  });

  createOrUpdateChart('scans', 'scanChart', {
    type: 'line',
    data: {
      labels: (data.scans_over_time || []).map(x => x.day),
      datasets: [{
        label: 'Scans',
        data: (data.scans_over_time || []).map(x => x.total),
        borderColor: '#2db6ff',
        backgroundColor: 'rgba(45, 182, 255, 0.16)',
        tension: 0.35,
        fill: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#cfe8ff' }, grid: { color: 'rgba(120,170,220,.08)' } },
        y: { ticks: { color: '#cfe8ff' }, grid: { color: 'rgba(120,170,220,.08)' }, beginAtZero: true }
      },
      plugins: { legend: { labels: { color: '#ecf6ff' } } }
    }
  });

  createOrUpdateChart('tools', 'toolChart', {
    type: 'pie',
    data: {
      labels: (data.tool_usage || []).map(x => x.tool),
      datasets: [{
        data: (data.tool_usage || []).map(x => x.total),
        backgroundColor: ['#2db6ff', '#38f2a6', '#ffb348', '#7a7cff', '#ff5f6d', '#39d7ff'],
        borderWidth: 0
      }]
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#ecf6ff' }}}}
  });

  document.getElementById('recentActivityBody').innerHTML = rowsHtml((data.recent_activity || []).map(item => `
    <tr>
      <td>${item.user || '-'}</td>
      <td>${item.action || '-'}</td>
      <td>${item.ip_address || '-'}</td>
      <td>${item.timestamp || '-'}</td>
      <td><span class="${badgeClass(item.status)}">${item.status || '-'}</span></td>
    </tr>
  `), 5);

  document.getElementById('latestThreatsBody').innerHTML = rowsHtml((data.latest_threats || []).map(item => `
    <tr>
      <td>${item.scan || '-'}</td>
      <td>${item.target || '-'}</td>
      <td>${item.risk_score ?? '-'}</td>
      <td><span class="${badgeClass(item.risk_label)}">${item.risk_label || '-'}</span></td>
      <td>${item.timestamp || '-'}</td>
    </tr>
  `), 5);
}

async function loadUsers() {
  const data = await fetchJson('/api/admin/users');
  document.getElementById('usersBody').innerHTML = rowsHtml((data.users || []).map(user => `
    <tr>
      <td>${user.id}</td>
      <td>${user.name || '-'}</td>
      <td>${user.email || '-'}</td>
      <td><span class="${badgeClass(user.role)}">${user.role || 'USER'}</span></td>
      <td>${user.date_registered || '-'}</td>
      <td>${user.last_login || '-'}</td>
      <td><button class="action-btn" type="button">View</button></td>
    </tr>
  `), 7);
}

async function loadActivity() {
  const data = await fetchJson('/api/admin/activity');
  document.getElementById('activityBody').innerHTML = rowsHtml((data.activity || []).map(item => `
    <tr>
      <td>${item.user || '-'}</td>
      <td>${item.action || '-'}</td>
      <td>${item.ip_address || '-'}</td>
      <td>${item.timestamp || '-'}</td>
      <td><span class="${badgeClass(item.status)}">${item.status || '-'}</span></td>
    </tr>
  `), 5);
}

async function loadThreats() {
  const risk = document.getElementById('threatFilter').value;
  const data = await fetchJson(`/api/admin/threats${risk ? `?risk=${encodeURIComponent(risk)}` : ''}`);
  document.getElementById('threatsBody').innerHTML = rowsHtml((data.threats || []).map(item => `
    <tr>
      <td>${item.scan || '-'}</td>
      <td>${item.target || '-'}</td>
      <td>${item.risk_score ?? '-'}</td>
      <td><span class="${badgeClass(item.risk_label)}">${item.risk_label || '-'}</span></td>
      <td>${item.timestamp || '-'}</td>
      <td><button class="action-btn" type="button">View</button></td>
    </tr>
  `), 6);
}

async function loadEmails() {
  const data = await fetchJson('/api/admin/emails');
  document.getElementById('emailsBody').innerHTML = rowsHtml((data.emails || []).map(item => `
    <tr>
      <td>${item.sender || '-'}</td>
      <td>${item.recipient || '-'}</td>
      <td>${item.subject || '-'}</td>
      <td>${item.timestamp || '-'}</td>
      <td><span class="${badgeClass(item.status)}">${item.status || '-'}</span></td>
    </tr>
  `), 5);
}

async function loadAll() {
  try {
    await Promise.all([loadStats(), loadUsers(), loadActivity(), loadThreats(), loadEmails()]);
  } catch (err) {
    console.error(err);
  }
}

function switchSection(section) {
  state.currentSection = section;
  document.querySelectorAll('.nav-link').forEach(btn => btn.classList.toggle('active', btn.dataset.section === section));
  document.querySelectorAll('.panel-section').forEach(panel => panel.classList.toggle('active', panel.id === `section-${section}`));
}

function bindUI() {
  document.querySelectorAll('.nav-link').forEach(btn => {
    btn.addEventListener('click', () => {
      switchSection(btn.dataset.section);
      document.getElementById('sidebar').classList.remove('open');
    });
  });

  document.getElementById('menuToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
  });

  document.getElementById('refreshBtn').addEventListener('click', loadAll);
  document.getElementById('threatFilter').addEventListener('change', loadThreats);

  document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
      await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (err) {
      console.error(err);
    }
    window.location.href = '/auth';
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  bindUI();
  await loadAll();
  state.refreshTimer = setInterval(loadAll, 15000);
});
