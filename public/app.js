let parsedEvents = [];
let currentFileName = '';
let currentTimelineEvents = [];
let selectedTimelineRow = null;

const fileInput = document.getElementById('file-input');
const analyzeBtn = document.getElementById('analyze-btn');
const uploadStatus = document.getElementById('upload-status');

const summaryTotal = document.getElementById('summary-total');
const summaryRange = document.getElementById('summary-range');
const summaryTopSeverity = document.getElementById('summary-top-severity');
const summaryTopCampaign = document.getElementById('summary-top-campaign');

const indicatorsList = document.getElementById('indicators-list');
const campaignsList = document.getElementById('campaigns-list');
const timelineEl = document.getElementById('timeline');
const eventDetailsEl = document.getElementById('event-details');

function setStatus(message, type = '') {
  uploadStatus.textContent = message || '';
  uploadStatus.className = 'status';
  if (type) uploadStatus.classList.add(type);
}

/** Map a 0–10 score to severity level for color display. */
function getSeverityFromScore(score) {
  const s = parseFloat(score) || 0;
  if (s >= 8) return 'critical';
  if (s >= 6) return 'high';
  if (s >= 4) return 'medium';
  if (s >= 2) return 'low';
  return 'unknown';
}

/** Max score allowed for each severity so display stays coherent (critical > high > medium > low). */
const maxScoreBySeverity = { low: 4, medium: 6, high: 8, critical: 10, unknown: 3 };

/** Effective score for display – capped by campaign severity to avoid 10/10 with low severity. */
function getEffectiveScore(score, highestSeverity) {
  const s = parseFloat(score) || 0;
  const cap = maxScoreBySeverity[(highestSeverity || 'low').toLowerCase()] ?? 7;
  return Math.min(s, cap, 10);
}

/** Format score for display (0–10 scale, whole numbers only). Clamps to max 10. */
function formatScore(score) {
  const s = parseFloat(score);
  if (Number.isNaN(s)) return '0';
  const clamped = Math.min(Math.max(s, 0), 10);
  return String(Math.round(clamped));
}

function parseCsv(text) {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) {
    throw new Error('CSV must contain a header row and at least one data row.');
  }

  const headerLine = lines[0];
  const useTabs = headerLine.includes('\t');
  const splitFn = useTabs ? (line) => line.split(/\t+/).map((c) => c.trim()) : splitCsvLine;
  const headers = splitFn(headerLine).map((h) => h.trim());

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitFn(lines[i]);
    if (cols.length === 1 && cols[0] === '') continue;

    const row = {};
    headers.forEach((h, idx) => {
      row[h] = cols[idx] !== undefined ? cols[idx] : '';
    });
    rows.push(normalizeEventRow(row));
  }
  return rows;
}

/** Map common column names to app format and add type, severity, message when missing. */
function normalizeEventRow(row) {
  const out = { ...row };
  if (row.destination_ip && !row.dest_ip) out.dest_ip = row.destination_ip;
  if (row.destination_port && !row.dest_port) out.dest_port = row.destination_port;
  if (!out.type && (row.action || out.dest_ip)) out.type = 'firewall';
  if (!out.severity) out.severity = out.action?.toLowerCase() === 'block' ? 'high' : 'low';
  const src = out.source_ip || row.source_ip || '';
  const dest = out.dest_ip || out.destination_ip || '';
  const port = out.dest_port || out.destination_port || '';
  if (!out.message && (src || dest)) {
    out.message = port
      ? `Firewall ${(out.action || 'allowed').toLowerCase()} outbound connection from ${src} to ${dest} on port ${port}`
      : `Firewall ${(out.action || 'allowed').toLowerCase()} connection from ${src} to ${dest}`;
  }
  return out;
}

function splitCsvLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (!file) {
    parsedEvents = [];
    analyzeBtn.disabled = true;
    setStatus('');
    return;
  }

  const name = file.name.toLowerCase();
  const isExcel = name.endsWith('.xlsx') || name.endsWith('.xls');
  const isCsv = name.endsWith('.csv') || name.endsWith('.tsv');

  if (!isExcel && !isCsv) {
    parsedEvents = [];
    currentFileName = '';
    analyzeBtn.disabled = true;
    setStatus('Please select a CSV or Excel (.xlsx) file.', 'error');
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      let rows;
      if (isExcel) {
        if (typeof XLSX === 'undefined') {
          throw new Error(
            'Excel parsing library is not available. Check network access to the XLSX script.'
          );
        }
        const data = new Uint8Array(e.target.result);
        rows = parseExcel(data);
      } else {
        const text = e.target.result;
        rows = parseCsv(text);
      }

      if (!rows.length) {
        setStatus('No rows found in the file.', 'error');
        analyzeBtn.disabled = true;
        return;
      }

      parsedEvents = rows;
      currentFileName = file.name;
      analyzeBtn.disabled = false;
      setStatus(
        `Loaded ${rows.length} rows from ${file.name}.`,
        'success'
      );
    } catch (err) {
      console.error('File parse error', err);
      parsedEvents = [];
      currentFileName = '';
      analyzeBtn.disabled = true;
      setStatus(err.message || 'Error parsing file.', 'error');
    }
  };
  reader.onerror = () => {
    parsedEvents = [];
    analyzeBtn.disabled = true;
    setStatus('Error reading file.', 'error');
  };

  setStatus('Reading file...');
  if (isExcel) {
    reader.readAsArrayBuffer(file);
  } else {
    reader.readAsText(file);
  }
});

function parseExcel(uint8) {
  const workbook = XLSX.read(uint8, { type: 'array' });
  const firstSheetName = workbook.SheetNames[0];
  const worksheet = workbook.Sheets[firstSheetName];
  const json = XLSX.utils.sheet_to_json(worksheet, { defval: '' });
  return json;
}

analyzeBtn.addEventListener('click', async () => {
  if (!parsedEvents.length) {
    setStatus('No events loaded from CSV.', 'error');
    return;
  }

  analyzeBtn.disabled = true;
  setStatus('Analyzing logs...');

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: parsedEvents, fileName: currentFileName })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `API error: ${res.status}`);
    }

    const data = await res.json();
    renderAnalysis(data);
    setStatus('Analysis complete.', 'success');
  } catch (err) {
    console.error('Analyze error', err);
    setStatus(err.message || 'Unexpected error analyzing logs.', 'error');
  } finally {
    analyzeBtn.disabled = false;
  }
});

function renderAnalysis(data) {
  const { summary, timeline, topIndicators, suspectedCampaigns } = data;

  if (!summary || !timeline) {
    summaryTotal.textContent = '-';
    summaryRange.textContent = '-';
    summaryTopSeverity.textContent = '-';
    summaryTopCampaign.textContent = '-';
    renderIndicators([]);
    renderCampaigns([]);
    renderTimeline([]);
    return;
  }

  summaryTotal.textContent = summary.totalEvents ?? '-';

  if (summary.timeRange && summary.timeRange.from && summary.timeRange.to) {
    const from = new Date(summary.timeRange.from);
    const to = new Date(summary.timeRange.to);
    summaryRange.textContent = `${formatShortTime(from)} → ${formatShortTime(
      to
    )}`;
  } else {
    summaryRange.textContent = '-';
  }

  const bySeverity = summary.bySeverity || {};
  const ordered = ['critical', 'high', 'medium', 'low'];
  const top = ordered.find((s) => bySeverity[s] > 0) || 'unknown';
  summaryTopSeverity.textContent =
    top === 'unknown' ? 'UNCLASSIFIED' : top.toUpperCase();

  if (suspectedCampaigns && suspectedCampaigns.length) {
    const c = suspectedCampaigns[0];
    const effectiveScore = getEffectiveScore(c.score, c.highestSeverity);
    const sev = getSeverityFromScore(effectiveScore);
    summaryTopCampaign.textContent = `${formatScore(effectiveScore)} / 10`;
    summaryTopCampaign.className = 'value score severity-' + sev;
  } else {
    summaryTopCampaign.textContent = '—';
    summaryTopCampaign.className = 'value';
  }

  renderIndicators(topIndicators || []);
  renderCampaigns(suspectedCampaigns || []);
  renderTimeline(timeline || []);
}

function renderIndicators(indicators) {
  indicatorsList.innerHTML = '';
  if (!indicators.length) {
    const li = document.createElement('li');
    li.className = 'list-item';
    li.textContent = 'No strong indicators detected.';
    indicatorsList.appendChild(li);
    return;
  }

  indicators.forEach((ind) => {
    const li = document.createElement('li');
    li.className = 'list-item';

    const header = document.createElement('div');
    header.className = 'list-item-header';

    const label = document.createElement('div');
    label.textContent = ind.label;

    const chip = document.createElement('div');
    chip.className = 'chip chip-score-display';
    if (ind.category === 'authentication') chip.classList.add('auth');
    if (ind.category === 'multi-vector') chip.classList.add('multi-vector');
    const effectiveScore = ind.highestSeverity
      ? getEffectiveScore(ind.score ?? 0, ind.highestSeverity)
      : (ind.score ?? 0);
    const sev = getSeverityFromScore(effectiveScore);
    chip.classList.add('severity-' + sev);

    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'chip-score';
    scoreSpan.textContent = formatScore(effectiveScore) + ' / 10';

    const catSpan = document.createElement('span');
    catSpan.className = 'chip-category';
    catSpan.textContent = (ind.category || 'indicator').toUpperCase();

    chip.appendChild(scoreSpan);
    chip.appendChild(document.createTextNode(' · '));
    chip.appendChild(catSpan);

    header.appendChild(label);
    header.appendChild(chip);

    const body = document.createElement('div');
    body.className = 'list-item-body';
    body.textContent = ind.details || '';

    li.appendChild(header);
    li.appendChild(body);
    indicatorsList.appendChild(li);
  });
}

function renderCampaigns(campaigns) {
  campaignsList.innerHTML = '';

  if (!campaigns.length) {
    const div = document.createElement('div');
    div.className = 'timeline-empty';
    div.textContent = 'No multi-step coordinated campaigns detected.';
    campaignsList.appendChild(div);
    return;
  }

  campaigns.forEach((c) => {
    const card = document.createElement('div');
    card.className = 'campaign-card';

    const title = document.createElement('div');
    title.className = 'campaign-title';
    title.textContent = `${c.sourceIp} · ${c.eventCount} events`;

    const meta = document.createElement('div');
    meta.className = 'campaign-meta';

    const sevPill = document.createElement('span');
    sevPill.className = 'pill';
    if (c.highestSeverity === 'critical') sevPill.classList.add('danger');
    else if (c.highestSeverity === 'high') sevPill.classList.add('warn');
    else sevPill.classList.add('ok');
    sevPill.textContent = c.highestSeverity.toUpperCase();

    const effectiveScore = getEffectiveScore(c.score, c.highestSeverity);
    const scorePill = document.createElement('span');
    scorePill.className = 'pill pill-score severity-' + getSeverityFromScore(effectiveScore);
    scorePill.textContent = `${formatScore(effectiveScore)}/10`;

    meta.appendChild(sevPill);
    meta.appendChild(scorePill);

    card.appendChild(title);
    card.appendChild(meta);
    campaignsList.appendChild(card);
  });
}

function renderTimeline(events) {
  timelineEl.innerHTML = '';
  currentTimelineEvents = events || [];
  selectedTimelineRow = null;

  if (!events.length) {
    const div = document.createElement('div');
    div.className = 'timeline-empty';
    div.textContent = 'No events to display.';
    timelineEl.appendChild(div);

    if (eventDetailsEl) {
      renderEventDetails(null);
    }
    return;
  }

  events.forEach((e, index) => {
    const row = document.createElement('div');
    row.className = 'timeline-row';
    row.dataset.index = String(index);

    const ts = document.createElement('div');
    ts.className = 'timeline-timestamp';
    ts.textContent = formatTimestamp(e.timestamp);

    const type = document.createElement('div');
    type.className = 'timeline-type';

    const sevDot = document.createElement('span');
    sevDot.className = 'severity-dot';
    const sevClass = `severity-${(e.severity || 'unknown').toLowerCase()}`;
    sevDot.classList.add(sevClass);

    type.appendChild(sevDot);
    type.appendChild(
      document.createTextNode((e.type || 'general').toUpperCase())
    );

    const actor = document.createElement('div');
    actor.className = 'timeline-actor';
    actor.textContent =
      e.username || e.sourceIp || e.destIp || e.domain || '(unknown)';

    const msg = document.createElement('div');
    msg.className = 'timeline-message';
    msg.textContent = e.message || '';

    row.appendChild(ts);
    row.appendChild(type);
    row.appendChild(actor);
    row.appendChild(msg);
    row.addEventListener('click', () => {
      renderEventDetails(e, row);
    });
    timelineEl.appendChild(row);
  });

  if (eventDetailsEl) {
    renderEventDetails(null);
  }
}

function formatTimestamp(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return `${d.toISOString().slice(0, 10)} ${formatTimeAmPm(d)}`;
}

function formatShortTime(d) {
  if (!(d instanceof Date) || Number.isNaN(d.getTime())) return '-';
  return formatTimeAmPm(d);
}

function formatTimeAmPm(d) {
  const pad = (n) => String(n).padStart(2, '0');
  let h = d.getHours();
  const m = d.getMinutes();
  const s = d.getSeconds();
  const ampm = h >= 12 ? 'PM' : 'AM';
  h = h % 12;
  if (h === 0) h = 12;
  return `${h}:${pad(m)}:${pad(s)} ${ampm}`;
}

function extractDestFromMessage(msg) {
  if (!msg || typeof msg !== 'string') return null;
  const ipPort = msg.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b/);
  if (ipPort) return ipPort[1];
  const toIp = /(?:to|destination|dest)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i.exec(msg);
  return toIp ? toIp[1] : null;
}

function extractPortFromMessage(msg) {
  if (!msg || typeof msg !== 'string') return null;
  const withPort = msg.match(/(?::|\bport\s+)(\d{2,5})\b/i);
  return withPort ? withPort[1] : null;
}

function renderEventDetails(event, row) {
  if (!eventDetailsEl) return;

  if (selectedTimelineRow) {
    selectedTimelineRow.classList.remove('selected');
  }
  if (row) {
    row.classList.add('selected');
    selectedTimelineRow = row;
  } else {
    selectedTimelineRow = null;
  }

  if (!event) {
    eventDetailsEl.innerHTML = `
      <h3 class="event-details-title">Event details</h3>
      <p class="event-details-empty">
        Click an event in the timeline to see an overview, ports involved, recommended preventive measures, and similar attacks to watch for.
      </p>
    `;
    return;
  }

  const timeText = formatTimestamp(event.timestamp);
  const actor =
    event.username ||
    event.sourceIp ||
    event.destIp ||
    event.domain ||
    '(unknown)';

  const destDisplay = event.destIp || extractDestFromMessage(event.message) || 'n/a';
  const port =
    event.destPort ||
    extractPortFromMessage(event.message) ||
    'Not observed';

  const measures = getPreventiveMeasures(event);
  const similars = getSimilarAttacks(event);

  const measuresHtml = measures
    .map((m) => `<li>${m}</li>`)
    .join('') || '<li>Monitor for recurrence and tune alerts.</li>';

  const similarHtml = similars
    .map((m) => `<li>${m}</li>`)
    .join('') || '<li>No closely related patterns identified in this dataset.</li>';

  eventDetailsEl.innerHTML = `
    <h3 class="event-details-title">Event overview</h3>
    <div class="event-details-meta">
      <strong>${(event.type || 'general').toUpperCase()}</strong>
      &nbsp;&bull;&nbsp;
      Severity: ${(event.severity || 'unknown').toUpperCase()}<br/>
      Time: ${timeText}<br/>
      Actor: ${actor}<br/>
      Source: ${event.sourceIp || 'n/a'} &nbsp;&bull;&nbsp;
      Destination: ${destDisplay} &nbsp;&bull;&nbsp;
      Port: ${port}
    </div>
    <div class="event-details-chip-row">
      <span class="event-details-chip">User: ${event.username || 'n/a'}</span>
      <span class="event-details-chip">Type: ${(event.type || 'general').toUpperCase()}</span>
      <span class="event-details-chip">Destination: ${destDisplay}</span>
      <span class="event-details-chip">Port: ${port}</span>
    </div>
    <div class="event-details-section-title">Attack Explanation</div>
    <p>${event.message || '(none)'}</p>
    <div class="event-details-section-title">Preventive measures</div>
    <ul class="event-details-list">${measuresHtml}</ul>
    <div class="event-details-section-title">Similar attacks to watch for</div>
    <ul class="event-details-list">${similarHtml}</ul>
  `;
}

function getPreventiveMeasures(event) {
  const type = (event.type || '').toLowerCase();
  const severity = (event.severity || '').toLowerCase();
  const items = [];

  if (type.includes('auth') || type.includes('login')) {
    items.push(
      'Enable account lockout and throttling for repeated failed logins.',
      'Enforce strong MFA on the affected accounts.',
      'Review recent login locations and devices for this user.',
      'Implement risk-based authentication (RBA) and conditional access policies.',
      'Review and restrict service accounts with interactive logon rights.',
      'Audit and reduce accounts with excessive privileges.',
      'Enable session timeout and concurrent session limits.',
      'Monitor for anomalous login times and geographic impossible travel.',
      'Integrate with SIEM for correlation of failed auth across systems.',
      'Consider passwordless authentication (FIDO2, certificate-based).',
      'Verify identity through secondary channel before restoring access.',
      'Apply principle of least privilege for all user and service accounts.',
      'Enable and tune alerts for brute-force and credential-stuffing patterns.'
    );
    if (severity === 'high' || severity === 'critical') {
      items.push(
        'Temporarily disable or reset the affected account and require password reset.',
        'Force password change and MFA re-enrollment for affected users.',
        'Escalate to security incident response for potential compromise.'
      );
    }
  } else if (type.includes('malware') || type.includes('alert')) {
    items.push(
      'Isolate the affected host from the network immediately.',
      'Run a full EDR/AV scan and reimage if necessary.',
      'Block the C2 domain/IP at firewall and secure web gateways.',
      'Capture memory and disk images for forensic analysis before remediation.',
      'Identify and remediate the initial access vector (phishing, exploit, etc.).',
      'Check for persistence mechanisms (scheduled tasks, registry, startup).',
      'Scan all hosts in the same VLAN or that communicated with the affected host.',
      'Update threat intelligence feeds with observed IOCs.',
      'Block file types commonly used in attacks at email gateway and proxy.',
      'Ensure EDR is deployed and updated across all endpoints.',
      'Review and harden application allowlisting policies.',
      'Validate backups and test recovery procedures.',
      'Disable or remove unauthorized lateral movement paths (RDP, SMB, etc.).',
      'Review VPN and remote access logs for the same user or IP.'
    );
  } else if (type.includes('firewall')) {
    items.push(
      'Review firewall rules allowing this traffic and tighten to least privilege.',
      'Block or geo-restrict the source IP or CIDR if appropriate.',
      'Implement egress filtering to restrict outbound connections to necessary ports only.',
      'Segment the network to limit lateral movement and blast radius.',
      'Enable and tune IDS/IPS signatures for similar traffic patterns.',
      'Consider blocking or alerting on traffic to high-risk countries/regions.',
      'Document and validate the business justification for any new rule requests.',
      'Implement micro-segmentation for critical assets.',
      'Review and remove stale or overly permissive rules.',
      'Correlate with asset inventory to verify expected behavior.',
      'Block commonly abused ports (RDP, SSH, SMB) from untrusted sources.',
      'Enable logging and alerting for policy violations and denied connections.',
      'Apply rate limiting or throttling for high-volume connections.'
    );
  } else if (type.includes('dns')) {
    items.push(
      'Add the suspicious domain to DNS and proxy blocklists.',
      'Search DNS logs for other hosts resolving the same domain.',
      'Enable DNS over HTTPS (DoH) or secure resolvers with full logging.',
      'Implement DNS sinkholing for known malicious domains.',
      'Monitor for DNS query rate anomalies (e.g., fast flux, tunneling).',
      'Correlate with passive DNS to identify related domains and infrastructure.',
      'Block or alert on queries to newly registered domains (NRD).',
      'Review DNS cache poisoning and amplification risks.',
      'Implement response policy zones (RPZ) for threat intelligence integration.',
      'Monitor for subdomain enumeration and typosquatting patterns.',
      'Restrict recursive DNS to internal resolvers only.',
      'Enable DNSSEC validation where supported.',
      'Tune alerts for domains with high entropy or algorithmically generated names.',
      'Review DNS over non-standard ports (e.g., 53 over TCP) for tunneling.'
    );
  }

  if (!items.length) {
    items.push(
      'Monitor for repeated patterns from the same source or user.',
      'Correlate with other log sources (auth, firewall, DNS) for context.',
      'Tune detection rules based on false positive analysis.',
      'Ensure logs are retained and searchable in a central SIEM.'
    );
  }

  return pickThreeForEvent(items, event);
}

function pickThreeForEvent(pool, event) {
  if (pool.length <= 3) return pool;
  const key = [event.timestamp, event.sourceIp, event.username, event.destIp, event.message, event.destPort].filter(Boolean).join('|');
  let seed = 0;
  for (let i = 0; i < key.length; i++) {
    seed = ((seed << 5) - seed + key.charCodeAt(i)) | 0;
  }
  seed = Math.abs(seed);
  const n = pool.length;
  const offsets = [1, 317, 733];
  const indices = new Set();
  for (let i = 0; i < 3; i++) {
    let idx = (seed + offsets[i] * (i + 1)) % n;
    while (indices.has(idx)) idx = (idx + 1) % n;
    indices.add(idx);
  }
  return Array.from(indices).sort((a, b) => a - b).map((i) => pool[i]);
}

function getSimilarAttacks(event) {
  const type = (event.type || '').toLowerCase();
  const message = (event.message || '').toLowerCase();
  const hints = [];

  if (type.includes('auth') || type.includes('login')) {
    hints.push(
      'Password spraying from distributed IPs against the same user or group.',
      'Credential stuffing from known breach corpuses targeting VPN or SSO.'
    );
  }

  if (type.includes('malware') || message.includes('beacon')) {
    hints.push(
      'Beaconing to different C2 domains or IPs from the same host.',
      'Lateral movement events from the same source host shortly after beaconing.'
    );
  }

  if (type.includes('firewall')) {
    hints.push(
      'Sequential port scanning from this source across many internal hosts.',
      'Repeated blocked connections on high-risk ports (e.g., RDP, SSH, SMB).'
    );
  }

  if (type.includes('dns')) {
    hints.push(
      'DNS queries to algorithmically generated or high-entropy domains from multiple hosts.',
      'DNS tunneling patterns (large TXT records or many small queries).'
    );
  }

  return hints;
}

