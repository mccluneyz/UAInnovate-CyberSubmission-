const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'File too large. Try a smaller CSV or fewer rows.' });
  }
  next(err);
});

/** Extract destination IP and port from message or other text when not in dedicated fields. */
function extractDestAndPort(text) {
  if (!text || typeof text !== 'string') return { destIp: null, port: null };
  const t = text.trim();
  const result = { destIp: null, port: null };

  const ipv4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const ipPort = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})\b/;
  const portOnly = /(?:port|:)\s*(\d{2,5})\b/i;

  const ipPortMatch = t.match(ipPort);
  if (ipPortMatch) {
    result.destIp = ipPortMatch[1];
    result.port = ipPortMatch[2];
    return result;
  }

  const destKeyword = /(?:to|destination|dest|dst)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i.exec(t);
  if (destKeyword) result.destIp = destKeyword[1];

  const portMatch = t.match(portOnly);
  if (portMatch) result.port = portMatch[1];

  if (!result.destIp) {
    const ips = t.match(ipv4);
    if (ips && ips.length >= 2) result.destIp = ips[1];
    else if (ips && ips.length === 1) result.destIp = ips[0];
  }

  return result;
}

/** Infer event type from message, action, and other common log fields when type is not set. */
function inferEventType(e) {
  const text = [
    e.message,
    e.msg,
    e.alert,
    e.description,
    e.action,
    e.outcome,
    e.event_action,
    e.log,
    e.details,
    e.event_category,
    e.event_type,
    e.kind
  ]
    .filter(Boolean)
    .map((x) => String(x).toLowerCase())
    .join(' ');

  if (!text) return null;

  if (/\b(auth|login|logout|logon|logoff|ssh|ldap|kerberos|password|credential|session|failed log|successful log)\b/.test(text)) return 'auth';
  if (/\b(firewall|block|dropped|denied|allowed|acl|iptables|nfw)\b/.test(text)) return 'firewall';
  if (/\b(dns|query|resolution|lookup|nxdomain)\b/.test(text)) return 'dns';
  if (/\b(http|request|response|get |post |url|4\d{2}|5\d{2})\b/.test(text)) return 'http';
  if (/\b(file|upload|download|read|write|access|created|deleted|modified)\b/.test(text)) return 'file';
  if (/\b(network|connection|port|socket|tcp|udp|icmp)\b/.test(text)) return 'network';
  if (/\b(email|smtp|mail|sendmail)\b/.test(text)) return 'email';
  if (/\b(malware|virus|threat|alert|detection|ransomware|phish)\b/.test(text)) return 'alert';
  if (/\b(registry|process|exec|sysmon)\b/.test(text)) return 'system';

  return null;
}

function normalizeEvents(events) {
  return events
    .filter(Boolean)
    .map((raw, idx) => {
      const e = { ...raw };

      const ts = e.timestamp || e.time || e['@timestamp'];
      const date = ts ? new Date(ts) : null;

      const typeFromFields = (
        e.type ||
        e.log_type ||
        e.category ||
        e.event_type ||
        e.kind ||
        e.event_type_name ||
        e.event_name ||
        e.event_category ||
        ''
      )
        .toString()
        .trim()
        .toLowerCase();

      const type = typeFromFields || inferEventType(e) || 'general';

      const sourceIp =
        e.source_ip ||
        e.src_ip ||
        e.client_ip ||
        e.src ||
        e.source ||
        null;

      let destIp =
        e.dest_ip ||
        e.destination_ip ||
        e.dst_ip ||
        e.dst ||
        e.destination ||
        null;

      const username = e.username || e.user || e.account || null;
      const domain = e.domain || e.hostname || e.fqdn || null;

      let destPort =
        e.dest_port || e.dport || e.destination_port || e.port || null;

      const action =
        e.action ||
        e.outcome ||
        e.result ||
        e.status ||
        e.decision ||
        null;

      const message =
        e.message ||
        e.msg ||
        e.alert ||
        e.description ||
        e.reason ||
        e.log ||
        e.log_message ||
        e.event_message ||
        e.details ||
        e.detail ||
        e.info ||
        '';

      const textForExtract = [message, e.details, e.message, e.msg].filter(Boolean).join(' ');
      if (!destIp || !destPort) {
        const extracted = extractDestAndPort(textForExtract);
        if (!destIp && extracted.destIp) destIp = extracted.destIp;
        if (!destPort && extracted.port) destPort = extracted.port;
      }

      const severityRaw =
        (e.severity || e.level || e.priority || e.severity_label || '').toString();
      const severity = mapSeverity(severityRaw, type, message);

      return {
        id: e.id || `${idx}`,
        raw,
        timestamp: date ? date.toISOString() : null,
        date,
        type,
        severity,
        sourceIp,
        destIp,
        destPort,
        username,
        domain,
        action,
        message
      };
    })
    .filter((e) => e.date);
}

function mapSeverity(raw, type, message) {
  const value = (raw || '').toString().trim().toLowerCase();
  const t = (type || '').toString().trim().toLowerCase();
  const msg = (message || '').toString().trim().toLowerCase();

  if (
    value.includes('critical') ||
    value === 'crit' ||
    value.includes('sev4') ||
    value.includes('sev-4') ||
    value === 'sev 4'
  ) {
    return 'critical';
  }

  if (
    value === 'high' ||
    value.includes('sev3') ||
    value.includes('sev-3') ||
    value === 'sev 3'
  ) {
    return 'high';
  }

  if (
    value === 'medium' ||
    value === 'med' ||
    value === 'warning' ||
    value === 'warn' ||
    value.includes('sev2') ||
    value.includes('sev-2') ||
    value === 'sev 2'
  ) {
    return 'medium';
  }

  if (
    value === 'low' ||
    value === 'info' ||
    value === 'informational' ||
    value === 'notice' ||
    value.includes('sev1') ||
    value.includes('sev-1') ||
    value === 'sev 1'
  ) {
    return 'low';
  }

  const num = parseInt(value, 10);
  if (!Number.isNaN(num)) {
    if (num >= 9) return 'critical';
    if (num >= 7) return 'high';
    if (num >= 4) return 'medium';
    return 'low';
  }

  if (t.includes('malware') || t.includes('ransom') || msg.includes('ransom')) {
    return 'critical';
  }
  if (t.includes('ids') || t.includes('ips')) {
    return 'high';
  }
  if (t.includes('firewall')) {
    if (msg.includes('blocked') || msg.includes('denied') || msg.includes('dropped')) {
      const highRiskPort = /\b(3389|22|445|139|135|5985|5986)\b/.test(msg);
      if (highRiskPort) return 'critical';
      return 'high';
    }
    if (msg.includes('drop') || msg.includes('reject')) return 'medium';
    return 'low';
  }
  if (t.includes('network')) {
    if (msg.includes('scan') || msg.includes('recon') || msg.includes('probe')) return 'high';
    if (msg.includes('refused') || msg.includes('reset') || msg.includes('suspicious')) return 'medium';
    return 'low';
  }
  if (t.includes('dns')) {
    if (msg.includes('malicious') || msg.includes('tunneling') || msg.includes('c2') || msg.includes('command')) return 'high';
    if (msg.includes('suspicious') || msg.includes('nxdomain') || msg.includes('dga')) return 'medium';
    return 'low';
  }
  if (t.includes('auth') || t.includes('login')) {
    if (msg.includes('failed') || msg.includes('denied')) return 'medium';
    return 'low';
  }

  return 'low';
}

function analyze(events, fileName) {
  const normalized = normalizeEvents(events);

  if (fileName) {
    const name = String(fileName).toLowerCase();
    const typeFromFile =
      name.includes('dns') ? 'dns' :
      name.includes('firewall') ? 'firewall' :
      name.includes('auth') ? 'auth' :
      name.includes('malware') ? 'malware' :
      null;
    if (typeFromFile) {
      normalized.forEach((e) => {
        e.type = typeFromFile;
      });
    }
  }
  if (!normalized.length) {
    return {
      summary: {
        totalEvents: 0,
        byType: {},
        bySeverity: {},
        timeRange: null
      },
      timeline: [],
      topIndicators: [],
      suspectedCampaigns: []
    };
  }

  normalized.sort((a, b) => a.date - b.date);

  const first = normalized[0].timestamp;
  const last = normalized[normalized.length - 1].timestamp;

  const byType = {};
  const bySeverity = {};

  const failedAuthByUser = new Map();
  const eventsBySource = new Map();
  const eventsBySourceAndWindow = [];

  for (const ev of normalized) {
    byType[ev.type] = (byType[ev.type] || 0) + 1;
    bySeverity[ev.severity] = (bySeverity[ev.severity] || 0) + 1;

    if (ev.type.includes('auth') || ev.type.includes('login')) {
      const key = ev.username || ev.sourceIp || 'unknown';
      const cur = failedAuthByUser.get(key) || { failures: 0, successes: 0 };
      const failed =
        (ev.action || '').toLowerCase().includes('fail') ||
        (ev.message || '').toLowerCase().includes('failed');
      const success =
        (ev.action || '').toLowerCase().includes('success') ||
        (ev.message || '').toLowerCase().includes('success');

      if (failed) cur.failures += 1;
      if (success) cur.successes += 1;
      failedAuthByUser.set(key, cur);
    }

    if (ev.sourceIp) {
      const arr = eventsBySource.get(ev.sourceIp) || [];
      arr.push(ev);
      eventsBySource.set(ev.sourceIp, arr);
    }
  }

  const suspiciousAuth = [];
  for (const [actor, stats] of failedAuthByUser.entries()) {
    if (stats.failures >= 5 && stats.successes === 0) {
      suspiciousAuth.push({
        actor,
        reason: 'Brute-force style pattern (5+ failed logins, no successes)',
        score: 8
      });
    } else if (stats.failures >= 3 && stats.successes >= 1) {
      suspiciousAuth.push({
        actor,
        reason:
          'Multiple failed logins followed by success (possible account takeover)',
        score: 7
      });
    }
  }

  const correlationWindowMs = 30 * 60 * 1000;
  const campaigns = [];

  for (const [sourceIp, evs] of eventsBySource.entries()) {
    evs.sort((a, b) => a.date - b.date);
    let campaign = [evs[0]];

    for (let i = 1; i < evs.length; i++) {
      const prev = campaign[campaign.length - 1];
      const current = evs[i];
      if (current.date - prev.date <= correlationWindowMs) {
        campaign.push(current);
      } else {
        if (campaign.length >= 3) {
          campaigns.push({ sourceIp, events: campaign });
        }
        campaign = [current];
      }
    }

    if (campaign.length >= 3) {
      campaigns.push({ sourceIp, events: campaign });
    }
  }

  /** Type weights for bonus (firewall > network > dns). */
  const typeWeight = {
    firewall: 1,
    network: 0.6,
    dns: 0.3,
    auth: 0.5,
    alert: 0.8,
    malware: 0.8,
    http: 0.2,
    file: 0.2,
    email: 0.2,
    system: 0.4,
    general: 0.2
  };

  /** Base score by severity – critical highest, then high, medium, low. Ranges ensure no overlap. */
  const severityBase = { critical: 9, high: 6, medium: 4, low: 2, unknown: 1 };
  const maxBonusBySeverity = { critical: 1, high: 2, medium: 2, low: 2, unknown: 2 };

  const enrichedCampaigns = campaigns.map((c) => {
    const users = new Set();
    const types = new Set();
    let highestSeverity = 'low';

    const severityRank = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
      unknown: 0
    };

    for (const ev of c.events) {
      if (ev.username) users.add(ev.username);
      if (ev.type) types.add(ev.type);
      if (severityRank[ev.severity] > severityRank[highestSeverity]) {
        highestSeverity = ev.severity;
      }
    }

    const firstEvent = c.events[0];
    const lastEvent = c.events[c.events.length - 1];

    const maxTypeWeight = types.size
      ? Math.max(...Array.from(types).map((t) => typeWeight[t] ?? 0.2))
      : 0.2;
    const typeBonus = Math.min(maxTypeWeight, 0.8);
    const lengthBonus = Math.min(c.events.length * 0.05, 0.5);
    const bonusCap = maxBonusBySeverity[highestSeverity] ?? 2;
    const bonus = Math.min(typeBonus + lengthBonus, bonusCap);
    const base = severityBase[highestSeverity] ?? 2;
    const score = Math.min(Math.round(base + bonus), 10);

    return {
      sourceIp: c.sourceIp,
      firstSeen: firstEvent.timestamp,
      lastSeen: lastEvent.timestamp,
      durationMinutes:
        (lastEvent.date.getTime() - firstEvent.date.getTime()) / 60000,
      userCount: users.size,
      users: Array.from(users),
      eventCount: c.events.length,
      types: Array.from(types),
      highestSeverity,
      score,
      events: c.events.map((e) => ({
        timestamp: e.timestamp,
        type: e.type,
        severity: e.severity,
        username: e.username,
        destIp: e.destIp,
        destPort: e.destPort,
        action: e.action,
        message: e.message
      }))
    };
  });

  enrichedCampaigns.sort((a, b) => b.score - a.score);

  const topIndicators = [];

  for (const auth of suspiciousAuth) {
    topIndicators.push({
      label: `Suspicious authentication pattern: ${auth.actor}`,
      score: auth.score,
      details: auth.reason,
      category: 'authentication'
    });
  }

  if (enrichedCampaigns.length) {
    const firstCampaign = enrichedCampaigns[0];
    topIndicators.push({
      label: `Coordinated activity from ${firstCampaign.sourceIp}`,
      score: firstCampaign.score,
      highestSeverity: firstCampaign.highestSeverity,
      details: `Correlated ${firstCampaign.eventCount} events across ${firstCampaign.types.length} log types over ~${Math.round(
        firstCampaign.durationMinutes || 1
      )} minutes.`,
      category: 'multi-vector'
    });
  }

  const timeline = normalized.map((e) => ({
    timestamp: e.timestamp,
    type: e.type,
    severity: e.severity,
    sourceIp: e.sourceIp,
    destIp: e.destIp,
    destPort: e.destPort,
    username: e.username,
    message: e.message
  }));

  return {
    summary: {
      totalEvents: normalized.length,
      byType,
      bySeverity,
      timeRange: { from: first, to: last }
    },
    timeline,
    topIndicators,
    suspectedCampaigns: enrichedCampaigns
  };
}

app.post('/api/analyze', (req, res) => {
  try {
    const { events, fileName } = req.body || {};
    if (!Array.isArray(events)) {
      return res.status(400).json({
        error:
          'Request body must be JSON with an "events" array. Each element should be a log object.'
      });
    }
    if (events.length > 500000) {
      return res.status(400).json({
        error: `Too many rows (${events.length}). Maximum 500,000 events per upload.`
      });
    }

    const result = analyze(events, fileName);
    res.json(result);
  } catch (err) {
    console.error('Error analyzing logs', err);
    res.status(500).json({
      error: err.message || 'Unexpected error while analyzing logs.'
    });
  }
});

app.listen(PORT, () => {
  console.log(`SOC dashboard listening on http://localhost:${PORT}`);
});

