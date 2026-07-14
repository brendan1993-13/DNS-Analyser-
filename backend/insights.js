// Advanced log analyses: co-occurrence, auto-gauged spikes, adaptive overnight detection.

// 1. CO-OCCURRENCE: domains that resolve in the same second, repeatedly = same app/SDK
function coOccurrence(db, classify, opts) {
  opts = opts || {};
  const minShared = opts.minShared || 5;     // must co-occur at least this many times
  const minRatio = opts.minRatio || 0.5;     // and in at least this fraction of appearances
  // Group lookups into same-second buckets
  const _splitListCo = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExprCo = _splitListCo ? `CASE WHEN domain IN (${_splitListCo}) THEN domain ELSE root_domain END` : 'root_domain';
  const rows = db.prepare(`SELECT ${_groupExprCo} as root_domain, substr(timestamp,1,19) as sec FROM logs WHERE root_domain IS NOT NULL AND root_domain != ''`).all();
  const buckets = {};
  const domainCounts = {};
  rows.forEach(r => {
    (buckets[r.sec] = buckets[r.sec] || new Set()).add(r.root_domain);
    domainCounts[r.root_domain] = (domainCounts[r.root_domain] || 0) + 1;
  });
  // Count pairs
  const pairs = {};
  Object.values(buckets).forEach(set => {
    const arr = [...set];
    for (let i=0;i<arr.length;i++) for (let j=i+1;j<arr.length;j++) {
      const key = [arr[i],arr[j]].sort().join('|||');
      pairs[key] = (pairs[key]||0)+1;
    }
  });
  const results = [];
  for (const key in pairs) {
    const shared = pairs[key];
    if (shared < minShared) continue;
    const [a,b] = key.split('|||');
    const ratio = shared / Math.min(domainCounts[a], domainCounts[b]);
    if (ratio < minRatio) continue;
    const ia = classify(a), ib = classify(b);
    results.push({ a, b, shared, ratio: Math.round(ratio*100)/100, catA: ia.cat, catB: ib.cat, ownerA: ia.owner, ownerB: ib.owner });
  }
  results.sort((x,y)=>y.shared-x.shared);
  return results.slice(0, opts.limit || 60);
}

// 2. SUDDEN SPIKES: auto-gauged against each domain's own daily variance
function spikes(db, classify) {
  const _splitListSp = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExprSp = _splitListSp ? `CASE WHEN domain IN (${_splitListSp}) THEN domain ELSE root_domain END` : 'root_domain';
  const rows = db.prepare(`SELECT ${_groupExprSp} as root_domain, substr(timestamp,1,10) as day, COUNT(*) as n FROM logs WHERE root_domain IS NOT NULL AND root_domain != '' GROUP BY ${_groupExprSp}, day`).all();
  const byDomain = {};
  rows.forEach(r => { (byDomain[r.root_domain] = byDomain[r.root_domain] || []).push({ day:r.day, n:r.n }); });
  const results = [];
  for (const dom in byDomain) {
    const days = byDomain[dom];
    if (days.length < 4) continue;              // need history to judge "normal"
    const counts = days.map(d=>d.n);
    const mean = counts.reduce((a,c)=>a+c,0)/counts.length;
    const variance = counts.reduce((a,c)=>a+(c-mean)*(c-mean),0)/counts.length;
    const sd = Math.sqrt(variance);
    if (sd === 0) continue;
    // Find the biggest outlier day (z-score)
    let peak = days[0];
    days.forEach(d => { if (d.n > peak.n) peak = d; });
    const z = (peak.n - mean) / sd;
    if (z < 3) continue;                         // only genuinely anomalous (3+ SD)
    const info = classify(dom);
    results.push({
      domain: dom, cat: info.cat, owner: info.owner, risk: info.risk,
      peakDay: peak.day, peakCount: peak.n,
      normalAvg: Math.round(mean*10)/10, zScore: Math.round(z*10)/10,
      multiplier: Math.round((peak.n/Math.max(mean,0.1))*10)/10
    });
  }
  results.sort((a,b)=>b.zScore-a.zScore);
  return results.slice(0, 60);
}

// 3. ADAPTIVE OVERNIGHT: define "quiet hours" from overall activity, flag domains
//    disproportionately active during those quiet hours (personalised, no fixed schedule)
function overnightDomains(db, classify) {
  // Overall lookups per hour-of-day
  const hourRows = db.prepare("SELECT substr(timestamp,12,2) as hr, COUNT(*) as n FROM logs GROUP BY hr").all();
  const hourTotals = {};
  let grand = 0;
  hourRows.forEach(r => { hourTotals[r.hr] = r.n; grand += r.n; });
  // Overnight = actual clock night hours (00:00–05:59). Fixed, not volume-based,
  // so afternoon low-volume hours don't get mislabelled as 'overnight'.
  const nightHours = ['00','01','02','03','04','05'];
  const quietSet = new Set(nightHours);
  const sortedHours = nightHours;
  const quietShareOverall = nightHours.reduce((a,h)=>a+(hourTotals[h]||0),0) / grand;

  // Per-domain: fraction of its lookups in quiet hours
  const _splitListOn = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExprOn = _splitListOn ? `CASE WHEN domain IN (${_splitListOn}) THEN domain ELSE root_domain END` : 'root_domain';
  const rows = db.prepare(`SELECT ${_groupExprOn} as root_domain, substr(timestamp,12,2) as hr, COUNT(*) as n FROM logs WHERE root_domain IS NOT NULL AND root_domain != '' GROUP BY ${_groupExprOn}, hr`).all();
  const byDomain = {};
  rows.forEach(r => {
    if (!byDomain[r.root_domain]) byDomain[r.root_domain] = { total:0, quiet:0 };
    byDomain[r.root_domain].total += r.n;
    if (quietSet.has(r.hr)) byDomain[r.root_domain].quiet += r.n;
  });
  const results = [];
  for (const dom in byDomain) {
    const d = byDomain[dom];
    if (d.total < 10) continue;
    const quietShare = d.quiet / d.total;
    // Flag if domain's quiet-hour share is well above the network average
    if (quietShare > quietShareOverall * 2.5 && quietShare > 0.5) {
      const info = classify(dom);
      results.push({
        domain: dom, cat: info.cat, owner: info.owner, risk: info.risk,
        quietPct: Math.round(quietShare*100), total: d.total,
        vsNetworkAvg: Math.round((quietShare/quietShareOverall)*10)/10
      });
    }
  }
  results.sort((a,b)=>b.quietPct-a.quietPct);
  return {
    quietHours: sortedHours.sort(),
    networkQuietPct: Math.round(quietShareOverall*100),
    domains: results.slice(0, 60)
  };
}

module.exports = { coOccurrence, spikes, overnightDomains };

// DETECTED APPS: mapped services with inferred usage sessions, plus unmapped "possible apps"
function detectedApps(db, classify, SERVICE_MAP, parentService, domainRole) {
  const GAP = 15*60*1000;

  // Helper: build active sessions from content/app-role lookups for a set of domains
  function sessionsFor(domains) {
    const ph = domains.map(()=>'?').join(',');
    const rows = db.prepare('SELECT domain, timestamp FROM logs WHERE root_domain IN ('+ph+') ORDER BY timestamp ASC').all(...domains);
    const active = rows.filter(r => domainRole(r.domain) === 'content');
    const times = active.map(r=>new Date(r.timestamp).getTime()).filter(t=>!isNaN(t)).sort((a,b)=>a-b);
    const sessions = [];
    if (times.length) {
      let start=times[0], last=times[0], cnt=1;
      for (let i=1;i<times.length;i++){
        if (times[i]-last>GAP){ sessions.push({start,end:last,lookups:cnt}); start=times[i]; cnt=1; }
        else cnt++;
        last=times[i];
      }
      sessions.push({start,end:last,lookups:cnt});
    }
    return sessions.map(s => ({
      start: new Date(s.start).toISOString(),
      end: new Date(s.end).toISOString(),
      minutes: Math.round((s.end-s.start)/60000),
      lookups: s.lookups
    }));
  }

  // 1. Mapped apps (high confidence)
  const services = {};
  Object.keys(SERVICE_MAP).forEach(dom => {
    const svc = SERVICE_MAP[dom];
    (services[svc] = services[svc] || []).push(dom);
  });
  const mapped = [];
  for (const svc in services) {
    const doms = services[svc];
    const present = db.prepare('SELECT COUNT(*) as n FROM logs WHERE root_domain IN ('+doms.map(()=>'?').join(',')+')').get(...doms).n;
    if (present === 0) continue;
    const sessions = sessionsFor(doms);
    const realSessions = sessions.filter(s => s.lookups >= 2); // drop trivial single-lookup blips
    mapped.push({
      app: svc,
      domains: doms.length,
      totalLookups: present,
      usageSessions: realSessions.length,
      sessions: realSessions.slice(0, 100),
      totalActiveMinutes: realSessions.reduce((a,s)=>a+s.minutes,0)
    });
  }
  mapped.sort((a,b)=>b.usageSessions-a.usageSessions);

  // 2. Possible apps (unmapped root domains with app-like signatures)
  const rows = db.prepare("SELECT root_domain, COUNT(*) as visits, COUNT(DISTINCT domain) as subdomains, COUNT(DISTINCT substr(timestamp,1,10)) as days FROM logs WHERE root_domain IS NOT NULL AND root_domain != '' GROUP BY root_domain").all();
  const possible = [];
  for (const r of rows) {
    const dom = r.root_domain;
    if (parentService(dom)) continue;                 // already mapped
    if (dom.endsWith('.invalid')) continue;
    // App-like signature: multiple subdomains, recurring across several days, decent volume
    if (r.subdomains >= 2 && r.days >= 3 && r.visits >= 15) {
      const info = classify(dom);
      // Skip pure infra/ad/analytics — not "apps" in the user sense
      if (['Infrastructure / CDN','Advertising / Ad Tech','Analytics / Monitoring'].includes(info.cat)) continue;
      possible.push({
        domain: dom, cat: info.cat, owner: info.owner, risk: info.risk,
        visits: r.visits, subdomains: r.subdomains, days: r.days
      });
    }
  }
  possible.sort((a,b)=>b.visits-a.visits);

  return { mapped, possible: possible.slice(0, 40) };
}

module.exports.detectedApps = detectedApps;

// Meta real-time connection signal — counts NetSeer IP-association lookups, which
// fire when the Meta app opens live connections (messaging, live features, notifications).
// Indicates ACTIVE INTERACTIVE use vs passive scrolling. Cannot isolate Messenger
// specifically, nor reveal contacts/content — DNS has no such resolution.
function metaRealtimeActivity(db) {
  const total = db.prepare("SELECT COUNT(*) n FROM logs WHERE domain LIKE '%netseer-ipaddr-assoc%'").get().n;
  const unique = db.prepare("SELECT COUNT(DISTINCT domain) n FROM logs WHERE domain LIKE '%netseer-ipaddr-assoc%'").get().n;
  // Per-day breakdown
  const byDay = db.prepare("SELECT substr(timestamp,1,10) as day, COUNT(DISTINCT domain) as connections FROM logs WHERE domain LIKE '%netseer-ipaddr-assoc%' GROUP BY day ORDER BY day DESC").all();
  // Per-hour distribution (when is Meta most actively connecting)
  const byHour = db.prepare("SELECT substr(timestamp,12,2) as hr, COUNT(DISTINCT domain) as connections FROM logs WHERE domain LIKE '%netseer-ipaddr-assoc%' GROUP BY hr ORDER BY hr").all();
  const activeDays = byDay.length;
  const avgPerDay = activeDays ? Math.round(unique / activeDays) : 0;
  // Peak day
  let peak = { day: null, connections: 0 };
  byDay.forEach(d => { if (d.connections > peak.connections) peak = d; });
  return {
    totalLookups: total,
    uniqueConnections: unique,
    activeDays,
    avgConnectionsPerActiveDay: avgPerDay,
    peakDay: peak,
    byDay: byDay.slice(0, 45),
    byHour,
    note: 'NetSeer connection events indicate active real-time Meta use (messaging, live features, notifications). Cannot isolate Messenger from Instagram DMs or other live features, and reveals nothing about contacts or content.'
  };
}

module.exports.metaRealtimeActivity = metaRealtimeActivity;
