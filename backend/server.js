let classify;
try {
  classify = require("./classify");
  console.log("classify.js loaded OK (" + Object.keys(require.cache[require.resolve("./classify")] ? {} : {}).length + ")");
} catch (e) {
  console.error("CRITICAL: classify.js failed to load - running in DEGRADED mode. Fix classify.js and restart. Error:", e.message);
  classify = function(d) {
    return { cat: "Unknown", owner: "Unknown", purpose: "classify.js is currently broken - see server logs", data: "Unknown", risk: "L", bg: true };
  };
  classify.SPLIT_DOMAINS = new Set();
  classify.groupKey = function(domain, rootDomain) { return rootDomain; };
}
const { researchDomain, researchAllUnknown, loadCustom } = require("./auto_classify");
const { verifyAll, loadReport, loadOverrides, loadFixLog } = require("./verify");
const { SERVICE_MAP, parentService, domainRole, computeVerdict } = require("./services");
const { coOccurrence, spikes, overnightDomains, detectedApps, metaRealtimeActivity } = require("./insights");
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const cron = require('node-cron');
const axios = require('axios');
const XLSX = require('xlsx');
const { parse } = require('csv-parse/sync');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = 3001;
const DB_FILE = path.join(__dirname, 'data', 'dns.db');
const CONFIG_FILE = path.join(__dirname, 'data', 'config.json');

app.use(cors());
app.use(express.json());

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));

const db = new Database(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, domain TEXT, root_domain TEXT,
    query_type TEXT, protocol TEXT, client_ip TEXT,
    status TEXT, reasons TEXT, destination_country TEXT, device_name TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ts ON logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_root ON logs(root_domain);
`);

function loadConfig() { try { return JSON.parse(fs.readFileSync(CONFIG_FILE,'utf8')); } catch(e) { return {}; } }
function saveConfig(cfg) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg)); }
function getLastTs() { return db.prepare('SELECT MAX(timestamp) as ts FROM logs').get()?.ts || ''; }

function classifyRow(r) {
  const gk = classify.groupKey ? classify.groupKey(r.domain||'', r.root_domain||'') : (r.root_domain||'');
  const info = classify(gk||'');
  let service = null;
  try { service = parentService(gk) || parentService(r.root_domain||'') || null; } catch(e) {}
  return {
    category: info.cat,
    risk: info.risk==='H'?'High':info.risk==='M'?'Medium':'Low',
    owner: info.owner,
    service
  };
}
function insertRows(rows) {
  const ins = db.prepare(`INSERT INTO logs (timestamp,domain,root_domain,query_type,protocol,client_ip,status,reasons,destination_country,device_name,category,risk,owner,service) VALUES (@timestamp,@domain,@root_domain,@query_type,@protocol,@client_ip,@status,@reasons,@destination_country,@device_name,@category,@risk,@owner,@service)`);
  db.transaction((rows) => { for (const r of rows) { const c = classifyRow(r); ins.run({timestamp:r.timestamp||'',domain:r.domain||'',root_domain:r.root_domain||'',query_type:r.query_type||'',protocol:r.protocol||'',client_ip:r.client_ip||'',status:r.status||'',reasons:r.reasons||'',destination_country:r.destination_country||'',device_name:r.device_name||r.device_model||'',category:c.category,risk:c.risk,owner:c.owner,service:c.service}); } })(rows);
}

function parseCSV(text) {
  return parse(text, { columns:true, skip_empty_lines:true, trim:true }).filter(r => r.timestamp);
}

async function fetchFromNextDNS(apiKey, profileId) {
  const r = await axios.get(`https://api.nextdns.io/profiles/${profileId}/logs`, { headers:{'X-Api-Key':apiKey}, params:{limit:1000} });
  const raw = r.data.data || [];
  // Normalise API format to match CSV format
  return raw.map(row => ({
    timestamp: row.timestamp || '',
    domain: row.domain || '',
    root_domain: row.root || row.root_domain || '',
    query_type: row.type || row.query_type || '',
    protocol: row.protocol || '',
    client_ip: row.clientIp || row.client_ip || '',
    status: row.status || '',
    reasons: Array.isArray(row.reasons) ? row.reasons.map(r=>r.id||r).join(',') : (row.reasons||''),
    destination_country: row.country || row.destination_country || '',
    device_name: (row.device && row.device.name) || row.device_name || ''
  }));
}

cron.schedule('*/15 * * * *', async () => {
  const cfg = loadConfig();
  if (!cfg.apiKey || !cfg.profileId) return;
  try {
    const fetched = await fetchFromNextDNS(cfg.apiKey, cfg.profileId);
    const lastTs = getLastTs();
    const newRows = lastTs ? fetched.filter(r => r.timestamp > lastTs) : fetched;
    if (newRows.length) insertRows(newRows);
    console.log(`Auto-pull: added ${newRows.length}`);
    if (newRows.length > 0) { setTimeout(backgroundResearch, 2000); setTimeout(detectNewDomains, 2500); }
  } catch(e) { console.error('Auto-pull failed:', e.message); }
});


// Auto-research unknown domains in the background (non-blocking)
let researchRunning = false;
async function backgroundResearch() {
  if (researchRunning) return;
  researchRunning = true;
  try {
    const rows = db.prepare('SELECT DISTINCT root_domain FROM logs').all();
    const custom = loadCustom();
    const unknown = rows.filter(r => {
      const rd = r.root_domain;
      if (!rd || !rd.trim()) return false;
      if (custom[rd]) return false;
      return classify(rd).cat === 'Unknown';
    });
    if (unknown.length === 0) { researchRunning = false; return; }
    console.log(`Background research: ${unknown.length} new unknown domains`);
    for (const r of unknown) {
      try {
        await researchDomain(r.root_domain);
        await new Promise(res => setTimeout(res, 600));
      } catch(e) {}
    }
    console.log('Background research complete');
  } catch(e) {
    console.error('Background research error:', e.message);
  }
  researchRunning = false;
}

app.get('/api/stats', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as n FROM logs').get().n;
  const domains = db.prepare('SELECT COUNT(DISTINCT root_domain) as n FROM logs').get().n;
  const days = db.prepare("SELECT COUNT(DISTINCT substr(timestamp,1,10)) as n FROM logs").get().n;
  const blocked = db.prepare("SELECT COUNT(*) as n FROM logs WHERE status='blocked'").get().n;
  res.json({ count, domains, days, blocked, lastTs: getLastTs() });
});

app.get('/api/summary', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as n FROM logs').get().n;
  const domains = db.prepare('SELECT COUNT(DISTINCT root_domain) as n FROM logs').get().n;
  const days = db.prepare("SELECT COUNT(DISTINCT substr(timestamp,1,10)) as n FROM logs").get().n;
  const blocked = db.prepare("SELECT COUNT(*) as n FROM logs WHERE status='blocked'").get().n;
  const _splitList2 = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExpr2 = _splitList2 ? `CASE WHEN domain IN (${_splitList2}) THEN domain ELSE root_domain END` : 'root_domain';
  const topDomainsRaw = db.prepare(`SELECT ${_groupExpr2} as domain, COUNT(*) as count FROM logs GROUP BY ${_groupExpr2} ORDER BY count DESC LIMIT 300`).all();
  const topDomains = topDomainsRaw.map(r => {
    const info = classify(r.domain||'');
    return { ...r, root_domain:r.domain, _cat:info.cat, _owner:info.owner, _purpose:info.purpose, _data:info.data, _risk:info.risk, _bg:info.bg };
  });
  const byDate = db.prepare("SELECT substr(timestamp,1,10) as date, COUNT(*) as count FROM logs GROUP BY date ORDER BY date").all();
  res.json({ count, domains, days, blocked, topDomains, byDate });
});

app.get('/api/rows', (req, res) => {
  const page = parseInt(req.query.page)||0;
  const limit = Math.min(parseInt(req.query.limit)||200, 500);
  const q = req.query.q||'';
  const tab = req.query.tab||'all';
  let where = '1=1';
  const params = {};
  if (q) { where += " AND (root_domain LIKE @q OR domain LIKE @q OR category LIKE @q OR service LIKE @q OR device_name LIKE @q OR destination_country LIKE @q OR status LIKE @q OR owner LIKE @q)"; params.q = `%${q}%`; }
  if (tab === 'blocked') where += " AND status='blocked'";
  const total = db.prepare(`SELECT COUNT(*) as n FROM logs WHERE ${where}`).get(params).n;
  const rawRows = db.prepare(`SELECT * FROM logs WHERE ${where} ORDER BY timestamp DESC LIMIT ${limit} OFFSET ${page*limit}`).all(params);
  const rows = rawRows.map(r => {
    const gk = classify.groupKey ? classify.groupKey(r.domain, r.root_domain) : r.root_domain;
    const info = classify(gk||'');
    return { ...r, _cat:info.cat, _owner:info.owner, _purpose:info.purpose, _data:info.data, _risk:info.risk, _bg:info.bg };
  });
  res.json({ count:total, page, pages:Math.ceil(total/limit), rows });
});

app.get('/api/persite', (req, res) => {
  const q = req.query.q||'';
  const catFilter = req.query.cat||'';
  const riskFilter = req.query.risk||'';
  const actFilter = req.query.act||'';
  const where = q ? "WHERE root_domain LIKE @q" : "";
  const params = q ? {q:`%${q}%`} : {};
  const _splitList3 = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExpr3 = _splitList3 ? `CASE WHEN domain IN (${_splitList3}) THEN domain ELSE root_domain END` : 'root_domain';
  let rows = db.prepare(`SELECT ${_groupExpr3} as root_domain, COUNT(*) as total_visits, COUNT(DISTINCT substr(timestamp,1,10)) as unique_days, MIN(substr(timestamp,1,10)) as first_seen, MAX(substr(timestamp,1,10)) as last_seen FROM logs ${where} GROUP BY ${_groupExpr3} ORDER BY total_visits DESC`).all(params);
  const SEARCH = new Set(['google.com','google.com.au','bing.com','duckduckgo.com','yahoo.com']);
  const USER_CATS = new Set(['Social Networking','Shopping / Retail','Entertainment / Streaming','Food / Transport','Travel / Logistics','Government','Pool / Aquatic','Work / Employment','Real Estate','News / Media','Health','Telecoms','AI Services','Adult Content','Finance / Banking','Messaging / Communication']);
  if (catFilter) rows = rows.filter(r => classify(r.root_domain||'').cat === catFilter);
  if (riskFilter) rows = rows.filter(r => classify(r.root_domain||'').risk === riskFilter);
  if (actFilter) rows = rows.filter(r => {
    const info = classify(r.root_domain||'');
    const at = SEARCH.has(r.root_domain) ? 'Search' : USER_CATS.has(info.cat) ? 'User-Initiated' : 'Background';
    return at === actFilter;
  });
  // Enrich each row with authoritative backend classification (single source of truth)
  const enriched = rows.map(r => {
    const info = classify(r.root_domain||'');
    const at = SEARCH.has(r.root_domain) ? 'Search' : USER_CATS.has(info.cat) ? 'User-Initiated' : 'Background';
    return { ...r, _cat:info.cat, _owner:info.owner, _purpose:info.purpose, _data:info.data, _risk:info.risk, _bg:info.bg, _at:at };
  });
  res.json({ rows: enriched });
});

app.get('/api/persite/:domain', (req, res) => {
  const domain = req.params.domain;
  const byDate = db.prepare(`SELECT substr(timestamp,1,10) as date, COUNT(*) as count FROM logs WHERE root_domain=? GROUP BY date ORDER BY date DESC`).all(domain);
  const byHour = db.prepare(`SELECT substr(timestamp,12,2) as hour, COUNT(*) as count FROM logs WHERE root_domain=? GROUP BY hour ORDER BY hour`).all(domain);
  const recent = db.prepare(`SELECT timestamp, domain, query_type, status, destination_country FROM logs WHERE root_domain=? ORDER BY timestamp DESC LIMIT 50`).all(domain);
  const blocked = db.prepare(`SELECT COUNT(*) as n FROM logs WHERE root_domain=? AND status='blocked'`).get(domain).n;
  res.json({ domain, byDate, byHour, recent, blocked });
});

app.get('/api/catdate', (req, res) => {
  const rows = db.prepare("SELECT substr(timestamp,1,10) as date, root_domain, status, COUNT(*) as count FROM logs GROUP BY date, root_domain ORDER BY date DESC LIMIT 5000").all();
  res.json({ rows });
});

const upload = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 500*1024*1024 } });
app.post('/api/upload', upload.single('file'), (req, res) => {
  try {
    const incoming = parseCSV(req.file.buffer.toString('utf8'));
    const lastTs = getLastTs();
    const newRows = lastTs ? incoming.filter(r => r.timestamp > lastTs) : incoming;
    if (newRows.length) insertRows(newRows);
    const total = db.prepare('SELECT COUNT(*) as n FROM logs').get().n;
    res.json({ success:true, total, added:newRows.length, skipped:incoming.length-newRows.length });
    if (newRows.length > 0) { setTimeout(backgroundResearch, 1000); setTimeout(detectNewDomains, 1500); }
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/pull', async (req, res) => {
  const cfg = loadConfig();
  if (!cfg.apiKey || !cfg.profileId) return res.status(400).json({ error:'No API key configured' });
  try {
    const fetched = await fetchFromNextDNS(cfg.apiKey, cfg.profileId);
    const lastTs = getLastTs();
    const newRows = lastTs ? fetched.filter(r => r.timestamp > lastTs) : fetched;
    if (newRows.length) insertRows(newRows);
    const total = db.prepare('SELECT COUNT(*) as n FROM logs').get().n;
    res.json({ success:true, total, added:newRows.length });
    if (newRows.length > 0) { setTimeout(backgroundResearch, 1000); setTimeout(detectNewDomains, 1500); }
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.post('/api/config', (req, res) => {
  saveConfig({ apiKey:req.body.apiKey, profileId:req.body.profileId });
  res.json({ success:true });
});

app.delete('/api/rows', (req, res) => {
  db.exec('DELETE FROM logs');
  res.json({ success:true });
});

app.get('/api/export', (req, res) => {
  // Filters: ?category=X  ?risk=H  ?from=YYYY-MM-DD  ?to=YYYY-MM-DD  ?full=1
  const catFilter = req.query.category || '';
  const catList = catFilter ? catFilter.split(',').map(x=>x.trim()).filter(Boolean) : [];
  const riskFilter = req.query.risk || '';
  const fromDate = req.query.from || '';
  const toDate = req.query.to || '';
  const fullRequested = req.query.full === '1' || req.query.full === 'true';
  const serviceFilter = req.query.service || '';
  const serviceList = serviceFilter ? serviceFilter.split(',').map(x=>x.trim()).filter(Boolean) : [];
  const isFiltered = serviceList.length || (req.query.category||'').length || (req.query.risk||'').length || (req.query.from||'').length || (req.query.to||'').length;
  const includeFullLog = fullRequested || isFiltered;

  // Build date WHERE clause
  const dateWhere = [];
  const dateParams = {};
  if (fromDate) { dateWhere.push("substr(timestamp,1,10) >= @from"); dateParams.from = fromDate; }
  if (toDate) { dateWhere.push("substr(timestamp,1,10) <= @to"); dateParams.to = toDate; }
  const whereClause = dateWhere.length ? 'WHERE ' + dateWhere.join(' AND ') : '';

  const SEARCH = new Set(['google.com','google.com.au','bing.com','duckduckgo.com','yahoo.com']);
  const USER_CATS = new Set(['Social Networking','Shopping / Retail','Entertainment / Streaming','Food / Transport','Travel / Logistics','Government','Pool / Aquatic','Work / Employment','Real Estate','News / Media','Health','Telecoms','AI Services','Adult Content','Finance / Banking','Messaging / Communication']);

  // Per-domain summary within the date range
  const _splitList = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExpr = _splitList ? `CASE WHEN domain IN (${_splitList}) THEN domain ELSE root_domain END` : 'root_domain';
  let domRows = db.prepare(`SELECT ${_groupExpr} as root_domain, COUNT(*) as total_visits, COUNT(DISTINCT substr(timestamp,1,10)) as unique_days, MIN(substr(timestamp,1,10)) as first_seen, MAX(substr(timestamp,1,10)) as last_seen, GROUP_CONCAT(DISTINCT status) as statuses FROM logs ${whereClause} GROUP BY ${_groupExpr} ORDER BY total_visits DESC`).all(dateParams);

  // Build set of domains for the requested service(s) (if any)
  let serviceDomains = null;
  if (serviceList.length) {
    const svcSet = new Set(serviceList);
    serviceDomains = new Set(Object.keys(SERVICE_MAP).filter(d => svcSet.has(SERVICE_MAP[d])));
  }

  // Apply category + risk + service filters (categories/services can be lists)
  domRows = domRows.filter(r => {
    const info = classify(r.root_domain||'');
    if (catList.length && !catList.includes(info.cat)) return false;
    if (riskFilter && info.risk !== riskFilter) return false;
    if (serviceDomains && !serviceDomains.has(r.root_domain)) return false;
    return true;
  });

  if (domRows.length === 0) return res.status(400).json({ error:'No data matches those filters' });

  const matchingDomains = new Set(domRows.map(r => r.root_domain));

  // ── Large full-detail exports: stream Activity Log as CSV (near-zero memory) ──
  // The xlsx library is fully in-memory; ~335K rows spikes to ~3GB and OOM-kills
  // the process. Above this threshold we stream row-by-row as CSV instead.
  const CSV_STREAM_THRESHOLD = 50000;
  if (includeFullLog) {
    const totalRows = db.prepare(`SELECT COUNT(*) c FROM logs ${whereClause}`).get(dateParams).c;
    if (totalRows > CSV_STREAM_THRESHOLD) {
      let cfname = 'dns_activity_log';
      if (fromDate) cfname += '_from-' + fromDate;
      if (toDate) cfname += '_to-' + toDate;
      cfname += '.csv';
      res.setHeader('Content-Disposition', 'attachment; filename=' + cfname);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      const csvEsc = v => {
        if (v === null || v === undefined) return '';
        const str = String(v);
        return /[",\n\r]/.test(str) ? '"' + str.replace(/"/g, '""') + '"' : str;
      };
      res.write('Timestamp,Date,Time,Service,Domain,Root Domain,Category,Owner,Purpose,Data Collected,Privacy Risk,Activity Type,Query Type,Protocol,Country,Status,Block Reason,Device\n');
      const stmt = db.prepare(`SELECT * FROM logs ${whereClause} ORDER BY timestamp ASC`);
      for (const r of stmt.iterate(dateParams)) {
        const gk = classify.groupKey ? classify.groupKey(r.domain, r.root_domain) : r.root_domain;
        if (!matchingDomains.has(gk)) continue;
        const info = classify(gk||'');
        const at = SEARCH.has(gk) ? 'Search' : USER_CATS.has(info.cat) ? 'User-Initiated' : 'Background';
        const svc = parentService(gk) || '';
        const ts = r.timestamp||'';
        const row = [ts, ts.split('T')[0]||'', (ts.split('T')[1]||'').substring(0,8), svc, r.domain||'', gk||'', info.cat, info.owner, info.purpose, info.data, info.risk==='H'?'High':info.risk==='M'?'Medium':'Low', at, r.query_type||'', r.protocol||'', r.destination_country||'', r.status||'', r.reasons||'', r.device_name||''];
        res.write(row.map(csvEsc).join(',') + '\n');
      }
      return res.end();
    }
  }

  const wb = XLSX.utils.book_new();

  // Sheet 1: Domain Intelligence (always included - the rich per-site data)
  const domHeaders = ['Domain','Category','Owner','Purpose','Data Collected','Privacy Risk','Activity Type','Total Visits','Unique Days','First Seen','Last Seen','Blocked?'];
  const domData = domRows.map(r => {
    const info = classify(r.root_domain||'');
    const at = SEARCH.has(r.root_domain) ? 'Search' : USER_CATS.has(info.cat) ? 'User-Initiated' : 'Background';
    return [r.root_domain, info.cat, info.owner, info.purpose, info.data, info.risk==='H'?'High':info.risk==='M'?'Medium':'Low', at, r.total_visits, r.unique_days, r.first_seen, r.last_seen, (r.statuses||'').includes('blocked')?'Yes':'No'];
  });
  const ws1 = XLSX.utils.aoa_to_sheet([domHeaders, ...domData]);
  ws1['!cols'] = [30,22,26,55,45,10,15,10,10,12,12,8].map(w=>({wch:w}));
  XLSX.utils.book_append_sheet(wb, ws1, 'Domain Intelligence');

  // Sheet 2: Category Summary (of the filtered set)
  const catMap = {};
  domRows.forEach(r => {
    const info = classify(r.root_domain||'');
    if (catMap[info.cat] === undefined) catMap[info.cat] = {visits:0,domains:0,h:0,m:0};
    catMap[info.cat].visits += r.total_visits;
    catMap[info.cat].domains++;
    if (info.risk==='H') catMap[info.cat].h++; else if (info.risk==='M') catMap[info.cat].m++;
  });
  const ws2 = XLSX.utils.aoa_to_sheet([['Category','Total Visits','Domains','High Risk','Medium Risk','Low Risk'],...Object.entries(catMap).sort((a,b)=>b[1].visits-a[1].visits).map(([c,v])=>[c,v.visits,v.domains,v.h,v.m,v.domains-v.h-v.m])]);
  ws2['!cols'] = [25,12,10,10,12,10].map(w=>({wch:w}));
  XLSX.utils.book_append_sheet(wb, ws2, 'Category Summary');

  // Sheet 3: Activity Log — every matching entry in chronological order, tagged by service
  if (includeFullLog) {
    const rows = db.prepare(`SELECT * FROM logs ${whereClause} ORDER BY timestamp ASC`).all(dateParams);
    const logHeaders = ['Timestamp','Date','Time','Service','Domain','Root Domain','Category','Owner','Purpose','Data Collected','Privacy Risk','Activity Type','Query Type','Protocol','Country','Status','Block Reason','Device'];
    const logData = rows.filter(r => matchingDomains.has(classify.groupKey ? classify.groupKey(r.domain, r.root_domain) : r.root_domain)).map(r => {
      const gk = classify.groupKey ? classify.groupKey(r.domain, r.root_domain) : r.root_domain;
      const info = classify(gk||'');
      const at = SEARCH.has(gk) ? 'Search' : USER_CATS.has(info.cat) ? 'User-Initiated' : 'Background';
      const svc = parentService(gk) || '';
      const ts = r.timestamp||'';
      return [ts, ts.split('T')[0]||'', (ts.split('T')[1]||'').substring(0,8), svc, r.domain||'', gk||'', info.cat, info.owner, info.purpose, info.data, info.risk==='H'?'High':info.risk==='M'?'Medium':'Low', at, r.query_type||'', r.protocol||'', r.destination_country||'', r.status||'', r.reasons||'', r.device_name||''];
    });
    const ws3 = XLSX.utils.aoa_to_sheet([logHeaders, ...logData]);
    ws3['!cols'] = [14,10,8,18,32,26,22,26,55,45,8,15,6,18,8,10,20,15].map(w=>({wch:w}));
    XLSX.utils.book_append_sheet(wb, ws3, 'Activity Log (chronological)');
  }

  // Build filename from filters
  let fname = 'dns';
  if (serviceList.length) fname += '_' + serviceList.join('-').replace(/[^a-z0-9]/gi,'-');
  if (catList.length) fname += '_' + catList.join('-').replace(/[^a-z0-9]/gi,'-');
  if (riskFilter) fname += '_risk-' + riskFilter;
  if (fromDate) fname += '_from-' + fromDate;
  if (toDate) fname += '_to-' + toDate;
  fname += '.xlsx';

  const buf = XLSX.write(wb, { type:'buffer', bookType:'xlsx' });
  res.setHeader('Content-Disposition', 'attachment; filename=' + fname);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});


// Get unknown domains list
app.get('/api/classify/unknown', (req, res) => {
  const rows = db.prepare('SELECT root_domain, COUNT(*) as visits FROM logs GROUP BY root_domain ORDER BY visits DESC').all();
  const custom = loadCustom();
  const unknown = rows.filter(r => {
    if (!r.root_domain || !r.root_domain.trim()) return false;
    if (custom[r.root_domain]) return false;
    return classify(r.root_domain).cat === 'Unknown';
  });
  res.json({ count: unknown.length, domains: unknown });
});

// Get custom classifications
app.get('/api/classify/custom', (req, res) => {
  res.json(loadCustom());
});

// Research a single domain
app.post('/api/classify/research/:domain', async (req, res) => {
  try {
    const result = await researchDomain(req.params.domain);
    res.json({ domain: req.params.domain, ...result });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Research all unknown domains (background)
app.post('/api/classify/research-all', async (req, res) => {
  res.json({ message: 'Research started in background' });
  backgroundResearch();
});


// Start verification against VirusTotal (background)
app.post('/api/verify/start', (req, res) => {
  const limit = parseInt(req.body && req.body.limit) || 100;
  res.json({ message: 'Verification started', limit, note: 'Checks most-recently-seen domains first. ~16s per domain due to free-tier rate limit.' });
  verifyAll(db, classify, { limit }).catch(e => console.error('Verify error:', e.message));
});

// Get the latest verification report
app.get('/api/verify/report', (req, res) => {
  const r = loadReport();
  if (!r) return res.json({ message: 'No verification run yet' });
  res.json(r);
});


// View what was auto-fixed
app.get('/api/verify/fixes', (req, res) => {
  res.json({ overrides: loadOverrides(), log: loadFixLog() });
});

// Undo a specific auto-fix
app.delete('/api/verify/fixes/:domain', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const f = path.join(__dirname, 'data', 'verified_overrides.json');
  try {
    const ov = JSON.parse(fs.readFileSync(f,'utf8'));
    delete ov[req.params.domain];
    fs.writeFileSync(f, JSON.stringify(ov, null, 2));
    res.json({ success:true, removed:req.params.domain });
  } catch(e) { res.status(500).json({ error:e.message }); }
});


// Daily auto-reverify — re-checks domains against VirusTotal and auto-fixes (3am daily)
cron.schedule('0 3 * * *', () => {
  const cfg = loadConfig();
  if (!cfg.vtKey) return;
  console.log('Daily auto-reverify starting...');
  verifyAll(db, classify, { limit: 200, autoFix: true }).then(r => {
    console.log('Daily reverify done:', r.checked, 'checked,', (r.autoFixed||[]).length, 'auto-fixed');
  }).catch(e => console.error('Reverify failed:', e.message));
});


app.get('/api/sessions/:domain', (req, res) => {
  const domain = req.params.domain;
  const GAP_MS = 15 * 60 * 1000;
  const rows = db.prepare('SELECT timestamp FROM logs WHERE root_domain=? ORDER BY timestamp ASC').all(domain);
  if (rows.length === 0) return res.json({ domain, sessions: [], totalMs: 0, note: 'No activity' });
  const times = rows.map(r => new Date(r.timestamp).getTime()).filter(t => !isNaN(t));
  const sessions = [];
  let start = times[0], last = times[0];
  for (let i = 1; i < times.length; i++) {
    if (times[i] - last > GAP_MS) { sessions.push({ start, end: last, durationMs: last - start }); start = times[i]; }
    last = times[i];
  }
  sessions.push({ start, end: last, durationMs: last - start });
  sessions.forEach(sess => {
    sess.lookups = times.filter(t => t >= sess.start && t <= sess.end).length;
    sess.startISO = new Date(sess.start).toISOString();
    sess.endISO = new Date(sess.end).toISOString();
    sess.minutes = Math.round(sess.durationMs / 60000);
  });
  const totalMs = sessions.reduce((a,x) => a + x.durationMs, 0);
  res.json({ domain, sessionCount: sessions.length, totalMs, totalMinutes: Math.round(totalMs/60000), estimate: true, note: 'Estimated from DNS lookup clustering. Actual usage likely higher due to caching.', sessions: sessions.sort((a,b)=>b.start-a.start) });
});

app.get('/api/byservice', (req, res) => {
  const _splitListBs = Array.from(classify.SPLIT_DOMAINS || []).map(d => "'" + d.replace(/'/g,"''") + "'").join(',');
  const _groupExprBs = _splitListBs ? `CASE WHEN domain IN (${_splitListBs}) THEN domain ELSE root_domain END` : 'root_domain';
  const rows = db.prepare(`SELECT ${_groupExprBs} as root_domain, COUNT(*) as visits, MIN(substr(timestamp,1,10)) as first_seen, MAX(substr(timestamp,1,10)) as last_seen FROM logs GROUP BY ${_groupExprBs}`).all();
  const services = {};
  rows.forEach(r => {
    const svc = parentService(r.root_domain);
    if (!svc) return;
    if (!services[svc]) services[svc] = { service: svc, domains: [], totalVisits: 0, firstSeen: r.first_seen, lastSeen: r.last_seen };
    services[svc].domains.push({ domain: r.root_domain, visits: r.visits });
    services[svc].totalVisits += r.visits;
    if (r.first_seen < services[svc].firstSeen) services[svc].firstSeen = r.first_seen;
    if (r.last_seen > services[svc].lastSeen) services[svc].lastSeen = r.last_seen;
  });
  const result = Object.values(services).map(x => ({ service:x.service, totalVisits:x.totalVisits, domainCount:x.domains.length, domains:x.domains.sort((a,b)=>b.visits-a.visits), firstSeen:x.firstSeen, lastSeen:x.lastSeen })).sort((a,b)=>b.totalVisits-a.totalVisits);
  res.json({ services: result });
});


// Human-usage verdict for a service (or single domain)
app.get('/api/verdict/:service', (req, res) => {
  const svc = req.params.service;
  // Gather all domains for this service
  const doms = Object.keys(SERVICE_MAP).filter(d => SERVICE_MAP[d] === svc);
  let rows;
  if (doms.length) {
    const ph = doms.map(()=>'?').join(',');
    rows = db.prepare('SELECT domain, timestamp FROM logs WHERE root_domain IN ('+ph+') ORDER BY timestamp ASC').all(...doms);
  } else {
    // Treat as a single root domain
    rows = db.prepare('SELECT domain, timestamp FROM logs WHERE root_domain=? ORDER BY timestamp ASC').all(svc);
  }
  const result = computeVerdict(rows);
  res.json({ service: svc, ...result, note: 'Inference from DNS patterns, not proof. Heavy caching can affect accuracy.' });
});


// Accurate active-time estimate for a service — counts only content/app-role
// lookups (real interaction), excluding auth/telemetry/push background chatter.
app.get('/api/servicetime/:service', (req, res) => {
  const svc = req.params.service;
  const doms = Object.keys(SERVICE_MAP).filter(d => SERVICE_MAP[d] === svc);
  let rows;
  if (doms.length) {
    const ph = doms.map(()=>'?').join(',');
    rows = db.prepare('SELECT domain, timestamp FROM logs WHERE root_domain IN ('+ph+') ORDER BY timestamp ASC').all(...doms);
  } else {
    rows = db.prepare('SELECT domain, timestamp FROM logs WHERE root_domain=? ORDER BY timestamp ASC').all(svc);
  }
  // Keep only lookups that indicate real interaction (content or general app), drop background
  const active = rows.filter(r => {
    const role = domainRole(r.domain);
    return role === 'content';
  });
  const GAP = 15*60*1000;
  const times = active.map(r => new Date(r.timestamp).getTime()).filter(t=>!isNaN(t)).sort((a,b)=>a-b);
  let totalMs = 0, sessionCount = 0;
  if (times.length) {
    let start = times[0], last = times[0];
    for (let i=1;i<times.length;i++){
      if (times[i]-last > GAP){ totalMs += (last-start); sessionCount++; start=times[i]; }
      last = times[i];
    }
    totalMs += (last-start); sessionCount++;
  }
  res.json({
    service: svc,
    activeMinutes: Math.round(totalMs/60000),
    activeSessions: sessionCount,
    contentLookups: active.length,
    totalLookups: rows.length,
    note: 'Active time estimated from content/interaction lookups only, excluding background auth/telemetry. Still an estimate; caching means real usage may be higher.'
  });
});


// ─── NEW SITES: detect domains never seen before ─────────────────────────────
const KNOWN_FILE = require('path').join(__dirname, 'data', 'known_domains.json');
const NEW_FILE = require('path').join(__dirname, 'data', 'new_domains.json');
function loadKnown() { try { return JSON.parse(require('fs').readFileSync(KNOWN_FILE,'utf8')); } catch(e) { return {}; } }
function loadNewList() { try { const l = JSON.parse(require('fs').readFileSync(NEW_FILE,'utf8')); return Array.isArray(l)?l:[]; } catch(e) { return []; } }
function saveKnown(k) { require('fs').writeFileSync(KNOWN_FILE, JSON.stringify(k)); }
function saveNewList(l) { require('fs').writeFileSync(NEW_FILE, JSON.stringify(l, null, 2)); }

// Scan the DB for any domain not in the known baseline; add to new list
function detectNewDomains() {
  const known = loadKnown();
  const newList = loadNewList();
  const seen = new Set(newList.map(n => n.domain));
  const rows = db.prepare('SELECT root_domain, MIN(timestamp) as first_seen, COUNT(*) as visits FROM logs GROUP BY root_domain').all();
  let added = 0;
  for (const r of rows) {
    const d = r.root_domain;
    if (!d || !d.trim()) continue;
    if (known[d]) continue;              // already known
    if (seen.has(d)) continue;           // already flagged
    // Brand new
    const info = classify(d);
    newList.unshift({
      domain: d,
      firstSeen: r.first_seen,
      visits: r.visits,
      cat: info.cat, owner: info.owner, risk: info.risk, purpose: info.purpose,
      service: (typeof parentService === 'function' ? parentService(d) : null) || null,
      detectedAt: new Date().toISOString(),
      reviewed: false
    });
    known[d] = true;
    added++;
  }
  if (added > 0) { saveKnown(known); saveNewList(newList); console.log('New Sites: detected ' + added + ' new domain(s)'); }
  return added;
}

// List new (never-seen-before) domains
app.get('/api/newsites', (req, res) => {
  detectNewDomains(); // refresh on load
  const list = loadNewList();
  res.json({ count: list.length, unreviewed: list.filter(n=>!n.reviewed).length, domains: list });
});

// Mark all new sites as reviewed (clears the badge but keeps history)
app.post('/api/newsites/reviewed', (req, res) => {
  const list = loadNewList().map(n => ({ ...n, reviewed: true }));
  saveNewList(list);
  res.json({ success: true });
});

// Clear the new sites list entirely
app.delete('/api/newsites', (req, res) => {
  saveNewList([]);
  res.json({ success: true });
});


app.get('/api/insights/cooccurrence', (req, res) => { res.json({ pairs: coOccurrence(db, classify, {}) }); });
app.get('/api/insights/spikes', (req, res) => { res.json({ spikes: spikes(db, classify) }); });
app.get('/api/insights/overnight', (req, res) => { res.json(overnightDomains(db, classify)); });


app.get('/api/detectedapps', (req, res) => {
  res.json(detectedApps(db, classify, SERVICE_MAP, parentService, domainRole));
});


app.get('/api/meta-realtime', (req, res) => { res.json(metaRealtimeActivity(db)); });


// ---- AI chat over the logs (text-to-SQL, PIN-gated) ----
const { ask: chatAsk } = require('./chat');
const CHAT_PIN = '4269'; // change to your own PIN
app.post('/api/chat', async (req, res) => {
  try {
    const pin = (req.body && req.body.pin) || '';
    if (pin !== CHAT_PIN) return res.status(401).json({ error: 'Incorrect PIN.' });
    const question = (req.body && req.body.question) || '';
    if (!question.trim()) return res.status(400).json({ error: 'Ask a question.' });
    const result = await chatAsk(question);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: (e && e.message) || 'Chat failed.' });
  }
});

app.listen(PORT, () => console.log(`DNS Analyser running on port ${PORT}`));
