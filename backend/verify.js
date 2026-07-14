const fs = require('fs');
const path = require('path');
const https = require('https');

const CONFIG = path.join(__dirname, 'data', 'config.json');
const REPORT = path.join(__dirname, 'data', 'verify_report.json');
const OVERRIDES = path.join(__dirname, 'data', 'verified_overrides.json');
const CUSTOM = path.join(__dirname, 'data', 'classify_custom.json');
const FIXLOG = path.join(__dirname, 'data', 'autofix_log.json');

function getKey() {
  try { return JSON.parse(fs.readFileSync(CONFIG,'utf8')).vtKey || ''; }
  catch(e) { return ''; }
}
function loadJSON(f) { try { return JSON.parse(fs.readFileSync(f,'utf8')); } catch(e) { return {}; } }
function saveJSON(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }

function vtLookup(domain, key) {
  return new Promise((resolve) => {
    const req = https.get({
      hostname: 'www.virustotal.com',
      path: '/api/v3/domains/' + encodeURIComponent(domain),
      headers: { 'x-apikey': key }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const attr = (JSON.parse(data).data || {}).attributes || {};
          const stats = attr.last_analysis_stats || {};
          resolve({
            categories: Object.values(attr.categories || {}),
            malicious: stats.malicious || 0,
            reputation: attr.reputation || 0
          });
        } catch(e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(10000, () => { req.destroy(); resolve(null); });
  });
}

function mapVTtoOurs(vtCats) {
  const j = vtCats.join(' ').toLowerCase();
  if (j.includes('adult') || j.includes('porn') || j.includes('mature')) return 'Adult Content';
  if (j.includes('malicious') || j.includes('malware') || j.includes('phishing') || j.includes('spam')) return 'Malicious / Threat';
  if (j.includes('gambling')) return 'Gambling';
  if (j.includes('social')) return 'Social Networking';
  if (j.includes('finance') || j.includes('bank')) return 'Finance / Banking';
  if (j.includes('shopping') || j.includes('ecommerce') || j.includes('store')) return 'Shopping / Retail';
  if (j.includes('streaming') || j.includes('entertainment') || j.includes('audio') || j.includes('video')) return 'Entertainment / Streaming';
  if (j.includes('advertisement') || j.includes('marketing') || j.includes('ads')) return 'Advertising / Ad Tech';
  if (j.includes('news')) return 'News / Media';
  if (j.includes('health') || j.includes('medic')) return 'Health';
  if (j.includes('technology') || j.includes('computers') || j.includes('cdn') || j.includes('content server') || j.includes('infrastructure')) return 'Infrastructure / CDN';
  if (j.includes('business') || j.includes('cloud') || j.includes('productivity')) return 'Productivity / Cloud';
  if (j.includes('search')) return 'Search / Google';
  if (j.includes('travel')) return 'Travel / Logistics';
  if (j.includes('government')) return 'Government';
  if (j.includes('chat') || j.includes('messaging') || j.includes('email')) return 'Messaging / Communication';
  if (j.includes('job') || j.includes('employment')) return 'Work / Employment';
  if (j.includes('real estate')) return 'Real Estate';
  return null;
}

// The core auto-fix logic with guardrails
const SAFE_DOMAINS = new Set([
  'google.com','youtube.com','googleapis.com','gstatic.com','googleusercontent.com','googlevideo.com',
  'apple.com','apple-dns.net','aaplimg.com','icloud.com',
  'microsoft.com','office.com','outlook.com','azure.com','cloud.microsoft','windows.net',
  'facebook.com','fbcdn.net','instagram.com','whatsapp.com',
  'amazon.com','amazonaws.com','cloudfront.net',
  'akamai.net','akamaiedge.net','akadns.net','fastly.net','cloudflare.com'
]);

function decideAutoFix(domain, ours, vtMapped, vtMalicious, vtCats) {
  const CRITICAL = ['Malicious / Threat', 'Adult Content', 'Gambling'];
  // Guardrail: never auto-flag known first-party platform domains into a CRITICAL
  // category off a single VT signal - shared CDN/infra domains get abused by malware
  // campaigns, and UGC platforms often pick up spurious "adult" vendor tags. Leave
  // these as manual-review mismatches instead of auto-writing an override.
  if (SAFE_DOMAINS.has(domain)) {
    return { fix: false, reason: 'domain on SAFE_DOMAINS allowlist - manual review required' };
  }
  // Rule 1: VT flags malicious with multiple vendors -> always override
  if (vtMalicious >= 3 && ours.cat !== 'Malicious / Threat') {
    return { fix: true, newCat: 'Malicious / Threat', reason: `${vtMalicious} VirusTotal vendors flag as malicious`, force: true };
  }
  // Rule 2: VT says critical category (adult/gambling) and we missed it -> override
  if (vtMapped && CRITICAL.includes(vtMapped) && !CRITICAL.includes(ours.cat)) {
    return { fix: true, newCat: vtMapped, reason: `VirusTotal categorises as ${vtMapped}`, force: true };
  }
  // Rule 3: soft category disagreement -> only fix if OUR source was low-confidence
  if (vtMapped && vtMapped !== ours.cat) {
    const lowConfidence = ours.source === 'pattern' || ours.source === 'urlscan.io' || ours.source === 'unresolved' || ours.cat === 'Unknown';
    if (lowConfidence) {
      return { fix: true, newCat: vtMapped, reason: `Low-confidence (${ours.source||'unknown'}) corrected to VirusTotal category`, force: false };
    }
  }
  return { fix: false };
}

async function verifyAll(db, classify, opts) {
  opts = opts || {};
  const key = getKey();
  if (!key) return { error: 'No VirusTotal key configured' };
  const limit = opts.limit || 100;
  const autoFix = opts.autoFix !== false; // default ON

  const rows = db.prepare(
    'SELECT root_domain, COUNT(*) as visits, MAX(timestamp) as last_seen FROM logs GROUP BY root_domain ORDER BY last_seen DESC'
  ).all().filter(r => r.root_domain && r.root_domain.trim() && !r.root_domain.endsWith('.invalid'));

  const overrides = loadJSON(OVERRIDES);
  const fixLog = Array.isArray(loadJSON(FIXLOG)) ? loadJSON(FIXLOG) : [];
  const report = { checked:0, agreements:0, mismatches:[], malicious:[], autoFixed:[], unmapped:0, ran:new Date().toISOString(), inProgress:true, autoFix };
  saveJSON(REPORT, report);

  for (const r of rows.slice(0, limit)) {
    const ours = classify(r.root_domain);
    const vt = await vtLookup(r.root_domain, key);
    report.checked++;

    if (vt) {
      const vtMapped = mapVTtoOurs(vt.categories);
      if (vt.malicious >= 3 && ours.cat !== 'Malicious / Threat' && ours.cat !== 'Adult Content') {
        report.malicious.push({ domain:r.root_domain, ourCat:ours.cat, vtMalicious:vt.malicious, visits:r.visits });
      }
      if (vtMapped === ours.cat) {
        report.agreements++;
      } else if (vtMapped) {
        report.mismatches.push({ domain:r.root_domain, ours:ours.cat, virustotal:vtMapped, vtRaw:vt.categories.slice(0,3), visits:r.visits });
        if (autoFix) {
          const decision = decideAutoFix(r.root_domain, ours, vtMapped, vt.malicious, vt.categories);
          if (decision.fix) {
            overrides[r.root_domain] = {
              cat: decision.newCat,
              owner: ours.owner !== 'Unknown' ? ours.owner : 'Verified via VirusTotal',
              purpose: ours.purpose && ours.cat !== 'Unknown' ? ours.purpose : ('VirusTotal category: ' + vt.categories.slice(0,2).join(', ')),
              data: ours.data || 'See VirusTotal',
              risk: decision.newCat === 'Malicious / Threat' ? 'H' : decision.newCat === 'Adult Content' ? 'H' : ours.risk || 'M',
              bg: ours.bg !== undefined ? ours.bg : true,
              source: 'virustotal-verified',
              verifiedAt: new Date().toISOString()
            };
            fixLog.push({ domain:r.root_domain, from:ours.cat, to:decision.newCat, reason:decision.reason, force:decision.force, at:new Date().toISOString() });
            report.autoFixed.push({ domain:r.root_domain, from:ours.cat, to:decision.newCat, reason:decision.reason });
            saveJSON(OVERRIDES, overrides);
            saveJSON(FIXLOG, fixLog);
          }
        }
      } else report.unmapped++;
    }
    saveJSON(REPORT, report);
    await new Promise(res => setTimeout(res, 16000));
  }
  report.inProgress = false;
  saveJSON(REPORT, report);
  return report;
}

function loadReport() { try { return JSON.parse(fs.readFileSync(REPORT,'utf8')); } catch(e) { return null; } }
function loadOverrides() { return loadJSON(OVERRIDES); }
function loadFixLog() { const l = loadJSON(FIXLOG); return Array.isArray(l) ? l : []; }

module.exports = { verifyAll, loadReport, loadOverrides, loadFixLog };
