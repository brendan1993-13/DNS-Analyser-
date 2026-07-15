// Classifies unknown domains using Claude, which actually knows what sites are -
// unlike urlscan, which only reports hosting metadata (every Cloudflare-fronted
// site was being mislabelled "Infrastructure / CDN").
//
// Usage:  node llm_classify.js            -> classify domains classify.js calls Unknown
//         node llm_classify.js --redo     -> also redo anything urlscan guessed
//         node llm_classify.js --limit 50 -> cap how many to do this run

const Database = require('better-sqlite3');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const classify = require('./classify.js');

const DB_PATH = path.join(__dirname, 'data', 'dns.db');
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');
const CUSTOM_PATH = path.join(__dirname, 'data', 'classify_custom.json');
const BATCH = 25;

const CATEGORIES = [
  'Advertising / Ad Tech', 'AI Services', 'Adult Content', 'Analytics / Monitoring',
  'Apple Services', 'Entertainment / Streaming', 'Finance / Banking', 'Food / Transport',
  'Gambling', 'Government', 'Health', 'Infrastructure / CDN', 'Malicious / Threat',
  'Media Delivery', 'Messaging / Communication', 'News / Media', 'Productivity / Cloud',
  'Real Estate', 'Shopping / Retail', 'Social Networking', 'Telecoms',
  'Travel / Logistics', 'Work / Employment', 'Unknown'
];

function loadCustom() {
  try { return JSON.parse(fs.readFileSync(CUSTOM_PATH, 'utf8')); } catch (e) { return {}; }
}
function saveCustom(d) {
  fs.writeFileSync(CUSTOM_PATH, JSON.stringify(d, null, 2));
}
function loadKey() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')).anthropicKey || '';
}

async function askClaude(key, domains) {
  const sys = 'You identify what internet domains are for. For each domain given, reply with what you actually know about it. ' +
    'Respond with ONLY a JSON array, no markdown, no prose. Each element: ' +
    '{"domain":"...","cat":"<one of the categories>","owner":"<company that owns it, or Unknown>","purpose":"<one short sentence on what it does>","risk":"H|M|L","bg":true|false}. ' +
    'cat MUST be exactly one of: ' + CATEGORIES.join(' | ') + '. ' +
    'risk: H = handles sensitive personal/financial data or heavy tracking, M = moderate tracking, L = benign. ' +
    'bg: true if it is background/automatic traffic (CDN, telemetry, push), false if it implies deliberate user action. ' +
    'If you genuinely do not recognise a domain, use cat "Unknown", owner "Unknown", and say so in purpose. Do not invent facts.';
  const user = 'Classify these domains:\n' + domains.join('\n');
  const resp = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 4000,
    system: sys,
    messages: [{ role: 'user', content: user }]
  }, {
    headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    timeout: 60000
  });
  let txt = resp.data.content.map(function (b) { return b.text || ''; }).join('').trim();
  txt = txt.replace(/^```json\s*/i, '').replace(/^```\s*/, '').replace(/```$/, '').trim();
  return JSON.parse(txt);
}

async function main() {
  const key = loadKey();
  if (!key) { console.error('No anthropicKey in config.json'); process.exit(1); }

  const redo = process.argv.indexOf('--redo') !== -1;
  const li = process.argv.indexOf('--limit');
  const limit = li !== -1 ? parseInt(process.argv[li + 1]) : 0;

  const db = new Database(DB_PATH, { readonly: true });
  const rows = db.prepare("SELECT root_domain, COUNT(*) n FROM logs WHERE root_domain IS NOT NULL AND root_domain != '' GROUP BY root_domain ORDER BY n DESC").all();
  db.close();

  const custom = loadCustom();
  let todo = rows.map(function (r) { return r.root_domain; }).filter(function (d) {
    const existing = custom[d];
    if (existing) {
      if (redo && (existing.source === 'urlscan.io' || existing.source === 'unresolved' || existing.cat === 'Unknown')) return true;
      return false;
    }
    return classify(d).cat === 'Unknown';
  });
  if (limit > 0) todo = todo.slice(0, limit);

  console.log('domains to classify:', todo.length);
  if (!todo.length) return;

  let done = 0, known = 0;
  for (let i = 0; i < todo.length; i += BATCH) {
    const batch = todo.slice(i, i + BATCH);
    try {
      const out = await askClaude(key, batch);
      out.forEach(function (r) {
        if (!r || !r.domain) return;
        const cat = CATEGORIES.indexOf(r.cat) !== -1 ? r.cat : 'Unknown';
        custom[r.domain] = {
          cat: cat,
          owner: r.owner || 'Unknown',
          purpose: (r.purpose || '').substring(0, 200),
          data: 'Identified by AI classifier',
          risk: ['H', 'M', 'L'].indexOf(r.risk) !== -1 ? r.risk : 'L',
          bg: !!r.bg,
          source: 'claude',
          researched: new Date().toISOString()
        };
        if (cat !== 'Unknown') known++;
        done++;
      });
      saveCustom(custom);
      console.log('  batch ' + (Math.floor(i / BATCH) + 1) + '/' + Math.ceil(todo.length / BATCH) + ' - ' + done + ' classified (' + known + ' identified)');
    } catch (e) {
      console.error('  batch failed:', e.message);
    }
    await new Promise(function (r) { setTimeout(r, 500); });
  }
  console.log('\nfinished. classified ' + done + ', of which ' + known + ' identified (rest genuinely unknown).');
}

main().catch(function (e) { console.error('FATAL', e.message); process.exit(1); });
