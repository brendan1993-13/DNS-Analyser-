const classify = require('/root/projects/dns-analyser/backend/classify.js');
const Database = require('better-sqlite3');
const db = new Database('/root/projects/dns-analyser/backend/data/dns.db');
const rows = db.prepare('SELECT root_domain, COUNT(*) as visits FROM logs GROUP BY root_domain ORDER BY visits DESC').all();

const flags = [];
rows.forEach(r => {
  const d = r.root_domain;
  if (!d) return;
  const info = classify(d);
  if (info.source === 'pattern') flags.push([d, info.cat, 'pattern-guessed', r.visits]);
  else if (info.source === 'urlscan.io') flags.push([d, info.cat, 'auto-researched', r.visits]);
  else if (info.owner === 'Unknown' && info.cat !== 'Unknown') flags.push([d, info.cat, 'owner-unknown', r.visits]);
  else if (info.cat === 'Unknown' && r.visits > 5) flags.push([d, info.cat, 'high-traffic-unknown', r.visits]);
});
flags.sort((a,b)=>b[3]-a[3]);
console.log('Domains to review (' + flags.length + '):');
flags.slice(0,50).forEach(f => console.log(String(f[3]).padStart(6), f[0].padEnd(42), f[1].padEnd(24), '['+f[2]+']'));
