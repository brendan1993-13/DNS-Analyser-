// One-time migration: add category/risk/owner/service columns to logs and
// backfill them from the existing classifier + service map, so every row is
// searchable by category, risk, owner, and parent app/service.
const Database = require('better-sqlite3');
const path = require('path');
const classify = require('/root/projects/dns-analyser/backend/classify.js');
const { SERVICE_MAP, parentService } = require('/root/projects/dns-analyser/backend/services.js');

const DB = '/root/projects/dns-analyser/backend/data/dns.db';
const db = new Database(DB);

// 1) add columns if missing
const cols = db.prepare("PRAGMA table_info(logs)").all().map(c => c.name);
for (const col of ['category', 'risk', 'owner', 'service']) {
  if (!cols.includes(col)) {
    db.prepare(`ALTER TABLE logs ADD COLUMN ${col} TEXT`).run();
    console.log('added column:', col);
  } else {
    console.log('column already present:', col);
  }
}

// 2) classify each distinct grouping key once
const groupKey = classify.groupKey || ((d, r) => r);
const svcFn = parentService || ((d) => (SERVICE_MAP && SERVICE_MAP[d]) || null);
const distinct = db.prepare('SELECT DISTINCT domain, root_domain FROM logs').all();
console.log('distinct domain rows:', distinct.length);

const cache = {};
for (const { domain, root_domain } of distinct) {
  const gk = groupKey(domain, root_domain);
  if (!(gk in cache)) {
    const info = classify(gk || '');
    cache[gk] = {
      category: info.cat,
      risk: info.risk === 'H' ? 'High' : info.risk === 'M' ? 'Medium' : 'Low',
      owner: info.owner,
      service: svcFn(gk) || svcFn(root_domain) || null
    };
  }
}
console.log('unique classifications:', Object.keys(cache).length);

// 3) backfill by grouping key in one transaction
const splitList = Array.from(classify.SPLIT_DOMAINS || [])
  .map(d => "'" + d.replace(/'/g, "''") + "'").join(',') || "''";
const update = db.prepare(`
  UPDATE logs SET category=@category, risk=@risk, owner=@owner, service=@service
  WHERE (CASE WHEN domain IN (${splitList}) THEN domain ELSE root_domain END) = @gk
`);
const run = db.transaction(() => {
  let n = 0;
  for (const gk in cache) { update.run({ ...cache[gk], gk }); if (++n % 200 === 0) process.stdout.write('.'); }
});
console.log('backfilling...');
run();
console.log('\nbackfill complete');

// 4) helpful indexes for fast searching
for (const col of ['category', 'service', 'risk', 'device_name', 'destination_country', 'status']) {
  try { db.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_${col} ON logs(${col})`).run(); } catch (e) {}
}
console.log('indexes ensured');

// 5) sanity report
console.log('\ntop categories:');
db.prepare("SELECT category, COUNT(*) n FROM logs GROUP BY category ORDER BY n DESC LIMIT 8")
  .all().forEach(r => console.log('  ', r.category, r.n));
console.log('top services:');
db.prepare("SELECT service, COUNT(*) n FROM logs WHERE service IS NOT NULL GROUP BY service ORDER BY n DESC LIMIT 8")
  .all().forEach(r => console.log('  ', r.service, r.n));
console.log('rows with no category:', db.prepare("SELECT COUNT(*) n FROM logs WHERE category IS NULL").get().n);

db.close();
