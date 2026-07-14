// AI chat over the DNS logs. Blends three sources:
//   1) your database (facts: category, service, counts, times, devices)
//   2) Claude's own general knowledge (what a site/app actually is)
//   3) urlscan.io fallback for domains Claude doesn't recognise
// Safety: any SQL the model writes is validated to a single read-only SELECT.

const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');
let researchDomain = null;
try { ({ researchDomain } = require('./auto_classify')); } catch (e) {}

const DB_PATH = path.join(__dirname, 'data', 'dns.db');
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');

const SCHEMA_DESCRIPTION = `
Table: logs
Columns:
  id                   INTEGER  - row id
  timestamp            TEXT     - ISO8601 UTC, e.g. '2026-07-12T21:37:11.123Z'
  domain               TEXT     - full hostname queried
  root_domain          TEXT     - registrable apex, e.g. 'facebook.com'
  query_type           TEXT     - DNS record type, e.g. 'A','AAAA','HTTPS'
  protocol             TEXT     - e.g. 'DNS-over-HTTPS'
  client_ip            TEXT     - source IP of the device
  status               TEXT     - '' (allowed) or 'blocked'
  reasons              TEXT     - block reason if any
  destination_country  TEXT     - 2-letter country code, e.g. 'US'
  device_name          TEXT     - device label
  category             TEXT     - content category, e.g. 'Adult Content','Gambling','Finance / Banking','Social Networking','Apple Services','Messaging / Communication','Shopping / Retail','Entertainment / Streaming','Malicious / Threat','Infrastructure / CDN'
  service              TEXT     - parent app/service, e.g. 'Netflix','Facebook / Instagram','Apple','Google' (NULL if unmapped)
  risk                 TEXT     - privacy risk: 'High','Medium','Low'
  owner                TEXT     - owning company

Notes for querying:
  - Times are UTC. User is Australian Eastern (UTC+10); use datetime(timestamp,'+10 hours') for local.
  - category/service/risk/owner are pre-computed; filter on them directly.
  - hundreds of thousands of rows; always constrain or aggregate.
`.trim();

function loadKey() {
  const cfg = JSON.parse(require('fs').readFileSync(CONFIG_PATH, 'utf8'));
  return cfg.anthropicKey || '';
}

function sanitiseSql(raw) {
  if (!raw || typeof raw !== 'string') throw new Error('No SQL produced.');
  let sql = raw.trim().replace(/^```sql\s*/i, '').replace(/^```\s*/, '').replace(/```$/, '').trim();
  sql = sql.replace(/;\s*$/, '').trim();
  if (!sql.toLowerCase().startsWith('select')) throw new Error('Only SELECT queries are allowed.');
  if (sql.includes(';')) throw new Error('Multiple statements are not allowed.');
  if (/\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum|reindex|truncate)\b/i.test(sql)) {
    throw new Error('Query contains a disallowed keyword.');
  }
  if (!/\blimit\s+\d+/i.test(sql)) sql += ' LIMIT 1000';
  return sql;
}

async function callClaude(key, system, messages, maxTokens) {
  const resp = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: maxTokens || 1024,
    system: system,
    messages: messages
  }, {
    headers: {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    timeout: 40000
  });
  return resp.data.content.map(function (b) { return b.text || ''; }).join('').trim();
}

function extractDomains(text) {
  const m = text.match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [];
  const uniq = [];
  m.forEach(function (d) {
    const low = d.toLowerCase();
    if (uniq.indexOf(low) === -1) uniq.push(low);
  });
  return uniq.slice(0, 3);
}

async function ask(question) {
  const key = loadKey();
  if (!key) throw new Error('No Anthropic API key configured on the server.');
  if (!question || !question.trim()) throw new Error('Empty question.');

  let sql = null;
  let rows = [];
  let sqlError = null;

  try {
    const sqlSystem = 'You are a SQLite expert. If the question needs data from the logs, respond with ONE SQLite SELECT query and nothing else. If the question is purely about what a site/app is (no data needed), respond with exactly NO_QUERY. Use only this schema:\n\n' + SCHEMA_DESCRIPTION;
    const rawSql = await callClaude(key, sqlSystem, [{ role: 'user', content: question }], 400);
    if (rawSql.trim().toUpperCase() !== 'NO_QUERY') {
      sql = sanitiseSql(rawSql);
      const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
      try {
        rows = db.prepare(sql).all();
      } finally {
        db.close();
      }
    }
  } catch (e) {
    sqlError = e.message;
  }

  const capped = rows.slice(0, 200);

  const research = [];
  if (researchDomain) {
    const domains = extractDomains(question);
    for (const d of domains) {
      try {
        const info = await researchDomain(d);
        if (info) {
          research.push({
            domain: d,
            purpose: info.purpose,
            owner: info.owner,
            category: info.cat,
            source: info.source
          });
        }
      } catch (e) {}
    }
  }

  const explainSystem = [
    "You are a helpful analyst answering questions about the user's DNS activity.",
    'You have THREE sources: (a) query results from their database, (b) your own general knowledge about what websites and apps are, (c) urlscan.io research on specific domains.',
    'Use all three. When you describe what a site or app IS, you may use your own knowledge - but make clear that description is general knowledge, while stats (visit counts, categories, times) come from their actual data.',
    'Be concise and specific. Use Australian English. If you are unsure what an obscure domain is, say so rather than guessing.'
  ].join(' ');

  const parts = ['Question: ' + question];
  if (sql) parts.push('\nSQL used: ' + sql);
  if (sqlError) parts.push('\n(No data query was run: ' + sqlError + ')');
  parts.push('\nDatabase results (JSON, up to 200 rows): ' + JSON.stringify(capped));
  if (research.length) parts.push('\nurlscan.io research on named domains: ' + JSON.stringify(research));

  const answer = await callClaude(key, explainSystem, [{ role: 'user', content: parts.join('\n') }], 1024);

  return {
    answer: answer,
    sql: sql || '(no query - answered from knowledge)',
    rowCount: rows.length
  };
}

module.exports = { ask: ask };
