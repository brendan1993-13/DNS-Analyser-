// AI chat over the DNS logs, using text-to-SQL against a READ-ONLY db handle.
// Safety model: the LLM may only produce a single SELECT; everything else is
// rejected before it ever touches the database, and the db handle itself is
// opened read-only so writes are impossible at the driver level.

const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'dns.db');
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');

const SCHEMA_DESCRIPTION = `
Table: logs
Columns:
  id                   INTEGER  - row id
  timestamp            TEXT     - ISO8601 UTC, e.g. '2026-07-12T21:37:11.123Z'
  domain               TEXT     - full hostname queried, e.g. 'mqtt.c10r.facebook.com'
  root_domain          TEXT     - registrable apex, e.g. 'facebook.com'
  query_type           TEXT     - DNS record type, e.g. 'A','AAAA','HTTPS'
  protocol             TEXT     - e.g. 'DNS-over-HTTPS'
  client_ip            TEXT     - source IP of the device
  status               TEXT     - '' (allowed) or 'blocked'
  reasons              TEXT     - block reason if any
  destination_country  TEXT     - 2-letter country code, e.g. 'US'
  device_name          TEXT     - device label, e.g. 'Ben's phone'
  category             TEXT     - content category, e.g. 'Adult Content','Gambling','Finance / Banking','Social Networking','Apple Services','Messaging / Communication','Shopping / Retail','Entertainment / Streaming','Malicious / Threat','Infrastructure / CDN'
  service              TEXT     - parent app/service, e.g. 'Netflix','Facebook / Instagram','Apple','Google','Microsoft','Spotify','Temu' (NULL if not mapped to a known app)
  risk                 TEXT     - privacy risk: 'High','Medium','Low'
  owner                TEXT     - owning company, e.g. 'Meta Platforms Inc.'

Notes for querying:
  - To find a category (adult, gambling, finance, etc.), filter on the category column, e.g. WHERE category = 'Adult Content'.
  - To find an app/service (Netflix, Facebook, etc.), filter on the service column, e.g. WHERE service = 'Netflix'.
  - category/service/risk/owner are pre-computed on every row - prefer them over guessing from domain text.
  - Times are UTC. The user is in Australian Eastern time (UTC+10). To express
    local time, apply datetime(timestamp,'+10 hours').
  - "blocked" rows are those where status = 'blocked'.
  - Use root_domain for grouping by service/site; domain for specific hostnames.
  - There are hundreds of thousands of rows; always constrain or aggregate.
`.trim();

function loadKey() {
  const cfg = JSON.parse(require('fs').readFileSync(CONFIG_PATH, 'utf8'));
  return cfg.anthropicKey || '';
}

// ---- SQL guardrails -------------------------------------------------------
function sanitiseSql(raw) {
  if (!raw || typeof raw !== 'string') throw new Error('No SQL produced.');
  let sql = raw.trim();
  // strip markdown fences if the model added them
  sql = sql.replace(/^```sql\s*/i, '').replace(/^```\s*/, '').replace(/```$/,'').trim();
  // drop a single trailing semicolon
  sql = sql.replace(/;\s*$/, '').trim();
  const lower = sql.toLowerCase();
  // must be a single SELECT
  if (!lower.startsWith('select')) throw new Error('Only SELECT queries are allowed.');
  // no statement chaining
  if (sql.includes(';')) throw new Error('Multiple statements are not allowed.');
  // block any write / schema / pragma keywords as whole words
  const banned = /\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum|reindex|truncate)\b/i;
  if (banned.test(sql)) throw new Error('Query contains a disallowed keyword.');
  // enforce a row cap unless the query is a pure aggregate with no LIMIT
  if (!/\blimit\s+\d+/i.test(sql)) sql += ' LIMIT 1000';
  return sql;
}

async function callClaude(key, system, messages, maxTokens) {
  const resp = await axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001',
    max_tokens: maxTokens || 1024,
    system,
    messages
  }, {
    headers: {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    timeout: 30000
  });
  return resp.data.content.map(b => b.text || '').join('').trim();
}

async function ask(question) {
  const key = loadKey();
  if (!key) throw new Error('No Anthropic API key configured on the server.');
  if (!question || !question.trim()) throw new Error('Empty question.');

  // 1) ask the model for a SELECT
  const sqlSystem = `You are a SQLite expert. Given a question about DNS logs, respond with ONE SQLite SELECT query and nothing else - no explanation, no markdown. Use only the schema given.\n\n${SCHEMA_DESCRIPTION}`;
  const rawSql = await callClaude(key, sqlSystem, [{ role: 'user', content: question }], 512);
  const sql = sanitiseSql(rawSql);

  // 2) run it read-only
  const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
  let rows;
  try {
    rows = db.prepare(sql).all();
  } finally {
    db.close();
  }
  // cap rows handed back to the model to keep tokens/cost sane
  const capped = rows.slice(0, 200);

  // 3) ask the model to explain the results in plain English
  const explainSystem = 'You are a helpful analyst. Answer the user\'s question about their DNS data using the query results provided. Be concise and specific. Use Australian English. If the results are empty, say so plainly.';
  const explainUser = `Question: ${question}\n\nSQL used: ${sql}\n\nResults (JSON, up to 200 rows): ${JSON.stringify(capped)}`;
  const answer = await callClaude(key, explainSystem, [{ role: 'user', content: explainUser }], 1024);

  return { answer, sql, rowCount: rows.length };
}

module.exports = { ask };
