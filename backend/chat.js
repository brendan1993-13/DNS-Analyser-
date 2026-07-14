// AI chat over the DNS logs. Blends three sources:
//   1) your database (facts: category, service, counts, times, devices)
//   2) Claude's own general knowledge (what a site/app actually is)
//   3) urlscan.io fallback for domains Claude doesn't recognise
// Supports multi-turn conversation via a history array.
// Safety: any SQL the model writes is validated to a single read-only SELECT.

const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');
let researchDomain = null;
try { ({ researchDomain } = require('./auto_classify')); } catch (e) {}

const DB_PATH = path.join(__dirname, 'data', 'dns.db');
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');
const MAX_TURNS = 10;

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
  const head = sql.toLowerCase();
  // allow plain SELECT and read-only CTEs (WITH ... SELECT); write keywords are
  // still blocked below, so a 'WITH ... DELETE' can never slip through.
  if (!head.startsWith('select') && !head.startsWith('with')) {
    throw new Error('Only SELECT (or WITH ... SELECT) queries are allowed.');
  }
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
  const m = (text || '').match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [];
  const uniq = [];
  m.forEach(function (d) {
    const low = d.toLowerCase();
    if (uniq.indexOf(low) === -1) uniq.push(low);
  });
  return uniq.slice(0, 3);
}

// history: [{role:'user'|'assistant', content:'...'}]
async function ask(question, history) {
  const key = loadKey();
  if (!key) throw new Error('No Anthropic API key configured on the server.');
  if (!question || !question.trim()) throw new Error('Empty question.');

  const hist = Array.isArray(history) ? history.slice(-MAX_TURNS * 2) : [];

  // look for domains in this question AND recent context, so follow-ups work
  const recentText = hist.map(function (m) { return m.content; }).join(' ') + ' ' + question;
  const named = extractDomains(question);
  const contextNamed = extractDomains(recentText);
  const mustQuery = named.length > 0 || contextNamed.length > 0;

  let sql = null;
  let rows = [];
  let sqlError = null;
  let queryRan = false;

  try {
    let sqlSystem = 'You are a SQLite expert helping with an ongoing conversation about DNS logs. Read the conversation so far, then respond to the latest question with ONE SQLite SELECT query and nothing else - no explanation, no markdown.';
    if (mustQuery) {
      sqlSystem += ' Relevant domain(s) in this conversation: ' + (named.length ? named : contextNamed).join(', ') + '. Write a query that looks up the data needed to answer the latest question.';
    } else {
      sqlSystem += ' IMPORTANT: almost every question about the user\'s own activity, usage, patterns, categories, services, devices or times DOES need data - write a query for those. Only reply NO_QUERY if the question is purely about what some external website/app is, with no reference to their own usage at all. If you reply NO_QUERY, reply with that word alone and nothing else.';
    }
    sqlSystem += ' Use only this schema:\n\n' + SCHEMA_DESCRIPTION;

    const sqlMessages = hist.concat([{ role: 'user', content: question }]);
    let rawSql = await callClaude(key, sqlSystem, sqlMessages, 400);

    if (!rawSql.trim().toUpperCase().startsWith('NO_QUERY')) {
      // try the query; if SQLite rejects it, hand the error back to the model
      // and let it correct itself (up to 2 retries).
      let lastErr = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const candidate = sanitiseSql(rawSql);
          const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
          try {
            rows = db.prepare(candidate).all();
            sql = candidate;
            queryRan = true;
            lastErr = null;
          } finally {
            db.close();
          }
          break;
        } catch (err) {
          lastErr = err;
          if (attempt === 2) break;
          if (!rawSql || !rawSql.trim()) break;
          const fixMsgs = sqlMessages.concat([
            { role: 'assistant', content: rawSql },
            { role: 'user', content: 'That query failed with this error:\n' + err.message + '\n\nRewrite it so it runs on SQLite. Note: SQLite GROUP_CONCAT does not accept DISTINCT together with a separator. Respond with the corrected SELECT query only, no explanation.' }
          ]);
          rawSql = await callClaude(key, sqlSystem, fixMsgs, 400);
        }
      }
      if (lastErr) throw lastErr;
    }
  } catch (e) {
    const api = e && e.response && e.response.data;
    sqlError = api ? (JSON.stringify(api).substring(0, 300)) : e.message;
    console.error('CHAT SQL STEP FAILED:', sqlError);
  }

  // Cap by SIZE as well as row count - a single row can be huge (e.g. a
  // GROUP_CONCAT of every domain), and an oversized prompt gets a 400 from the API.
  const MAX_JSON = 60000; // ~15k tokens of data
  let capped = rows.slice(0, 200);
  let dataJson = JSON.stringify(capped);
  while (dataJson.length > MAX_JSON && capped.length > 1) {
    capped = capped.slice(0, Math.max(1, Math.floor(capped.length / 2)));
    dataJson = JSON.stringify(capped);
  }
  if (dataJson.length > MAX_JSON) dataJson = dataJson.substring(0, MAX_JSON) + '...(truncated)';
  const dataNote = capped.length < rows.length ? ' (showing ' + capped.length + ' of ' + rows.length + ' rows - too large to include in full)' : '';

  const research = [];
  if (researchDomain) {
    for (const d of named) {
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
    "You are a helpful analyst in an ongoing conversation about the user's DNS activity.",
    'You have THREE sources: (a) query results from their database, (b) your own general knowledge about what websites and apps are, (c) urlscan.io research on specific domains.',
    'Use all three. When you describe what a site or app IS, you may use your own knowledge - but make clear that description is general knowledge, while stats come from their actual data.',
    'CRITICAL: only state that something is absent from their logs if a SQL query actually ran and returned zero rows. If no query ran, say you did not check rather than claiming there are no records.',
    'This is a conversation - refer back to earlier turns naturally and answer follow-ups in context.',
    'Be concise and specific. Use Australian English. If unsure what an obscure domain is, say so rather than guessing.'
  ].join(' ');

  const parts = ['Latest question: ' + question];
  if (sql) parts.push('\nSQL used: ' + sql);
  if (sqlError) parts.push('\n(SQL step failed, no data was checked: ' + sqlError + ')');
  if (queryRan) {
    parts.push('\nA query DID run. Database results' + dataNote + ': ' + dataJson);
    if (rows.length === 0) parts.push('\nThe query ran and genuinely returned zero rows - it is safe to say there is no matching activity.');
  } else {
    parts.push('\nNO query was run against their database - do NOT claim anything is absent from their logs.');
  }
  if (research.length) parts.push('\nurlscan.io research: ' + JSON.stringify(research));

  const explainMessages = hist.concat([{ role: 'user', content: parts.join('\n') }]);
  let answer;
  try {
    answer = await callClaude(key, explainSystem, explainMessages, 1024);
  } catch (e) {
    const api = e && e.response && e.response.data;
    const detail = api ? JSON.stringify(api).substring(0, 200) : e.message;
    console.error('CHAT EXPLAIN FAILED:', detail);
    throw new Error('Could not summarise that result (' + detail + '). Try narrowing the question.');
  }

  return {
    answer: answer,
    sql: sql || '(no query - answered from knowledge)',
    rowCount: rows.length
  };
}

function fetchRows(rawSql) {
  const sql = sanitiseSql(rawSql);
  const db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
  try { return db.prepare(sql).all(); } finally { db.close(); }
}

module.exports = { ask: ask, fetchRows: fetchRows, sanitiseSql: sanitiseSql };
