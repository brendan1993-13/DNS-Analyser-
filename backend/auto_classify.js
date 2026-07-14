const fs = require('fs');
const path = require('path');
const https = require('https');

const CUSTOM_FILE = path.join(__dirname, 'data', 'classify_custom.json');

function loadCustom() {
  try { return JSON.parse(fs.readFileSync(CUSTOM_FILE, 'utf8')); }
  catch(e) { return {}; }
}

function saveCustom(data) {
  fs.writeFileSync(CUSTOM_FILE, JSON.stringify(data, null, 2));
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'DNS-Analyser/1.0' } }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve(null); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function guessFromDomain(domain) {
  const d = domain.toLowerCase();
  if (d.endsWith('.invalid') || d.startsWith('this-url-does-not-exist'))
    return {cat:'Infrastructure / CDN',risk:'L',bg:true,purpose:'DNS probe test domain (mobile OS DNS hijack check)'};
  if (d.includes('analytics') || d.includes('metric') || d.includes('telemetry'))
    return {cat:'Analytics / Monitoring',risk:'M',bg:true,purpose:'Analytics or telemetry service'};
  if (d.includes('pixel') || d.includes('adserv') || d.includes('adtech') || d.includes('adnetwork'))
    return {cat:'Advertising / Ad Tech',risk:'M',bg:true,purpose:'Advertising or tracking domain'};
  if (d.includes('pay') || d.includes('bank') || d.includes('loan') || d.includes('credit') || d.includes('finance'))
    return {cat:'Finance / Banking',risk:'M',bg:false,purpose:'Financial services domain'};
  if (d.includes('shop') || d.includes('store') || d.includes('cart') || d.includes('product'))
    return {cat:'Shopping / Retail',risk:'L',bg:false,purpose:'Shopping or retail domain'};
  if (d.includes('chat') || d.includes('message') || d.includes('mail'))
    return {cat:'Messaging / Communication',risk:'L',bg:true,purpose:'Messaging or communication service'};
  if (d.includes('stream') || d.includes('video') || d.includes('music') || d.includes('audio'))
    return {cat:'Entertainment / Streaming',risk:'L',bg:false,purpose:'Media or streaming service'};
  if (d.includes('news') || d.includes('media') || d.includes('press'))
    return {cat:'News / Media',risk:'L',bg:false,purpose:'News or media domain'};
  if (d.includes('health') || d.includes('medical') || d.includes('pharma'))
    return {cat:'Health',risk:'M',bg:false,purpose:'Health or medical service'};
  if (d.includes('cdn') || d.includes('static') || d.includes('assets') || d.includes('cloud') || d.includes('host'))
    return {cat:'Infrastructure / CDN',risk:'L',bg:true,purpose:'Cloud, CDN, or hosting infrastructure'};
  return null;
}

async function researchDomain(domain) {
  const custom = loadCustom();
  if (custom[domain]) return custom[domain];

  let result = null;

  try {
    const data = await httpsGet('https://urlscan.io/api/v1/search/?q=domain:' + encodeURIComponent(domain) + '&size=1');
    if (data && data.results && data.results.length > 0) {
      const r = data.results[0];
      const title = (r.page && r.page.title) || '';
      const asn = (r.page && r.page.asnname) || '';
      const country = (r.page && r.page.country) || '';
      const combined = (title + ' ' + asn).toLowerCase();

      let cat = 'Unknown', risk = 'L', bg = true;
      if (combined.includes('adult') || combined.includes('porn')) { cat='Adult Content'; risk='H'; bg=false; }
      else if (combined.includes('malware') || combined.includes('phish')) { cat='Malicious / Threat'; risk='H'; bg=true; }
      else if (combined.includes('gambling') || combined.includes('casino') || combined.includes('bet')) { cat='Gambling'; risk='M'; bg=false; }
      else if (combined.includes('shop') || combined.includes('store') || combined.includes('commerce')) { cat='Shopping / Retail'; risk='L'; bg=false; }
      else if (combined.includes('bank') || combined.includes('finance') || combined.includes('payment')) { cat='Finance / Banking'; risk='M'; bg=false; }
      else if (combined.includes('news') || combined.includes('media')) { cat='News / Media'; risk='L'; bg=false; }
      else if (combined.includes('analytics') || combined.includes('tracking')) { cat='Analytics / Monitoring'; risk='M'; bg=true; }
      else if (combined.includes('advertis') || combined.includes('adtech')) { cat='Advertising / Ad Tech'; risk='M'; bg=true; }
      else if (combined.includes('cdn') || combined.includes('cloud') || combined.includes('hosting')) { cat='Infrastructure / CDN'; risk='L'; bg=true; }
      else if (combined.includes('social')) { cat='Social Networking'; risk='M'; bg=false; }

      let purpose = title || ('Hosted on ' + (asn || 'unknown network'));
      if (country === 'CN') purpose += ' (China-hosted)';

      result = {
        cat, owner: asn || 'Unknown',
        purpose: purpose.substring(0, 180),
        data: 'Auto-researched via urlscan.io',
        risk, bg,
        source: 'urlscan.io',
        researched: new Date().toISOString()
      };
    }
  } catch(e) {}

  if (!result || result.cat === 'Unknown') {
    const guess = guessFromDomain(domain);
    if (guess) {
      result = {
        cat: guess.cat, owner: 'Unknown',
        purpose: guess.purpose,
        data: 'Pattern-matched',
        risk: guess.risk, bg: guess.bg,
        source: 'pattern',
        researched: new Date().toISOString()
      };
    }
  }

  if (!result) {
    result = {
      cat: 'Unknown', owner: 'Unknown',
      purpose: domain + ' — could not be automatically classified',
      data: 'Unknown', risk: 'L', bg: true,
      source: 'unresolved',
      researched: new Date().toISOString()
    };
  }

  custom[domain] = result;
  saveCustom(custom);
  console.log('Classified ' + domain + ': ' + result.cat + ' (' + result.source + ')');
  return result;
}

async function researchAllUnknown(db, classify) {
  const rows = db.prepare('SELECT DISTINCT root_domain FROM logs').all();
  const custom = loadCustom();
  const unknown = rows.filter(r => {
    const rd = r.root_domain;
    if (!rd || !rd.trim()) return false;
    if (custom[rd]) return false;
    return classify(rd).cat === 'Unknown';
  });
  console.log('Researching ' + unknown.length + ' unknown domains...');
  for (const r of unknown) {
    try {
      await researchDomain(r.root_domain);
      await new Promise(res => setTimeout(res, 600));
    } catch(e) {}
  }
  return { researched: unknown.length };
}

module.exports = { researchDomain, researchAllUnknown, loadCustom };
