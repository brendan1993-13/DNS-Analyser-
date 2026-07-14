// Maps individual domains to their parent service, so fragmented
// CDN/gateway/API domains consolidate into one recognisable app.
const SERVICE_MAP = {
  // Snapchat
  'snapchat.com':'Snapchat','sc-gw.com':'Snapchat','sc-static.net':'Snapchat','snapkit.com':'Snapchat','sc-cdn.net':'Snapchat',
  // Meta / Facebook / Instagram
  'facebook.com':'Facebook / Instagram','fbcdn.net':'Facebook / Instagram','cdninstagram.com':'Facebook / Instagram','instagram.com':'Facebook / Instagram','fb.com':'Facebook / Instagram','facebook.net':'Facebook / Instagram','fbsbx.com':'Facebook / Instagram','whatsapp.com':'Facebook / Instagram','whatsapp.net':'Facebook / Instagram','graph.facebook.com':'Facebook / Instagram','graph-video.facebook.com':'Facebook / Instagram','rupload.facebook.com':'Facebook / Instagram','mqtt.c10r.facebook.com':'Facebook / Instagram','edge-mqtt.facebook.com':'Facebook / Instagram','chat-e2ee.facebook.com':'Facebook / Instagram','chat-e2ee.c10r.facebook.com':'Facebook / Instagram',
  // Apple
  'apple.com':'Apple','apple-dns.net':'Apple','aaplimg.com':'Apple','icloud.com':'Apple','mzstatic.com':'Apple','cdn-apple.com':'Apple','icloud-content.com':'Apple','apple.news':'Apple','me.com':'Apple','itunes.com':'Apple','apple.map.fastly.net':'Apple',
  // Google
  'google.com':'Google','google.com.au':'Google','gstatic.com':'Google','googleapis.com':'Google','doubleclick.net':'Google','googlevideo.com':'Google','ytimg.com':'Google','youtube.com':'Google','ggpht.com':'Google','googleusercontent.com':'Google','google-analytics.com':'Google','googlecommerce.com':'Google','googlesyndication.com':'Google','googletagmanager.com':'Google','gmail.com':'Google','firebaselogging-pa.googleapis.com':'Google',
  // Microsoft
  'microsoft.com':'Microsoft','office.com':'Microsoft','outlook.com':'Microsoft','live.com':'Microsoft','hotmail.com':'Microsoft','microsoftonline.com':'Microsoft','msidentity.com':'Microsoft','msauth.net':'Microsoft','azure.com':'Microsoft','cloud.microsoft':'Microsoft','appcenter.ms':'Microsoft','skype.com':'Microsoft','sfx.ms':'Microsoft','windows.com':'Microsoft','bing.com':'Microsoft','licdn.com':'Microsoft','copilot.com':'Microsoft',
  // Spotify
  'spotify.com':'Spotify','scdn.co':'Spotify','spotifycdn.com':'Spotify','byspotify.com':'Spotify',
  // Netflix
  'netflix.com':'Netflix','nflxvideo.net':'Netflix','nflxso.net':'Netflix','nflximg.net':'Netflix',
  // Amazon
  'amazon.com':'Amazon','amazon.com.au':'Amazon','amazonaws.com':'Amazon','media-amazon.com':'Amazon','ssl-images-amazon.com':'Amazon','amazon.co.jp':'Amazon','audible.com.au':'Amazon',
  // TikTok
  'tiktok.com':'TikTok','tiktokcdn.com':'TikTok','byteoversea.com':'TikTok','tiktokv.com':'TikTok',
  // Disney
  'go.com':'Disney','bamgrid.com':'Disney','dssott.com':'Disney','disney-plus.net':'Disney','disneyplus.com':'Disney',
  // Yoto
  'yotoplay.com':'Yoto','yoto-au.netlify.app':'Yoto','yoto-australia.myshopify.com':'Yoto',
  // Tuya smart home
  'tuya.com':'Tuya Smart Home','tuyaeu.com':'Tuya Smart Home','tuyaus.com':'Tuya Smart Home',
  // Temu
  'temu.com':'Temu','kwcdn.com':'Temu',
  // NAB banking
  'nab.com.au':'NAB',
  // Uber
  'uber.com':'Uber','uber-assets.com':'Uber','uberinternal.com':'Uber',
  // eBay
  'ebay.com':'eBay','ebayimg.com':'eBay','ebaystatic.com':'eBay',
  // AliExpress / Alibaba
  'paypal.com':'PayPal','paypalobjects.com':'PayPal',
  'aliexpress.com':'AliExpress','alicdn.com':'AliExpress','aliyuncs.com':'AliExpress','taobao.com':'AliExpress','alibaba.com':'AliExpress','alibabausercontent.com':'AliExpress','alipay.com':'AliExpress','aliapp.org':'AliExpress'
};

function parentService(domain) {
  return SERVICE_MAP[domain] || null;
}

module.exports = { SERVICE_MAP, parentService };

// Classify a full subdomain's ROLE from its name — powers the human-vs-background verdict.
function domainRole(fullDomain) {
  const d = (fullDomain || '').toLowerCase();
  // Telemetry / tracking — idle apps emit these
  if (/^(tr|track|telemetry|metrics|analytics|log|logs|beacon|pixel|stats|events?)\./.test(d) || d.includes('crashlytics') || d.includes('-tr.') || d.includes('.tr.')) return 'telemetry';
  // Auth / login / token / API — background token refresh
  if (/^(api|auth|login|token|oauth|id|identity|account|gateway|gw)\./.test(d) || d.includes('snapkit') || d.includes('.api.') || d.includes('sc-gw')) return 'auth';
  // Content / media / CDN — actual usage loading things
  if (/^(cdn|static|media|img|images|video|videos|content|assets|thumb|stream|dl|download)\./.test(d) || d.includes('cdn') || d.includes('static') || d.includes('-media') || d.includes('.media.') || d.includes('scontent') || d.includes('fbcdn') || d.includes('cdninstagram') || d.includes('nflxvideo') || d.includes('googlevideo') || d.includes('ytimg')) return 'content';
  // Push notifications
  if (/^(push|gcm|fcm|notify|notification|mtalk)\./.test(d)) return 'push';
  // Default: treat bare/app domains as general app traffic
  return 'app';
}

// Compute a human-usage verdict for a set of log rows (each: {domain, timestamp}).
// Time-of-day is intentionally NOT used as a strong signal (sporadic waking hours).
function computeVerdict(rows) {
  if (!rows.length) return { verdict: 'No activity', tier: 'none', score: 0, signals: {} };

  const roles = { content:0, auth:0, telemetry:0, push:0, app:0 };
  rows.forEach(r => { roles[domainRole(r.domain)]++; });
  const total = rows.length;

  // Session clustering (15-min gap)
  const GAP = 15*60*1000;
  const times = rows.map(r => new Date(r.timestamp).getTime()).filter(t=>!isNaN(t)).sort((a,b)=>a-b);
  const sessions = [];
  let start = times[0], last = times[0], count = 1;
  for (let i=1;i<times.length;i++){
    if (times[i]-last > GAP){ sessions.push({count}); start=times[i]; count=1; }
    else count++;
    last = times[i];
  }
  sessions.push({count});
  const avgBurst = sessions.reduce((a,s)=>a+s.count,0)/sessions.length;
  const singleLookupSessions = sessions.filter(s=>s.count<=2).length / sessions.length;

  // Interval regularity: coefficient of variation of gaps (low = machine-regular)
  const gaps = [];
  for (let i=1;i<times.length;i++) gaps.push(times[i]-times[i-1]);
  let regularity = 0;
  if (gaps.length > 3) {
    const mean = gaps.reduce((a,g)=>a+g,0)/gaps.length;
    const variance = gaps.reduce((a,g)=>a+(g-mean)*(g-mean),0)/gaps.length;
    const cv = mean > 0 ? Math.sqrt(variance)/mean : 0;
    regularity = cv; // higher = more irregular = more human
  }

  const contentRatio = roles.content / total;
  const authTelemetryRatio = (roles.auth + roles.telemetry) / total;

  // SCORE 0-100 (higher = more human). Content ratio dominates.
  let score = 0;
  score += contentRatio * 45;                          // up to 45: real content loading
  score += Math.min(avgBurst/20, 1) * 25;              // up to 25: dense bursts
  score += Math.min(regularity/2, 1) * 15;             // up to 15: irregular timing
  score += (1 - singleLookupSessions) * 10;            // up to 10: multi-lookup sessions
  score += (1 - authTelemetryRatio) * 5;               // up to 5: not pure auth/telemetry
  score = Math.round(score);

  // Override: near-zero content + dominant auth/telemetry = background (automated refresh)
  if (contentRatio < 0.05 && authTelemetryRatio > 0.7) {
    score = Math.min(score, 20);
  }
  // Override: near-zero content caps at "Light use" — high burst alone (e.g. background
  // sync hammering APIs) is NOT proof of human use without content loading.
  else if (contentRatio < 0.05) {
    score = Math.min(score, 45);
  }
  // Override: heavy content with dense sessions is definitely active
  if (contentRatio > 0.25 && avgBurst > 15) {
    score = Math.max(score, 60);
  }

  let tier, verdict;
  if (score >= 55) { tier='active'; verdict='Actively used'; }
  else if (score >= 25) { tier='light'; verdict='Light use'; }
  else { tier='background'; verdict='Background only'; }

  return {
    verdict, tier, score,
    signals: {
      totalLookups: total,
      contentPct: Math.round(contentRatio*100),
      authTelemetryPct: Math.round(authTelemetryRatio*100),
      avgLookupsPerSession: Math.round(avgBurst*10)/10,
      sessions: sessions.length,
      singleLookupSessionPct: Math.round(singleLookupSessions*100),
      roles
    }
  };
}

module.exports.domainRole = domainRole;
module.exports.computeVerdict = computeVerdict;
