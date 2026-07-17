package dashboard

// indexHTML adalah halaman dashboard mandiri (tanpa file eksternal / CDN).
const indexHTML = `<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ExactusWAF - Dashboard</title>
<style>
  :root{--bg:#0f172a;--card:#1e293b;--card2:#243449;--muted:#94a3b8;--text:#e2e8f0;
        --accent:#38bdf8;--danger:#f87171;--ok:#4ade80;--warn:#fbbf24;--orange:#fb923c;--track:#334155}
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
  header{padding:18px 28px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #334155;
         position:sticky;top:0;background:var(--bg);z-index:5}
  header h1{font-size:20px;margin:0}
  .live{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px;margin-left:6px}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:pulse 1.6s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
  .badge{margin-left:auto;padding:4px 12px;border-radius:999px;font-size:13px;font-weight:600}
  .badge.block{background:rgba(74,222,128,.15);color:var(--ok)}
  .badge.monitor{background:rgba(251,191,36,.15);color:var(--warn)}
  main{padding:24px;max-width:1200px;margin:0 auto}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}
  .stat{background:var(--card);border-radius:14px;padding:18px}
  .stat .label{color:var(--muted);font-size:13px}
  .stat .value{font-size:30px;font-weight:700;margin-top:6px}
  .stat .value.danger{color:var(--danger)}
  .stat .value.ok{color:var(--ok)}
  .cols{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  @media(max-width:820px){.cols{grid-template-columns:1fr}}
  .panel{background:var(--card);border-radius:14px;padding:20px;margin-bottom:22px}
  .panel h2{font-size:14px;margin:0 0 14px;color:var(--text);font-weight:700;display:flex;
            align-items:center;gap:8px}
  .panel h2 .cnt{margin-left:auto;color:var(--muted);font-weight:500;font-size:12px}
  /* Bar list */
  .bars{display:flex;flex-direction:column;gap:10px;max-height:420px;overflow-y:auto}
  .bar-row{display:flex;flex-direction:column;gap:4px}
  .bar-top{display:flex;align-items:center;gap:8px;font-size:13px}
  .bar-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .bar-cve{font-family:monospace;font-size:11px;color:var(--accent)}
  .bar-count{margin-left:auto;font-weight:700;font-variant-numeric:tabular-nums}
  .bar-track{height:8px;background:var(--track);border-radius:999px;overflow:hidden}
  .bar-fill{height:100%;border-radius:999px;transition:width .5s ease}
  .f-critical{background:var(--danger)} .f-high{background:var(--orange)}
  .f-medium{background:var(--warn)} .f-low{background:var(--accent)} .f-ip{background:var(--accent)}
  .sev{padding:1px 7px;border-radius:6px;font-size:11px;font-weight:600}
  .sev.critical{background:rgba(248,113,113,.2);color:var(--danger)}
  .sev.high{background:rgba(251,146,60,.2);color:var(--orange)}
  .sev.medium{background:rgba(251,191,36,.2);color:var(--warn)}
  .sev.low{background:rgba(56,189,248,.2);color:var(--accent)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #334155}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase}
  td.mono{font-family:monospace;font-size:12px}
  .foot{color:var(--muted);font-size:12px;text-align:center;padding:16px}
  .empty{color:var(--muted);padding:24px;text-align:center;font-size:14px}
</style>
</head>
<body>
<header>
  <span style="font-size:24px">🛡️</span>
  <h1>ExactusWAF</h1>
  <span class="live"><span class="dot"></span>LIVE</span>
  <span id="modeBadge" class="badge">—</span>
</header>
<main>
  <div class="grid">
    <div class="stat"><div class="label">Total Permintaan</div><div id="total" class="value">0</div></div>
    <div class="stat"><div class="label">Serangan Diblokir</div><div id="blocked" class="value danger">0</div></div>
    <div class="stat"><div class="label">Permintaan Aman</div><div id="allowed" class="value ok">0</div></div>
    <div class="stat"><div class="label">Aturan Aktif</div><div id="rules" class="value">0</div></div>
    <div class="stat"><div class="label">Aktif Sejak</div><div id="uptime" class="value" style="font-size:20px">0s</div></div>
  </div>

  <div class="cols">
    <!-- ATURAN YANG TERPICU -->
    <div class="panel">
      <h2>🎯 Aturan yang Teraplikasi <span id="rulesCnt" class="cnt"></span></h2>
      <div id="rulesBars" class="bars"></div>
      <div id="rulesEmpty" class="empty">Belum ada aturan yang terpicu. 🎉</div>
    </div>
    <!-- TOTAL HIT PER IP -->
    <div class="panel">
      <h2>🌐 Total Hit per IP <span id="ipsCnt" class="cnt"></span></h2>
      <div id="ipsBars" class="bars"></div>
      <div id="ipsEmpty" class="empty">Belum ada IP tercatat.</div>
    </div>
  </div>

  <!-- SERANGAN TERBARU -->
  <div class="panel">
    <h2>📜 Serangan Terbaru</h2>
    <div style="overflow-x:auto">
    <table>
      <thead><tr><th>Waktu</th><th>IP</th><th>Metode</th><th>Path</th><th>Aturan</th><th>CVE</th><th>Tingkat</th><th>Aksi</th></tr></thead>
      <tbody id="events"></tbody>
    </table>
    </div>
    <div id="eventsEmpty" class="empty">Belum ada serangan terdeteksi. 🎉</div>
  </div>
</main>
<div class="foot">ExactusWAF &middot; Aturan versi <span id="rulesVer">-</span> &middot; Data diperbarui otomatis tiap 2 detik</div>

<script>
function fmtUptime(s){
  var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),sec=s%60;
  if(d>0)return d+"h "+h+"j"; if(h>0)return h+"j "+m+"m";
  if(m>0)return m+"m "+sec+"d"; return sec+"d";
}
function esc(t){var e=document.createElement('div');e.textContent=t==null?'':String(t);return e.innerHTML;}
function num(n){return (n||0).toLocaleString('id');}

function renderRules(rules){
  document.getElementById('rulesCnt').textContent=rules.length?rules.length+' jenis':'';
  document.getElementById('rulesEmpty').style.display=rules.length?'none':'block';
  var max=rules.length?rules[0].count:1;
  document.getElementById('rulesBars').innerHTML=rules.map(function(r){
    var pct=Math.max(4,Math.round(r.count/max*100));
    var sev=esc(r.severity||'low');
    var cve=r.cve?'<span class="bar-cve">'+esc(r.cve)+'</span>':'';
    return '<div class="bar-row"><div class="bar-top">'+
      '<span class="sev '+sev+'">'+sev+'</span>'+
      '<span class="bar-name" title="'+esc(r.rule_name)+'">'+esc(r.rule_name)+'</span>'+cve+
      '<span class="bar-count">'+num(r.count)+'</span></div>'+
      '<div class="bar-track"><div class="bar-fill f-'+sev+'" style="width:'+pct+'%"></div></div></div>';
  }).join('');
}
function renderIPs(ips){
  document.getElementById('ipsCnt').textContent=ips.length?ips.length+' IP':'';
  document.getElementById('ipsEmpty').style.display=ips.length?'none':'block';
  var max=ips.length?ips[0].count:1;
  document.getElementById('ipsBars').innerHTML=ips.map(function(x){
    var pct=Math.max(4,Math.round(x.count/max*100));
    return '<div class="bar-row"><div class="bar-top">'+
      '<span class="bar-name mono" style="font-family:monospace">'+esc(x.ip)+'</span>'+
      '<span class="bar-count">'+num(x.count)+' hit</span></div>'+
      '<div class="bar-track"><div class="bar-fill f-ip" style="width:'+pct+'%"></div></div></div>';
  }).join('');
}
function renderEvents(ev){
  document.getElementById('eventsEmpty').style.display=ev.length?'none':'block';
  document.getElementById('events').innerHTML=ev.map(function(e){
    var t=new Date(e.time).toLocaleTimeString('id');
    var sev=esc(e.severity||'low');
    return '<tr><td>'+t+'</td><td class="mono">'+esc(e.ip)+'</td><td>'+esc(e.method)+
      '</td><td class="mono">'+esc(e.path)+'</td><td>'+esc(e.rule_name)+
      '</td><td class="mono">'+esc(e.cve||'-')+'</td><td><span class="sev '+sev+'">'+sev+
      '</span></td><td>'+esc(e.action)+'</td></tr>';
  }).join('');
}

async function refresh(){
  try{
    var res=await fetch('/api/stats'); if(!res.ok)return;
    var d=await res.json();
    document.getElementById('total').textContent=num(d.total_requests);
    document.getElementById('blocked').textContent=num(d.total_blocked);
    document.getElementById('allowed').textContent=num(d.total_allowed);
    document.getElementById('rules').textContent=d.rules_count;
    document.getElementById('uptime').textContent=fmtUptime(d.uptime_seconds);
    document.getElementById('rulesVer').textContent=d.rules_updated||'-';
    var badge=document.getElementById('modeBadge');
    badge.textContent=d.mode==='block'?'Mode: BLOKIR':'Mode: MONITOR';
    badge.className='badge '+(d.mode==='block'?'block':'monitor');
    renderRules(d.rules||[]);
    renderIPs(d.top_ips||[]);
    renderEvents(d.recent||[]);
  }catch(err){/* diam saat gagal sesaat */}
}
refresh();
setInterval(refresh,2000);
</script>
</body>
</html>`
