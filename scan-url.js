'use strict';
const fs = require('node:fs');

const url = process.argv[2];
const apiBase = (process.env.ARC_API_BASE || 'http://127.0.0.1:3000').replace(/\/$/, '');
if (!url) {
  console.error('Uso: node scan-url.js https://ejemplo.com');
  process.exit(2);
}
(async () => {
  const headers = {'content-type':'application/json'};
  if (process.env.ARC_API_KEY) headers['x-arc-key'] = process.env.ARC_API_KEY;
  const res = await fetch(apiBase + '/api/scan', {method:'POST', headers, body:JSON.stringify({url})});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  fs.writeFileSync('arc-report.json', JSON.stringify(data, null, 2));
  console.log(`ArcTool: ${data.totals.findings} hallazgos, score ${data.score}/100. Reporte: arc-report.json`);
})().catch(err => { console.error(err.stack || err.message); process.exit(1); });
