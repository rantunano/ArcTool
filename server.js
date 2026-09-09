'use strict';

const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { chromium } = require('playwright');
const axe = require('axe-core');



function isPrivateIp(ip) {
  if (!net.isIP(ip)) return false;
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true;
  if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127);
  }
  return false;
}

async function assertSafePublicUrl(rawUrl, dnsCache = new Map()) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { throw new Error('URL inválida'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Sólo se permiten URLs http/https');
  if (parsed.username || parsed.password) throw new Error('No se permiten credenciales embebidas en la URL');
  const hostname = parsed.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.local')) throw new Error('No se permiten hosts locales');
  if (net.isIP(hostname) && isPrivateIp(hostname)) throw new Error('No se permiten direcciones de red privadas');
  if (!net.isIP(hostname)) {
    let ips = dnsCache.get(hostname);
    if (!ips) {
      ips = (await dns.lookup(hostname, { all: true, verbatim: true })).map(x => x.address);
      dnsCache.set(hostname, ips);
    }
    if (!ips.length || ips.some(isPrivateIp)) throw new Error('El host resuelve a una dirección privada o no válida');
  }
  return parsed.toString();
}



const SEVERITY_ORDER = { critical: 0, serious: 1, moderate: 2, minor: 3, info: 4 };
const SEVERITY_WEIGHT = { critical: 25, serious: 12, moderate: 5, minor: 2, info: 0 };

function normalizeSeverity(value) {
  const v = String(value || '').toLowerCase();
  if (v === 'critical' || v === 'serious' || v === 'moderate' || v === 'minor') return v;
  if (v === 'major') return 'serious';
  return 'minor';
}

function scoreFromFindings(findings) {
  const counts = { critical: 0, serious: 0, moderate: 0, minor: 0, info: 0 };
  for (const finding of findings || []) {
    const severity = normalizeSeverity(finding.severity || finding.impact);
    counts[severity] += 1;
  }
  const penalty = Object.entries(counts).reduce((sum, [severity, count]) => sum + (SEVERITY_WEIGHT[severity] || 0) * count, 0);
  return { score: Math.max(0, Math.round(100 - Math.min(100, penalty))), counts };
}

function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) => {
    const sa = SEVERITY_ORDER[normalizeSeverity(a.severity || a.impact)];
    const sb = SEVERITY_ORDER[normalizeSeverity(b.severity || b.impact)];
    if (sa !== sb) return sa - sb;
    const fa = String(a.frameUrl || '');
    const fb = String(b.frameUrl || '');
    if (fa !== fb) return fa.localeCompare(fb);
    return String(a.ruleId || a.title || '').localeCompare(String(b.ruleId || b.title || ''));
  });
}

function summarizeByRule(findings) {
  const map = new Map();
  for (const f of findings || []) {
    const key = f.ruleId || f.id || f.title || 'unknown';
    const item = map.get(key) || {
      ruleId: key,
      title: f.title || key,
      severity: normalizeSeverity(f.severity || f.impact),
      wcag: f.wcag || [],
      count: 0
    };
    item.count += 1;
    if (SEVERITY_ORDER[normalizeSeverity(f.severity || f.impact)] < SEVERITY_ORDER[item.severity]) {
      item.severity = normalizeSeverity(f.severity || f.impact);
    }
    map.set(key, item);
  }
  return [...map.values()].sort((a, b) => {
    const d = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    return d || b.count - a.count;
  });
}

function buildReport({ url, startedAt, durationMs, frames, findings, inventory, warnings }) {
  const sorted = sortFindings(findings);
  const { score, counts } = scoreFromFindings(sorted);
  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    url,
    startedAt,
    durationMs,
    score,
    severityCounts: counts,
    summaryByRule: summarizeByRule(sorted),
    totals: {
      frames: frames.length,
      elementsScanned: frames.reduce((sum, f) => sum + (f.elementCount || 0), 0),
      findings: sorted.length,
      inventoryItems: inventory.length
    },
    frames,
    inventory,
    findings: sorted,
    warnings: warnings || [],
    disclaimer: 'Automated accessibility testing can identify many WCAG issues but cannot certify complete conformance. Manual keyboard, screen-reader and usability testing remains necessary.'
  };
}




const DEFAULTS = {
  navigationTimeoutMs: 20000,
  scanTimeoutMs: 45000,
  settleMs: 1200,
  maxFrames: 30,
  maxFindings: 5000,
  maxInventoryItems: 5000,
  viewport: { width: 1440, height: 1000 }
};

function tagsToWcag(tags) {
  return (tags || []).filter(t => /^wcag\d/.test(t) || /^best-practice$/.test(t));
}

function truncate(value, max = 900) {
  const s = String(value || '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

async function elementMetadata(frame, target) {
  try {
    return await frame.evaluate((selector) => {
      function accessibleName(el) {
        return (el.getAttribute('aria-label') || el.getAttribute('alt') || el.getAttribute('title') || el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 300);
      }
      let el = null;
      try { el = document.querySelector(selector); } catch (_) {}
      if (!el) return null;
      const cs = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      return {
        tag: el.tagName.toLowerCase(),
        id: el.id || null,
        role: el.getAttribute('role') || null,
        accessibleName: accessibleName(el),
        text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 500),
        ariaLabel: el.getAttribute('aria-label'),
        alt: el.getAttribute('alt'),
        title: el.getAttribute('title'),
        href: el.getAttribute('href'),
        type: el.getAttribute('type'),
        tabIndex: el.tabIndex,
        display: cs.display,
        visibility: cs.visibility,
        color: cs.color,
        backgroundColor: cs.backgroundColor,
        fontSize: cs.fontSize,
        fontWeight: cs.fontWeight,
        rect: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }
      };
    }, target);
  } catch {
    return null;
  }
}

async function runAxeInFrame(frame, frameIndex) {
  await frame.evaluate(axe.source);
  const result = await frame.evaluate(async () => {
    return await axe.run(document, {
      resultTypes: ['violations'],
      rules: { region: { enabled: true } }
    });
  });
  const findings = [];
  for (const violation of result.violations || []) {
    for (let nodeIndex = 0; nodeIndex < violation.nodes.length; nodeIndex += 1) {
      const node = violation.nodes[nodeIndex];
      const target = Array.isArray(node.target) ? node.target.join(' ') : String(node.target || '');
      findings.push({
        source: 'axe-core',
        frameIndex,
        frameUrl: frame.url(),
        ruleId: violation.id,
        title: violation.help,
        description: violation.description,
        severity: normalizeSeverity(violation.impact),
        wcag: tagsToWcag(violation.tags),
        helpUrl: violation.helpUrl,
        target,
        html: truncate(node.html, 1200),
        failureSummary: truncate(node.failureSummary, 1500),
        nodeIndex
      });
    }
  }
  return findings;
}

async function collectInventory(frame, frameIndex, maxItems) {
  return await frame.evaluate(({ frameIndex, maxItems }) => {
    const selectors = 'a,button,input,select,textarea,img,iframe,video,audio,h1,h2,h3,h4,h5,h6,p,li,span,small,strong,em,td,th,caption,legend,[role],[tabindex],form,label,nav,main,header,footer,aside,section';
    const nodes = [...document.querySelectorAll(selectors)].slice(0, maxItems);
    const items = nodes.map((el, index) => {
      const r = el.getBoundingClientRect();
      const text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 240);
      return {
        frameIndex,
        index,
        tag: el.tagName.toLowerCase(),
        id: el.id || null,
        role: el.getAttribute('role'),
        text,
        ariaLabel: el.getAttribute('aria-label'),
        alt: el.getAttribute('alt'),
        title: el.getAttribute('title'),
        href: el.getAttribute('href'),
        type: el.getAttribute('type'),
        tabIndex: el.tabIndex,
        rect: { width: Math.round(r.width), height: Math.round(r.height) }
      };
    });
    return { elementCount: document.querySelectorAll('*').length, items };
  }, { frameIndex, maxItems });
}

async function runCustomChecks(frame, frameIndex) {
  return await frame.evaluate(({ frameIndex }) => {
    const findings = [];
    const push = (f) => findings.push({ source: 'ArcTool', frameIndex, frameUrl: location.href, ...f });
    const cssPath = (el) => {
      if (!el) return '';
      if (el.id) return `#${CSS.escape(el.id)}`;
      const parts = [];
      let cur = el;
      while (cur && cur.nodeType === 1 && parts.length < 5) {
        let part = cur.tagName.toLowerCase();
        const siblings = cur.parentElement ? [...cur.parentElement.children].filter(x => x.tagName === cur.tagName) : [];
        if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(cur) + 1})`;
        parts.unshift(part);
        cur = cur.parentElement;
      }
      return parts.join(' > ');
    };
    const nameOf = el => (el.getAttribute('aria-label') || el.getAttribute('title') || el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();

    document.querySelectorAll('iframe').forEach((el) => {
      if (!el.getAttribute('title')?.trim()) push({ ruleId: 'iframe-title-custom', title: 'iframe sin título descriptivo', severity: 'serious', wcag: ['wcag412'], target: cssPath(el), failureSummary: 'Agrega un atributo title que describa el propósito del frame.' });
    });

    document.querySelectorAll('button,[role="button"]').forEach((el) => {
      if (!nameOf(el)) push({ ruleId: 'control-name-custom', title: 'Control sin nombre accesible', severity: 'critical', wcag: ['wcag412'], target: cssPath(el), failureSummary: 'El control no expone texto, aria-label ni title utilizable.' });
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24)) push({ ruleId: 'target-size-custom', title: 'Objetivo táctil muy pequeño', severity: 'moderate', wcag: ['wcag258'], target: cssPath(el), failureSummary: `Tamaño aproximado ${Math.round(r.width)}×${Math.round(r.height)} px; revisa WCAG 2.5.8.` });
    });

    document.querySelectorAll('a[href]').forEach((el) => {
      if (!nameOf(el) && !el.querySelector('img[alt]')) push({ ruleId: 'link-name-custom', title: 'Enlace sin nombre accesible', severity: 'critical', wcag: ['wcag244', 'wcag412'], target: cssPath(el), failureSummary: 'El enlace no tiene texto ni alternativa accesible.' });
    });

    const headings = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')];
    for (let i = 1; i < headings.length; i += 1) {
      const prev = Number(headings[i - 1].tagName.slice(1));
      const curr = Number(headings[i].tagName.slice(1));
      if (curr - prev > 1) push({ ruleId: 'heading-jump-custom', title: 'Salto en jerarquía de encabezados', severity: 'moderate', wcag: ['wcag131'], target: cssPath(headings[i]), failureSummary: `La jerarquía salta de H${prev} a H${curr}.` });
    }

    document.querySelectorAll('[onclick]:not(a):not(button):not(input):not(select):not(textarea)').forEach((el) => {
      const role = el.getAttribute('role');
      if (!role || (el.tabIndex < 0 && role !== 'presentation')) push({ ruleId: 'clickable-semantic-custom', title: 'Elemento clicable sin semántica/teclado evidente', severity: 'serious', wcag: ['wcag211', 'wcag412'], target: cssPath(el), failureSummary: 'Un elemento con onclick puede no ser alcanzable o entendible mediante teclado/lector de pantalla.' });
    });

    document.querySelectorAll('video,audio').forEach((el) => {
      if (el.autoplay && !el.muted) push({ ruleId: 'autoplay-media-custom', title: 'Multimedia con reproducción automática', severity: 'serious', wcag: ['wcag142'], target: cssPath(el), failureSummary: 'Revisa controles para pausar/detener audio que inicia automáticamente.' });
    });

    return findings;
  }, { frameIndex });
}

async function scanPage(rawUrl, options = {}) {
  const cfg = { ...DEFAULTS, ...options };
  const startedAt = new Date().toISOString();
  const start = Date.now();
  const dnsCache = new Map();
  const url = await assertSafePublicUrl(rawUrl, dnsCache);
  let browser;
  const warnings = [];

  const task = (async () => {
    try {
      browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage', '--no-sandbox'] });
      const context = await browser.newContext({ viewport: cfg.viewport, reducedMotion: 'reduce' });
      await context.route('**/*', async route => {
        try {
          const requestUrl = route.request().url();
          if (requestUrl.startsWith('data:') || requestUrl.startsWith('blob:')) return route.continue();
          await assertSafePublicUrl(requestUrl, dnsCache);
          return route.continue();
        } catch {
          return route.abort('blockedbyclient');
        }
      });
      const page = await context.newPage();
      page.setDefaultTimeout(8000);
      page.setDefaultNavigationTimeout(cfg.navigationTimeoutMs);
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: cfg.navigationTimeoutMs });
      await page.waitForTimeout(cfg.settleMs);

      const allFrames = page.frames();
      if (allFrames.length > cfg.maxFrames) warnings.push(`Se detectaron ${allFrames.length} frames; sólo se analizaron los primeros ${cfg.maxFrames}.`);
      const framesToScan = allFrames.slice(0, cfg.maxFrames);
      const frames = [];
      const findings = [];
      const inventory = [];

      for (let i = 0; i < framesToScan.length; i += 1) {
        const frame = framesToScan[i];
        if (!frame.url() || frame.url() === 'about:blank') continue;
        const frameEntry = { index: i, url: frame.url(), name: frame.name() || null, elementCount: 0, status: 'ok' };
        try {
          const inv = await collectInventory(frame, i, Math.max(0, cfg.maxInventoryItems - inventory.length));
          frameEntry.elementCount = inv.elementCount;
          inventory.push(...inv.items);
          const axeFindings = await runAxeInFrame(frame, i);
          const customFindings = await runCustomChecks(frame, i);
          findings.push(...axeFindings, ...customFindings);
        } catch (error) {
          frameEntry.status = 'partial';
          frameEntry.error = truncate(error.message, 500);
          warnings.push(`Frame ${i} no pudo analizarse completamente: ${frameEntry.error}`);
        }
        frames.push(frameEntry);
        if (findings.length >= cfg.maxFindings) {
          warnings.push(`Se alcanzó el límite de ${cfg.maxFindings} hallazgos; el reporte fue truncado.`);
          findings.length = cfg.maxFindings;
          break;
        }
      }

      for (const finding of findings) {
        if (finding.target) finding.element = await elementMetadata(page.frames()[finding.frameIndex] || page.mainFrame(), finding.target);
      }

      return buildReport({
        url: page.url(),
        startedAt,
        durationMs: Date.now() - start,
        frames,
        findings,
        inventory: inventory.slice(0, cfg.maxInventoryItems),
        warnings
      });
    } finally {
      if (browser) await browser.close().catch(() => {});
    }
  })();

  const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error(`El análisis excedió ${cfg.scanTimeoutMs / 1000}s y fue cancelado.`)), cfg.scanTimeoutMs));
  return await Promise.race([task, timeout]).finally(async () => { if (browser) await browser.close().catch(() => {}); });
}




const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ARC_API_KEY || '';
let activeScans = 0;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_SCANS || 2);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(x => x.trim()) : true }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname)));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  const supplied = req.get('x-arc-key') || '';
  if (supplied !== API_KEY) return res.status(401).json({ error: 'API key inválida.' });
  next();
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'ArcTool scanner', version: 2, activeScans }));

app.post('/api/scan', requireKey, async (req, res) => {
  const url = String(req.body?.url || '').trim();
  if (!url) return res.status(400).json({ error: 'Falta url.' });
  if (activeScans >= MAX_CONCURRENT) return res.status(429).json({ error: 'Scanner ocupado. Intenta nuevamente en unos segundos.' });
  activeScans += 1;
  try {
    const report = await scanPage(url, {
      scanTimeoutMs: Number(process.env.SCAN_TIMEOUT_MS || 45000),
      maxFrames: Number(process.env.MAX_FRAMES || 30),
      maxFindings: Number(process.env.MAX_FINDINGS || 5000),
      maxInventoryItems: Number(process.env.MAX_INVENTORY || 5000)
    });
    res.json(report);
  } catch (error) {
    const message = error?.message || 'Error de análisis';
    const status = /URL|host|privad|local|credenciales/i.test(message) ? 400 : 500;
    res.status(status).json({ error: message });
  } finally {
    activeScans -= 1;
  }
});

app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`ArcTool scanner listening on :${PORT}`));
