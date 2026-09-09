'use strict';

const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const net = require('node:net');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { chromium, devices } = require('playwright');
const axe = require('axe-core');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ARC_API_KEY || '';
const BROWSERLESS_TOKEN = process.env.BROWSERLESS_TOKEN || '';
const BROWSERLESS_HOST = (process.env.BROWSERLESS_HOST || 'https://production-sfo.browserless.io').replace(/\/$/, '');
const SESSION_TTL_MS = clampNumber(process.env.SESSION_TTL_MS, 60_000, 1_800_000, 300_000);
const MAX_SESSIONS = clampNumber(process.env.MAX_SESSIONS, 1, 20, 3);
const MAX_FINDINGS = clampNumber(process.env.MAX_FINDINGS, 100, 20_000, 5000);
const MAX_INVENTORY = clampNumber(process.env.MAX_INVENTORY, 100, 20_000, 5000);
const MAX_FRAMES = clampNumber(process.env.MAX_FRAMES, 1, 100, 30);

const sessions = new Map();
const severityOrder = { critical: 0, serious: 1, moderate: 2, minor: 3, info: 4 };
const severityWeight = { critical: 25, serious: 12, moderate: 5, minor: 2, info: 0 };

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return false;
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true;
  if (/^(fc|fd|fe80:)/i.test(ip)) return true;
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  return false;
}

async function assertSafePublicUrl(raw, cache = new Map()) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('URL inválida.'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Sólo se permiten URLs http/https.');
  if (u.username || u.password) throw new Error('No se permiten credenciales embebidas en la URL.');
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local')) throw new Error('No se permiten hosts locales.');
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('No se permiten redes privadas.');
  } else {
    let ips = cache.get(host);
    if (!ips) {
      ips = (await dns.lookup(host, { all: true, verbatim: true })).map(x => x.address);
      cache.set(host, ips);
    }
    if (!ips.length || ips.some(isPrivateIp)) throw new Error('El host resuelve a una red privada o no válida.');
  }
  return u.toString();
}

function normalizeSeverity(v) {
  const s = String(v || '').toLowerCase();
  if (['critical', 'serious', 'moderate', 'minor'].includes(s)) return s;
  if (s === 'major') return 'serious';
  return 'minor';
}

function wcagTags(tags = []) {
  return tags.filter(t => /^wcag\d/.test(t) || t === 'best-practice');
}

function truncate(v, max = 1000) {
  const s = String(v || '').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function scoreFindings(findings) {
  const counts = { critical: 0, serious: 0, moderate: 0, minor: 0, info: 0 };
  for (const f of findings) counts[normalizeSeverity(f.severity || f.impact)]++;
  const penalty = Object.entries(counts).reduce((sum, [s, c]) => sum + (severityWeight[s] || 0) * c, 0);
  return { score: Math.max(0, 100 - Math.min(100, penalty)), counts };
}

function sortFindings(items) {
  return [...items].sort((a, b) => {
    const d = severityOrder[normalizeSeverity(a.severity)] - severityOrder[normalizeSeverity(b.severity)];
    if (d) return d;
    return String(a.pageUrl || '').localeCompare(String(b.pageUrl || '')) || String(a.ruleId || '').localeCompare(String(b.ruleId || ''));
  });
}

function summarizeRules(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = f.ruleId || f.title || 'unknown';
    const cur = m.get(k) || { ruleId: k, title: f.title || k, severity: normalizeSeverity(f.severity), count: 0, wcag: f.wcag || [] };
    cur.count++;
    if (severityOrder[normalizeSeverity(f.severity)] < severityOrder[cur.severity]) cur.severity = normalizeSeverity(f.severity);
    m.set(k, cur);
  }
  return [...m.values()].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || b.count - a.count);
}

function deviceConfig(name) {
  const n = String(name || 'desktop').toLowerCase();
  if (n === 'iphone') return { ...devices['iPhone 15'], label: 'iPhone' };
  if (n === 'tablet') return { ...devices['iPad (gen 7)'], label: 'Tablet' };
  return { viewport: { width: 1440, height: 1000 }, userAgent: undefined, isMobile: false, hasTouch: false, label: 'Desktop' };
}

async function createRemoteBrowser(deviceName) {
  // Use Browserless' native Playwright transport for the long-lived session.
  // Keeping the whole browser attached over CDP while a LiveURL viewer also
  // attaches can generate duplicate Target.attachedToTarget events in
  // Playwright and crash the Node process with "Duplicate target".
  const wsBase = BROWSERLESS_HOST.replace(/^https:/i, 'wss:').replace(/^http:/i, 'ws:');
  const params = new URLSearchParams({
    token: BROWSERLESS_TOKEN,
    timeout: String(SESSION_TTL_MS)
  });
  const endpoint = `${wsBase}/chromium/playwright?${params.toString()}`;
  const browser = await chromium.connect(endpoint, { timeout: 60_000 });
  const d = deviceConfig(deviceName);
  const existing = browser.contexts()[0];
  const context = existing || await browser.newContext({ viewport: d.viewport, userAgent: d.userAgent, isMobile: d.isMobile, hasTouch: d.hasTouch });
  const page = context.pages()[0] || await context.newPage();
  return { browser, context, page, remote: { mode: 'playwright-native' } };
}

async function createLocalBrowser(deviceName) {
  const browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage', '--no-sandbox'] });
  const d = deviceConfig(deviceName);
  const context = await browser.newContext({ viewport: d.viewport, userAgent: d.userAgent, isMobile: d.isMobile, hasTouch: d.hasTouch });
  const page = await context.newPage();
  return { browser, context, page, remote: null };
}

async function installNetworkGuard(context, dnsCache) {
  await context.route('**/*', async route => {
    const url = route.request().url();
    if (/^(data:|blob:|about:)/.test(url)) return route.continue();
    try { await assertSafePublicUrl(url, dnsCache); return route.continue(); }
    catch { return route.abort('blockedbyclient'); }
  });
}

async function mintLiveUrl(session) {
  if (!session.remote) return null;
  try {
    const cdp = await session.context.newCDPSession(session.page);
    session.captchaSeen = false;
    cdp.on('Browserless.captchaFound', () => { session.captchaSeen = true; });

    // The live-view lifetime must be shorter than the remaining Browserless
    // session lifetime. Asking for the full session TTL after navigation can
    // make Browserless return an error instead of a liveURL.
    const preferredTimeout = Math.min(120_000, Math.max(30_000, SESSION_TTL_MS - 30_000));
    let result = await cdp.send('Browserless.liveURL', {
      quality: 70,
      timeout: preferredTimeout,
      interactable: true,
      resizable: true
    });

    // Browserless reports some liveURL failures in result.error rather than
    // throwing. Retry once with its default timeout (30s) before giving up.
    if (!result?.liveURL && result?.error) {
      session.warnings.push(`Browserless liveURL reintento: ${truncate(result.error, 300)}`);
      result = await cdp.send('Browserless.liveURL', {
        quality: 70,
        interactable: true,
        resizable: true
      });
    }

    if (!result?.liveURL) {
      const detail = result?.error ? truncate(result.error, 300) : 'Browserless no devolvió liveURL.';
      session.warnings.push(`No se pudo crear vista interactiva: ${detail}`);
      console.warn(`ArcTool liveURL unavailable: ${detail}`);
      return null;
    }

    return result.liveURL;
  } catch (e) {
    const detail = truncate(e.message, 300);
    session.warnings.push(`No se pudo crear vista interactiva: ${detail}`);
    console.warn(`ArcTool liveURL error: ${detail}`);
    return null;
  }
}

async function detectInteractionGate(page, captchaSeen = false) {
  const snapshot = await page.evaluate(() => ({
    title: document.title || '',
    text: (document.body?.innerText || '').slice(0, 20_000),
    html: (document.documentElement?.outerHTML || '').slice(0, 50_000),
    passwordInputs: document.querySelectorAll('input[type="password"]').length,
    captchaHints: document.querySelectorAll('[class*="captcha" i],[id*="captcha" i],iframe[src*="captcha" i],iframe[src*="recaptcha" i],iframe[src*="hcaptcha" i],iframe[src*="turnstile" i]').length
  })).catch(() => ({ title: '', text: '', html: '', passwordInputs: 0, captchaHints: 0 }));
  const haystack = `${snapshot.title}\n${snapshot.text}\n${snapshot.html}`.toLowerCase();
  const patterns = [
    /verify you are human/, /checking your browser/, /security check/, /challenge/, /captcha/,
    /cloudflare/, /cf-chl-/, /akamai/, /bot manager/, /access denied.*reference/,
    /hcaptcha/, /g-recaptcha/, /turnstile/
  ];
  const antiBot = captchaSeen || snapshot.captchaHints > 0 || patterns.some(r => r.test(haystack));
  const login = snapshot.passwordInputs > 0 || /\b(sign in|log in|iniciar sesi[oó]n|acceder)\b/.test(haystack.slice(0, 8000));
  return { antiBot, login, interactionSuggested: antiBot || login, title: snapshot.title };
}

async function elementMetadata(frame, selector) {
  try {
    return await frame.evaluate(sel => {
      let el = null;
      try { el = document.querySelector(sel); } catch (_) {}
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const name = (el.getAttribute('aria-label') || el.getAttribute('alt') || el.getAttribute('title') || el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 300);
      return {
        tag: el.tagName.toLowerCase(), role: el.getAttribute('role'), accessibleName: name,
        text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 500),
        ariaLabel: el.getAttribute('aria-label'), alt: el.getAttribute('alt'), title: el.getAttribute('title'),
        href: el.getAttribute('href'), type: el.getAttribute('type'), tabIndex: el.tabIndex,
        rect: { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) },
        color: cs.color, backgroundColor: cs.backgroundColor, fontSize: cs.fontSize, fontWeight: cs.fontWeight
      };
    }, selector);
  } catch { return null; }
}

async function runAxe(frame, pageUrl, pageIndex, frameIndex) {
  await frame.evaluate(axe.source);
  const result = await frame.evaluate(async () => axe.run(document, { resultTypes: ['violations'], rules: { region: { enabled: true } } }));
  const out = [];
  for (const v of result.violations || []) {
    for (const node of v.nodes || []) {
      const target = Array.isArray(node.target) ? node.target.join(' ') : String(node.target || '');
      out.push({
        source: 'axe-core', pageIndex, pageUrl, frameIndex, frameUrl: frame.url(), ruleId: v.id,
        title: v.help, description: v.description, severity: normalizeSeverity(v.impact), wcag: wcagTags(v.tags),
        helpUrl: v.helpUrl, target, html: truncate(node.html, 1200), failureSummary: truncate(node.failureSummary, 1600)
      });
    }
  }
  return out;
}

async function customChecks(frame, pageUrl, pageIndex, frameIndex) {
  return frame.evaluate(({ pageUrl, pageIndex, frameIndex }) => {
    const findings = [];
    const cssPath = el => {
      if (!el) return '';
      if (el.id) return `#${CSS.escape(el.id)}`;
      const parts = []; let cur = el;
      while (cur && cur.nodeType === 1 && parts.length < 5) {
        let p = cur.tagName.toLowerCase();
        const sib = cur.parentElement ? [...cur.parentElement.children].filter(x => x.tagName === cur.tagName) : [];
        if (sib.length > 1) p += `:nth-of-type(${sib.indexOf(cur) + 1})`;
        parts.unshift(p); cur = cur.parentElement;
      }
      return parts.join(' > ');
    };
    const name = el => (el.getAttribute('aria-label') || el.getAttribute('title') || el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
    const push = f => findings.push({ source: 'ArcTool', pageUrl, pageIndex, frameIndex, frameUrl: location.href, ...f });

    document.querySelectorAll('iframe').forEach(el => {
      if (!el.getAttribute('title')?.trim()) push({ ruleId: 'iframe-title-custom', title: 'iframe sin título descriptivo', severity: 'serious', wcag: ['wcag412'], target: cssPath(el), failureSummary: 'Agrega un title que describa el propósito del frame.' });
    });
    document.querySelectorAll('button,[role="button"]').forEach(el => {
      if (!name(el)) push({ ruleId: 'control-name-custom', title: 'Control sin nombre accesible', severity: 'critical', wcag: ['wcag412'], target: cssPath(el), failureSummary: 'El control no expone un nombre accesible.' });
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24)) push({ ruleId: 'target-size-custom', title: 'Objetivo táctil muy pequeño', severity: 'moderate', wcag: ['wcag258'], target: cssPath(el), failureSummary: `Tamaño ${Math.round(r.width)}×${Math.round(r.height)} px.` });
    });
    document.querySelectorAll('a[href]').forEach(el => {
      if (!name(el) && !el.querySelector('img[alt]')) push({ ruleId: 'link-name-custom', title: 'Enlace sin nombre accesible', severity: 'critical', wcag: ['wcag244', 'wcag412'], target: cssPath(el), failureSummary: 'El enlace no tiene texto ni alternativa accesible.' });
    });
    const hs = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')];
    for (let i = 1; i < hs.length; i++) {
      const a = Number(hs[i - 1].tagName.slice(1)); const b = Number(hs[i].tagName.slice(1));
      if (b - a > 1) push({ ruleId: 'heading-jump-custom', title: 'Salto en jerarquía de encabezados', severity: 'moderate', wcag: ['wcag131'], target: cssPath(hs[i]), failureSummary: `La jerarquía salta de H${a} a H${b}.` });
    }
    document.querySelectorAll('[onclick]:not(a):not(button):not(input):not(select):not(textarea)').forEach(el => {
      if (el.tabIndex < 0 && !el.getAttribute('role')) push({ ruleId: 'clickable-semantic-custom', title: 'Elemento clicable sin semántica/teclado evidente', severity: 'serious', wcag: ['wcag211', 'wcag412'], target: cssPath(el), failureSummary: 'El elemento con onclick puede no ser alcanzable mediante teclado.' });
    });
    return findings;
  }, { pageUrl, pageIndex, frameIndex });
}

async function inventoryFrame(frame, pageUrl, pageIndex, frameIndex, limit) {
  return frame.evaluate(({ pageUrl, pageIndex, frameIndex, limit }) => {
    const sel = 'a,button,input,select,textarea,img,iframe,video,audio,h1,h2,h3,h4,h5,h6,p,li,td,th,caption,legend,[role],[tabindex],form,label,nav,main,header,footer,aside,section';
    const nodes = [...document.querySelectorAll(sel)].slice(0, limit);
    const items = nodes.map((el, index) => {
      const r = el.getBoundingClientRect();
      return { pageUrl, pageIndex, frameIndex, frameUrl: location.href, index, tag: el.tagName.toLowerCase(), id: el.id || null,
        role: el.getAttribute('role'), text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 240),
        ariaLabel: el.getAttribute('aria-label'), alt: el.getAttribute('alt'), title: el.getAttribute('title'), href: el.getAttribute('href'),
        type: el.getAttribute('type'), tabIndex: el.tabIndex, rect: { width: Math.round(r.width), height: Math.round(r.height) } };
    });
    return { totalElements: document.querySelectorAll('*').length, items };
  }, { pageUrl, pageIndex, frameIndex, limit });
}

async function scanCurrentPage(session, pageIndex) {
  const page = session.page;
  const pageUrl = page.url();
  const frames = page.frames().slice(0, MAX_FRAMES);
  const frameSummaries = [];
  const findings = [];
  const inventory = [];
  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    if (!frame.url() || frame.url() === 'about:blank') continue;
    const summary = { pageIndex, pageUrl, frameIndex: i, frameUrl: frame.url(), name: frame.name() || null, status: 'ok', elementCount: 0 };
    try {
      const inv = await inventoryFrame(frame, pageUrl, pageIndex, i, Math.max(0, MAX_INVENTORY - inventory.length));
      summary.elementCount = inv.totalElements;
      inventory.push(...inv.items);
      findings.push(...await runAxe(frame, pageUrl, pageIndex, i));
      findings.push(...await customChecks(frame, pageUrl, pageIndex, i));
    } catch (e) {
      summary.status = 'partial'; summary.error = truncate(e.message, 400);
      session.warnings.push(`Frame parcial ${frame.url()}: ${summary.error}`);
    }
    frameSummaries.push(summary);
    if (findings.length >= MAX_FINDINGS) break;
  }
  for (const f of findings.slice(0, MAX_FINDINGS)) {
    const frame = frames[f.frameIndex] || page.mainFrame();
    if (f.target) f.element = await elementMetadata(frame, f.target);
  }
  const title = await page.title().catch(() => '');
  return { page: { index: pageIndex, url: pageUrl, title, frames: frameSummaries.length }, frames: frameSummaries, findings: findings.slice(0, MAX_FINDINGS), inventory: inventory.slice(0, MAX_INVENTORY) };
}

async function internalLinks(page, origin, max) {
  const hrefs = await page.evaluate(() => [...document.querySelectorAll('a[href]')].map(a => a.href).filter(Boolean).slice(0, 500));
  const out = [];
  for (const href of hrefs) {
    try {
      const u = new URL(href);
      if (u.origin !== origin || !['http:', 'https:'].includes(u.protocol)) continue;
      u.hash = '';
      const s = u.toString();
      if (!out.includes(s)) out.push(s);
      if (out.length >= max) break;
    } catch (_) {}
  }
  return out;
}

async function scanSession(session) {
  if (session.scanning) throw new Error('Esta sesión ya está analizando.');
  session.scanning = true;
  const started = Date.now();
  try {
    const scope = session.options.scope === 'site' ? 'site' : 'page';
    const maxPages = scope === 'site' ? clampNumber(session.options.maxPages, 1, 30, 5) : 1;
    const root = new URL(session.page.url());
    const queue = [session.page.url()];
    const seen = new Set();
    const pages = [], frames = [], findings = [], inventory = [];

    while (queue.length && pages.length < maxPages && findings.length < MAX_FINDINGS) {
      const target = queue.shift();
      if (seen.has(target)) continue;
      seen.add(target);
      if (session.page.url() !== target) {
        await assertSafePublicUrl(target, session.dnsCache);
        await session.page.goto(target, { waitUntil: 'domcontentloaded', timeout: 25_000 });
        await session.page.waitForTimeout(800);
      }
      const gate = await detectInteractionGate(session.page, false);
      if (gate.antiBot) {
        session.warnings.push(`La página ${session.page.url()} muestra una verificación anti-bot; no se calculó un score para esa página hasta completar la interacción humana.`);
        if (pages.length === 0) {
          return { blocked: true, interactionRequired: true, reason: 'security_challenge', finalUrl: session.page.url(), title: gate.title, liveUrl: session.liveUrl, sessionId: session.id };
        }
        continue;
      }
      const result = await scanCurrentPage(session, pages.length);
      pages.push(result.page); frames.push(...result.frames); findings.push(...result.findings); inventory.push(...result.inventory);
      if (scope === 'site' && queue.length + seen.size < maxPages * 4) {
        const links = await internalLinks(session.page, root.origin, maxPages * 3);
        for (const link of links) if (!seen.has(link) && !queue.includes(link)) queue.push(link);
      }
    }

    const sorted = sortFindings(findings.slice(0, MAX_FINDINGS));
    const { score, counts } = scoreFindings(sorted);
    return {
      schemaVersion: 3,
      generatedAt: new Date().toISOString(),
      requestedUrl: session.requestedUrl,
      finalUrl: session.page.url(),
      scope,
      device: session.options.device,
      score,
      severityCounts: counts,
      totals: { pages: pages.length, frames: frames.length, elementsScanned: frames.reduce((s, f) => s + (f.elementCount || 0), 0), findings: sorted.length, inventoryItems: inventory.length },
      summaryByRule: summarizeRules(sorted), pages, frames, inventory: inventory.slice(0, MAX_INVENTORY), findings: sorted,
      warnings: session.warnings,
      durationMs: Date.now() - started,
      disclaimer: 'La automatización detecta muchos problemas WCAG, pero no certifica conformidad total. Se requiere validación manual con teclado, VoiceOver/TalkBack y revisión contextual.'
    };
  } finally { session.scanning = false; }
}

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }

function reportHtml(r) {
  const rows = (r.findings || []).map((f, i) => `<tr><td>${i+1}</td><td>${esc(f.severity)}</td><td>${esc(f.pageUrl)}</td><td>${esc(f.title)}</td><td>${esc((f.wcag||[]).join(', '))}</td><td>${esc(f.element?.accessibleName || f.element?.text || '')}</td><td>${esc(f.frameUrl)}</td><td><code>${esc(f.target)}</code></td><td>${esc(f.failureSummary || f.description || '')}</td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><style>@page{size:A4 landscape;margin:12mm}body{font:11px Arial;color:#111}h1{font-size:24px;margin:0 0 6px}.meta{color:#555}.cards{display:flex;gap:10px;margin:14px 0}.card{border:1px solid #ddd;border-radius:8px;padding:10px;min-width:90px}.card strong{font-size:20px;display:block}table{width:100%;border-collapse:collapse;font-size:8px}th,td{border:1px solid #ddd;padding:5px;vertical-align:top;word-break:break-word}th{background:#f4f4f4;text-align:left}tr:nth-child(even){background:#fafafa}code{font-size:7px}</style></head><body><h1>ArcTool V3 · Accessibility Audit</h1><div class="meta">URL: ${esc(r.requestedUrl)}<br>Generado: ${esc(r.generatedAt)} · Alcance: ${esc(r.scope)} · Dispositivo: ${esc(r.device)}</div><div class="cards"><div class="card"><strong>${esc(r.score)}</strong>Score</div><div class="card"><strong>${esc(r.severityCounts?.critical||0)}</strong>Critical</div><div class="card"><strong>${esc(r.severityCounts?.serious||0)}</strong>Serious</div><div class="card"><strong>${esc(r.severityCounts?.moderate||0)}</strong>Moderate</div><div class="card"><strong>${esc(r.severityCounts?.minor||0)}</strong>Minor</div><div class="card"><strong>${esc(r.totals?.elementsScanned||0)}</strong>Elementos</div></div><h2>Hallazgos priorizados</h2><table><thead><tr><th>#</th><th>Prioridad</th><th>Página</th><th>Problema</th><th>WCAG</th><th>Texto / nombre</th><th>Frame</th><th>Selector</th><th>Recomendación / detalle</th></tr></thead><tbody>${rows}</tbody></table><p>${esc(r.disclaimer||'')}</p></body></html>`;
}

async function closeSession(session) {
  if (!session || session.closed) return;
  session.closed = true;
  try { await session.browser.close(); } catch (_) {}
  if (session.remote?.stop) {
    try { await fetch(`${session.remote.stop}${session.remote.stop.includes('?') ? '&' : '?'}force=true`, { method: 'DELETE' }); } catch (_) {}
  }
  sessions.delete(session.id);
}

setInterval(() => {
  const now = Date.now();
  for (const s of sessions.values()) if (s.expiresAt < now) closeSession(s).catch(() => {});
}, 30_000).unref();

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(s => s.trim()) : true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

function requireKey(req, res, next) {
  if (!API_KEY) return next();
  if ((req.get('x-arc-key') || '') !== API_KEY) return res.status(401).json({ error: 'API key inválida.' });
  next();
}

app.get('/api/health', (_req, res) => res.json({ ok: true, version: 3, interactiveBrowser: !!BROWSERLESS_TOKEN, sessions: sessions.size }));

app.post('/api/session/start', requireKey, async (req, res) => {
  if (sessions.size >= MAX_SESSIONS) return res.status(429).json({ error: 'Se alcanzó el máximo de sesiones activas.' });
  const requestedUrl = String(req.body?.url || '').trim();
  const options = { scope: req.body?.scope === 'site' ? 'site' : 'page', device: ['iphone','tablet','desktop'].includes(req.body?.device) ? req.body.device : 'desktop', maxPages: clampNumber(req.body?.maxPages, 1, 30, 5) };
  const dnsCache = new Map();
  let session;
  try {
    const url = await assertSafePublicUrl(requestedUrl, dnsCache);
    const holder = BROWSERLESS_TOKEN ? await createRemoteBrowser(options.device) : await createLocalBrowser(options.device);
    session = { id: crypto.randomUUID(), requestedUrl: url, options, dnsCache, warnings: [], captchaSeen: false, scanning: false, closed: false, expiresAt: Date.now() + SESSION_TTL_MS, ...holder };
    sessions.set(session.id, session);
    await installNetworkGuard(session.context, dnsCache);
    session.page.setDefaultTimeout(8000);
    session.page.setDefaultNavigationTimeout(25_000);
    await session.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25_000 });
    await session.page.waitForTimeout(1000);
    session.liveUrl = await mintLiveUrl(session);
    const gate = await detectInteractionGate(session.page, false);
    res.json({
      sessionId: session.id, requestedUrl: url, finalUrl: session.page.url(), title: gate.title,
      interactionRequired: gate.interactionSuggested, reason: gate.antiBot ? 'security_challenge' : gate.login ? 'login' : null,
      liveUrl: session.liveUrl, interactiveAvailable: !!session.liveUrl,
      interactiveWarning: session.liveUrl ? null : (session.warnings.find(w => /vista interactiva|liveURL/i.test(w)) || null),
      message: gate.interactionSuggested ? 'Se recomienda completar la interacción humana antes de continuar.' : 'Página lista para auditoría.'
    });
  } catch (e) {
    if (session) await closeSession(session).catch(() => {});
    res.status(/URL|host|privad|local|credenciales/i.test(e.message) ? 400 : 500).json({ error: e.message });
  }
});

app.post('/api/session/:id/scan', requireKey, async (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || session.closed) return res.status(404).json({ error: 'Sesión expirada o inexistente.' });
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  try {
    const gate = await detectInteractionGate(session.page, false);
    if (gate.antiBot) return res.status(409).json({ error: 'La verificación anti-bot sigue activa.', interactionRequired: true, liveUrl: session.liveUrl });
    const report = await scanSession(session);
    if (report.blocked) return res.status(409).json(report);
    session.lastReport = report;
    res.json(report);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/session/:id/status', requireKey, async (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || session.closed) return res.status(404).json({ error: 'Sesión expirada o inexistente.' });
  const gate = await detectInteractionGate(session.page, false);
  res.json({ sessionId: session.id, finalUrl: session.page.url(), title: gate.title, interactionRequired: gate.interactionSuggested, reason: gate.antiBot ? 'security_challenge' : gate.login ? 'login' : null, liveUrl: session.liveUrl });
});

app.delete('/api/session/:id', requireKey, async (req, res) => {
  const session = sessions.get(req.params.id);
  if (session) await closeSession(session);
  res.json({ ok: true });
});

app.post('/api/report/pdf', requireKey, async (req, res) => {
  const report = req.body?.report;
  if (!report || !Array.isArray(report.findings)) return res.status(400).json({ error: 'Reporte inválido.' });
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage', '--no-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(reportHtml(report), { waitUntil: 'load' });
    const pdf = await page.pdf({ format: 'A4', landscape: true, printBackground: true, margin: { top: '12mm', right: '10mm', bottom: '12mm', left: '10mm' } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="ArcTool-accessibility-report.pdf"');
    res.send(pdf);
  } catch (e) { res.status(500).json({ error: e.message }); }
  finally { if (browser) await browser.close().catch(() => {}); }
});

app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`ArcTool V3 listening on :${PORT} · interactive=${!!BROWSERLESS_TOKEN}`));
