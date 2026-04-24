// ============================================================
// SERVER-SIDE PDF EXPORT
// ============================================================
//
// Status: backend route is LIVE once wired in server.js, but the frontend
// (resumebuilder.html → exportPDF) does NOT call it yet. The client still
// uses the browser print-dialog path until STATE.useServerPdf is flipped
// on and a fetch() call is added. See the integration checklist at the
// bottom of this header.
//
// Endpoint: POST /api/builder/export/pdf-server
//   auth:  Firebase ID token (Bearer) — applied by server.js via requireAuth
//   body:  { html: string, paper?: 'letter' | 'a4' }
//   returns: application/pdf (attachment)
//
// Rate limit: 15 requests / 60s per Firebase uid (in-memory sliding window).
// Payload cap: 2MB of HTML.
//
// ------------------------------------------------------------
// Hosting (Railway)
// ------------------------------------------------------------
// Playwright's Chromium needs ~1GB of memory and several system libraries
// (libnss3, libatk, libxkbcommon, libdrm, libgbm, etc.). The companion
// `nixpacks.toml` + `package.json` postinstall script install everything
// during the Railway build so no runtime Chromium download is needed.
//
// Minimum Railway service size: 1GB RAM. 2GB is safer for long resumes.
//
// ------------------------------------------------------------
// Security notes
// ------------------------------------------------------------
//   • Auth is enforced by the server.js mount (requireAuth middleware).
//     Never mount this router without auth — Chromium rendering is
//     expensive and trivially abusable.
//   • The `html` field is rendered inside a sandboxed Chromium process
//     with --no-sandbox launch flag. The host (Railway container) is the
//     trust boundary; we never return rendered HTML back to other users.
//   • Hard 15s timeout on setContent + page.pdf prevents a malicious
//     payload from pinning a Chromium worker forever.
//
// ------------------------------------------------------------
// Frontend integration checklist (still TODO)
// ------------------------------------------------------------
//   [ ] In resumebuilder.html add `STATE.useServerPdf = false` (default off).
//   [ ] Expose backend origin via window.SERVER_PDF_URL or reuse BACKEND_URL.
//   [ ] In exportPDF(), when STATE.useServerPdf: fetch this endpoint with
//       { html, paper } and download the returned blob. On any error, fall
//       back to the current print-dialog path.
//   [ ] When active, soften/remove the "approximation" copy in the Word +
//       PowerPoint PDF button titles and the post-export toast.
//
// ============================================================

const express = require('express');
const router  = express.Router();

// Lazily-required so this file can sit in the repo without Playwright
// being installed during local dev. Importing at the top would throw at
// require-time and break the rest of the backend.
let _chromium = null;
function _getChromium() {
  if (_chromium) return _chromium;
  try {
    // eslint-disable-next-line global-require
    _chromium = require('playwright').chromium;
  } catch (e) {
    const err = new Error(
      'Playwright not installed. Run `npm install playwright` in projectbackend/ and `npx playwright install chromium` to activate the server-side PDF path.'
    );
    err.code = 'PLAYWRIGHT_MISSING';
    throw err;
  }
  return _chromium;
}

// Soft cap on payload size so callers can't POST a 200MB HTML blob.
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2MB

// Simple per-uid sliding-window rate limit: 15 requests / 60s.
// In-memory only — resets on container restart. Good enough for this
// endpoint; swap for Redis if we ever horizontally scale the backend.
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 15;
const _rateHits = new Map(); // uid -> [timestamps]
function _rateLimit(uid) {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  const arr = (_rateHits.get(uid) || []).filter(t => t > cutoff);
  if (arr.length >= RATE_LIMIT_MAX) return false;
  arr.push(now);
  _rateHits.set(uid, arr);
  return true;
}

async function htmlToPdf(html, { paper } = {}) {
  const chromium = _getChromium();
  // Flags tuned for container environments (Railway, Docker, Cloud Run).
  // --no-sandbox / --disable-setuid-sandbox: required when running as root.
  // --disable-dev-shm-usage: /dev/shm is 64MB in Docker which is too small
  //                         for Chromium's IPC buffers.
  // --disable-gpu:          no GPU in the container, avoids a crash path.
  //
  // Deliberately NOT set:
  //   --no-zygote: incompatible with Playwright's process manager and
  //                causes `page.pdf` to crash mid-render.
  //   --single-process: same issue.
  const browser = await chromium.launch({
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu'
    ]
  });
  let lastPageError = null;
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    // Surface in-page errors so we don't get a generic "browser closed".
    page.on('pageerror', (err) => { lastPageError = err; console.error('[export-pdf-server] pageerror:', err && err.message); });
    page.on('crash', () => { lastPageError = new Error('Page process crashed'); console.error('[export-pdf-server] page crashed'); });
    // waitUntil: 'load' — does NOT require network silence, which is unreliable
    // when Google Fonts (or any external resource) takes a while or is blocked.
    // After DOM+resources load, we explicitly wait for document.fonts.ready
    // (bounded) so webfonts render correctly without hanging on networkidle.
    await page.setContent(html, { waitUntil: 'load', timeout: 15000 });
    try {
      await page.evaluate(() => (document.fonts && document.fonts.ready) ? document.fonts.ready : null);
    } catch (_) { /* font timeout — render anyway with fallback fonts */ }
    const format = (paper === 'a4' || paper === 'A4') ? 'A4' : 'Letter';
    const buffer = await page.pdf({
      format,
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
      preferCSSPageSize: true
    });
    return buffer;
  } catch (err) {
    // Attach any captured page error so the caller gets context.
    if (lastPageError && err && !err._pageError) {
      err._pageError = lastPageError.message || String(lastPageError);
    }
    throw err;
  } finally {
    try { await browser.close(); } catch (_) { /* noop */ }
  }
}

// POST /api/builder/export/pdf-server
// Auth + JSON body parsing are applied by the server.js mount.
router.post('/api/builder/export/pdf-server', async (req, res) => {
  try {
    const uid = req.uid || 'anon';
    if (!_rateLimit(uid)) {
      return res.status(429).json({ error: 'Too many PDF requests — try again in a minute.' });
    }
    const { html, paper } = req.body || {};
    if (typeof html !== 'string' || !html.trim()) {
      return res.status(400).json({ error: 'Missing `html` string in request body.' });
    }
    if (Buffer.byteLength(html, 'utf8') > MAX_HTML_BYTES) {
      return res.status(413).json({ error: 'HTML payload exceeds 2MB limit.' });
    }
    const pdf = await htmlToPdf(html, { paper });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="resume.pdf"');
    res.setHeader('Cache-Control', 'private, no-store');
    return res.status(200).send(pdf);
  } catch (err) {
    if (err && err.code === 'PLAYWRIGHT_MISSING') {
      return res.status(501).json({ error: err.message });
    }
    // Log the full error to Railway so we can diagnose without exposing
    // internals to end users.
    console.error('[export-pdf-server] render failed:', err && err.stack || err);
    if (err && err._pageError) {
      console.error('[export-pdf-server] captured page error:', err._pageError);
    }
    // While we are stabilising the server-PDF path, return the actual
    // error message to authenticated callers. This is gated by an env
    // var so we can lock it down later without another deploy cycle.
    const debug = process.env.PDF_SERVER_DEBUG === '1';
    const payload = { error: 'PDF render failed.' };
    if (debug) {
      payload.detail = (err && err.message) || String(err);
      if (err && err._pageError) payload.pageError = err._pageError;
    }
    return res.status(500).json(payload);
  }
});

module.exports = { router, htmlToPdf };
