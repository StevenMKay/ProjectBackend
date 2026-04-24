// ============================================================
// SERVER-SIDE PDF EXPORT — NOT ACTIVE YET
// ============================================================
//
// Status: SCAFFOLD ONLY. This module is NOT required by server.js and
// NOT wired to any client code in resumebuilder.html. It exists so the
// eventual server-side PDF pipeline has a known shape to deploy against.
// Do not import this file from production code paths without completing
// the integration checklist at the bottom of this header.
//
// ------------------------------------------------------------
// WHY a server-side PDF path?
// ------------------------------------------------------------
// The current client-side PDF flow (exportPDF() in resumebuilder.html)
// opens a new window and invokes the browser's print dialog. That path
// is reliable but depends on the user's browser/printer driver and is
// explicitly an APPROXIMATION of the Word / PowerPoint layouts — not a
// byte-accurate render of those native formats.
//
// A server-side renderer gives us:
//   • consistent pagination + margins across browsers / OSes
//   • no "Save as PDF" dialog step (direct binary download)
//   • ability to run automated tests against the produced PDF
//
// ------------------------------------------------------------
// WHAT this scaffold provides
// ------------------------------------------------------------
//   • POST /builder/export/pdf-server
//       body: { html?: string, model?, template?, accent?, paper? }
//       returns: application/pdf buffer
//   • Playwright-based HTML → PDF pipeline with sane defaults
//   • Letter / A4 paper switch, printBackground:true, zero margin
//   • Launch flags compatible with containerized hosts (--no-sandbox)
//
// ------------------------------------------------------------
// WHAT is still missing (integration checklist)
// ------------------------------------------------------------
//   [ ] Pick a host (see "Hosting" below). GitHub Pages cannot run this.
//   [ ] `npm install playwright` (local Chromium) OR
//       `npm install @sparticuz/chromium puppeteer-core` for Vercel/Lambda.
//   [ ] Decide how the client builds the HTML to POST. Two options:
//         (a) Client builds HTML with _selectAndRender(...) and sends
//             the full string — simpler, but payload is large.
//         (b) Client sends { model, template, accent } and the server
//             re-renders via a shared template lib — keeps payload
//             small but requires extracting the renderer into Node.
//   [ ] Auth guard: require a Firebase ID token (reuse requireAuth
//       middleware from server.js) so random callers can't abuse the
//       PDF service.
//   [ ] Rate limit per-uid (Stripe-like sliding window).
//   [ ] Wire the route into server.js: `app.use(require('./export-pdf-server').router);`
//   [ ] Frontend: add feature flag `STATE.useServerPdf`; when ON,
//       `exportPDF()` POSTs to SERVER_PDF_URL and downloads the blob
//       instead of opening the print window. Fall back to the current
//       client-side path on network error or 5xx.
//   [ ] Set env var SERVER_PDF_URL on the static site side (or hard-
//       code the backend origin if same-deploy).
//
// ------------------------------------------------------------
// Hosting
// ------------------------------------------------------------
//   • GitHub Pages  — STATIC ONLY. Cannot run Node / Playwright.
//   • Vercel Serverless — works with @sparticuz/chromium-min +
//       puppeteer-core. Function needs ~1024MB RAM and up to 30s
//       max-duration. Cold start ~1-3s.
//   • Railway / Render / Fly.io — full container, Playwright installs
//       its own Chromium, works out of the box. Recommended for this
//       repo since projectbackend/ is already an Express app.
//   • Memory: budget >= 512MB; 1024MB is safer for long resumes.
//
// ------------------------------------------------------------
// Security notes
// ------------------------------------------------------------
//   • NEVER trust the `html` field from an anonymous caller. When wiring
//     for production, either (a) require auth + rate-limit, or (b) switch
//     to payload option (b) above so the server renders from a trusted
//     template.
//   • Set a hard timeout on page.setContent + page.pdf (we do — 15s) so
//     a malicious payload can't pin a Chromium worker forever.
//   • Chromium is launched with --no-sandbox because most container hosts
//     don't allow user-namespaces. This is standard for serverless but
//     means the host itself must be the trust boundary.
//
// ============================================================

const express = require('express');
const router  = express.Router();

// Lazily-required so this file can sit in the repo without Playwright
// being installed. Importing at the top would throw at require-time.
let _chromium = null;
function _getChromium() {
  if (_chromium) return _chromium;
  try {
    // eslint-disable-next-line global-require
    _chromium = require('playwright').chromium;
  } catch (e) {
    const err = new Error(
      'Playwright not installed. Run `npm install playwright` in projectbackend/ to activate the server-side PDF path.'
    );
    err.code = 'PLAYWRIGHT_MISSING';
    throw err;
  }
  return _chromium;
}

// Soft cap on payload size so callers can't POST a 200MB HTML blob.
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2MB

async function htmlToPdf(html, { paper } = {}) {
  const chromium = _getChromium();
  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    // networkidle so web fonts + images are loaded before snapshot.
    await page.setContent(html, { waitUntil: 'networkidle', timeout: 15000 });
    const format = (paper === 'a4' || paper === 'A4') ? 'A4' : 'Letter';
    const buffer = await page.pdf({
      format,
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
      preferCSSPageSize: true
    });
    return buffer;
  } finally {
    try { await browser.close(); } catch (_) { /* noop */ }
  }
}

// POST /builder/export/pdf-server
// NOTE: unauthenticated for now — DO NOT mount this router in server.js
// without adding the requireAuth middleware from server.js.
router.post(
  '/builder/export/pdf-server',
  express.json({ limit: MAX_HTML_BYTES }),
  async (req, res) => {
    try {
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
      console.error('[export-pdf-server] render failed:', err);
      return res.status(500).json({ error: 'PDF render failed.' });
    }
  }
);

module.exports = { router, htmlToPdf };
