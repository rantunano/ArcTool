# ArcTool V3

**© 2026 rantunano. Proprietary software. All rights reserved.**

ArcTool V3 is a mobile-first accessibility auditing web application. The end user works entirely from the HTML interface: URL, scope, device, human interaction, results, filters and exports.

## What V3 adds

- Graphical HTML interface; no GitHub Actions or terminal required for end users.
- Any public HTTP/HTTPS URL as the audit target.
- Page mode or same-origin site crawl mode.
- Desktop, iPhone and tablet profiles.
- DOM, text, links, buttons, form controls, images, headings, ARIA and iframe analysis.
- axe-core plus ArcTool custom checks.
- Element-level findings with page, frame, selector, accessible name, text and WCAG tags.
- Priority ordering: Critical → Serious → Moderate → Minor.
- Search and filters by severity/page/text/WCAG/selector.
- PDF, CSV and JSON export.
- Human-in-the-loop remote browser handoff for CAPTCHA/login/MFA when Browserless is configured.
- Challenge detection that avoids presenting an anti-bot page score as the target website score.

## Human interaction model

ArcTool does **not** automate or defeat CAPTCHA/security challenges. If a site requests human verification, ArcTool can expose the same running remote browser session through Browserless `liveURL`. The user completes the interaction directly in the target page, then returns to ArcTool and selects **Ya terminé · Continuar auditoría**. The same browser state/cookies are preserved for the scan.

Credentials are not entered into ArcTool's own form. They are typed directly into the target page in the interactive browser session.

## Architecture

```text
iPhone / Desktop browser
        |
        v
   ArcTool HTML UI
        |
        v
    ArcTool API
        |
        +--> Local Playwright (normal automated scans + PDF generation)
        |
        +--> Browserless persistent session (optional human interaction)
                    |
                    +--> liveURL -> user completes CAPTCHA/login/MFA
                    |
                    +--> same Chromium session -> axe-core + ArcTool rules
        |
        v
  Findings table + PDF/CSV/JSON
```

## Local development

```bash
npm install
npx playwright install --with-deps chromium
npm start
```

Open `http://localhost:3000`.

Without `BROWSERLESS_TOKEN`, normal public pages can be scanned, but human-in-the-loop interaction is unavailable.

## Interactive mode

Set a Browserless API token in the backend environment:

```bash
BROWSERLESS_TOKEN=your_token
```

Optional:

```bash
BROWSERLESS_HOST=https://production-sfo.browserless.io
SESSION_TTL_MS=300000
```

The Browserless token is server-side only and is never placed in the HTML application.

## Deployment

The full V3 should run on a container-capable host because the API needs Node.js and Chromium. `Dockerfile` is included.

GitHub Pages can still host a frontend-only copy of `index.html`, but then **Configuración avanzada → Backend ArcTool** must point to the deployed API. The cleaner production deployment is to host both the HTML and API together from the same Node/container service.

## API

- `GET /api/health`
- `POST /api/session/start`
- `POST /api/session/:id/scan`
- `GET /api/session/:id/status`
- `DELETE /api/session/:id`
- `POST /api/report/pdf`

### Start session body

```json
{
  "url": "https://example.com",
  "scope": "page",
  "device": "iphone",
  "maxPages": 5
}
```

## Security/stability safeguards

- Blocks localhost, private/reserved IP ranges and embedded URL credentials.
- Guards browser subrequests against private networks.
- Session TTL and maximum active-session limit.
- Limits pages, frames, inventory and findings.
- Explicit session cleanup endpoint.
- Browserless connection and stop URLs remain server-side.
- Optional `ARC_API_KEY` and `CORS_ORIGIN`.

## Important limitations

Automated testing cannot certify full WCAG conformance. Keyboard behavior, VoiceOver/TalkBack experience, cognitive usability and contextual criteria still require manual review.

A remote anti-bot/security challenge must be completed by an authorized human or allowlisted by the website owner. ArcTool should not be used to bypass access controls.
