# ArcTool Accessibility Auditor

**© 2026 rantunano. All rights reserved. Proprietary software.**

ArcTool is a mobile-first accessibility auditor designed to inspect a web page piece by piece and prioritize the most important accessibility failures.

## What v2 scans

- Main DOM and all browser-accessible iframes (up to configurable limits)
- axe-core WCAG-oriented automated rules per frame
- Text, headings, links, buttons, inputs, labels, images, forms, landmarks and ARIA roles
- Accessible names and affected HTML/selectors for each violation
- Custom checks for iframe titles, unnamed controls/links, target size, heading jumps, non-semantic clickable elements and autoplay media
- Per-element inventory with frame attribution
- Critical → Serious → Moderate → Minor prioritization
- JSON and HTML reports

The scanner uses **Playwright + Chromium + axe-core**. Running the scanner in a real browser process is necessary because GitHub Pages alone cannot inspect arbitrary third-party DOMs or cross-origin frames.

## Architecture

```text
iPhone / Web UI
      |
      v
POST /api/scan
      |
Node/Express scanner
      |
Playwright Chromium
  |         |
main DOM   iframes
  |         |
axe-core + ArcTool custom rules
      |
prioritized report (JSON / HTML)
```

## Run locally

```bash
npm install
npx playwright install --with-deps chromium
npm start
```

Open `http://localhost:3000`.

## Run a URL audit from the command line

```bash
npm run scan -- https://example.com
```

The report is saved as `arc-report.json`.

## Run from GitHub Actions

Open **Actions → Audit URL with ArcTool → Run workflow**, enter a public URL, then download the `arc-accessibility-report` artifact when the job finishes.

## Deploy the full scanner

GitHub Pages can host `index.html`, but the Playwright scanner needs a Node/container runtime. Deploy this repository to a container-capable host using the included `Dockerfile`, then in ArcTool's **Configuración del scanner** set the backend URL.

Environment variables:

- `PORT` (default `3000`)
- `ARC_API_KEY` optional API key
- `CORS_ORIGIN` comma-separated allowed web origins
- `MAX_CONCURRENT_SCANS` default `2`
- `SCAN_TIMEOUT_MS` default `45000`
- `MAX_FRAMES` default `30`
- `MAX_FINDINGS` default `5000`
- `MAX_INVENTORY` default `5000`

## Security / stability safeguards

- Blocks localhost, private IP ranges and embedded URL credentials to reduce SSRF risk
- Blocks redirects/assets that resolve to private networks
- Navigation and overall scan timeouts
- Limits frames, findings, inventory size and concurrent scans
- Browser is closed in `finally` paths to reduce leaks/crashes
- API request body is size-limited

## Testing

```bash
npm run check
npm test
```

GitHub CI runs syntax checks and unit tests on pushes and pull requests.

## Important limitation

Automated accessibility testing cannot certify complete WCAG conformance. Keyboard behavior, VoiceOver/TalkBack experience, cognitive usability and some visual/contextual criteria still require manual testing.

## License

Proprietary. See `LICENSE.txt`.
