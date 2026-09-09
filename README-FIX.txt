ArcTool V3 - Browserless compatibility fix

Replace only these two files in branch v3-web-app:
- package.json
- Dockerfile

Do NOT replace server.js. Keep the current Hybrid server.js.
Do NOT change BROWSERLESS_TOKEN or SESSION_TTL_MS (120000).

Reason:
Browserless' current compatibility notes add support through Playwright 1.61, while ArcTool was running Playwright 1.63.0. The interactive LiveURL worked, but Playwright 1.63 crashed with "Duplicate target" when Browserless LiveURL attached to the same CDP session.

This fix pins both the Node package and the Playwright Docker image to 1.61.1.
