# OWASP Web Security Inspector

[![CI](https://github.com/Clipperone/owasp-web-security-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/Clipperone/owasp-web-security-inspector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

OWASP Web Security Inspector is a browser-side extension for OWASP-inspired security review of cookies, JWTs, storage secrets, and HTTP headers, with a built-in cookie editor. It runs on **Chrome, Firefox, and Edge** (Manifest V3).

Its **security assessment is passive**: it observes what the browser exposes and never probes endpoints, forces requests, or modifies requests, responses, or headers. The **Cookies tab** additionally offers explicit, user-initiated cookie management (create, edit, delete). Findings help reviewers compare what an application exposes in the browser against OWASP guidance, especially the OWASP Cheat Sheet Series and the broader OWASP Top 10 awareness model.

## What This Extension Is For

Use it to review what the browser can actually observe and store during an application flow:

- cookies and their session-related attributes
- tokens and JWTs found in cookies or web storage
- secrets and PII (private keys, API keys, credentials, cards, IBANs, tax codes) exposed in web storage
- response headers captured from the active tab context
- an aggregated assessment report you can export as a self-contained HTML file for QA or release review

The focus is practical browser-side verification of common OWASP-aligned best practices, such as:

- `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, and cookie lifetime choices
- non-persistent session cookies where appropriate
- avoiding risky token storage patterns in `localStorage`, `sessionStorage`, and IndexedDB
- security header posture such as CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP, COEP, CORP, and Permissions-Policy
- logout-related cleanup signals such as `Cache-Control: no-store` and `Clear-Site-Data`
- conservative CORS behavior for browser-consumed responses

## What It Does Not Prove

This extension is intentionally browser-side only. It surfaces useful findings and best-practice gaps, but it does not prove full application security or compliance. It does not verify, for example:

- token revocation or session invalidation on the backend
- JWT signature trust beyond the opt-in local verification in the Tokens tab
- secret strength or key management quality
- session rotation correctness on the server
- full formal compliance with OWASP ASVS or other standards

## Main Capabilities

### Assessment

- Incremental assessment workspace with a second-level tab model: `Headers`, `Transport`, `Cookies`, `Tokens`, `Storage`.
- **Headers** validates the active page response against the OWASP Secure Headers project semantics, grouped into collapsible `Required`, `Advisory`, and `Should Be Absent` sections with per-section `Fail`/`Warn`/`Pass` counters. Missing required headers are `Fail`; present-but-noncompliant values are `Warn`. Deep per-directive **Content-Security-Policy** analysis flags `unsafe-inline`/`unsafe-eval`, wildcard and insecure-scheme sources, missing `object-src`/`base-uri`/`frame-ancestors`/`default-src`, and recognizes Trusted Types, violation reporting, nonce/hash mitigation, and report-only mode.
- **Transport & TLS** is a passive browser-side review of HTTPS adoption, sensitive-flow exposure, HSTS posture, downgrade signals, and transport evidence quality — using only observed requests, response headers, storage hints, and current-document DOM metadata. It never probes endpoints or forces requests. It also covers **Subresource Integrity**, **mixed content**, insecure **`ws://` WebSockets**, and a best-effort **third-party origin/cookie inventory** (eTLD+1 heuristic).
- **Cookies / Tokens / Storage** surface the cookie, JWT/opaque-token, and web-storage findings produced by the same engine, each in its own subtab.
- **Local JWT signature verification** — the Tokens tab includes an opt-in "Verify signature" panel that runs entirely in the browser via the Web Crypto API (HS/RS/PS/ES; explicit algorithm choice to block algorithm-confusion; always rejects `alg: none`). No key material leaves the browser.
- Per-finding **filters** (minimum severity, "actionable only", text search) drive both the on-screen view and the export, so what you see is what you export.
- The assessment **re-scans automatically** when the active tab navigates (full load or SPA route change) or when you switch tabs — no extra permission.

### Storage secret & PII detection

- Beyond JWT/opaque-token hints, storage values are scanned by a ReDoS-safe detection engine for **private keys** (PEM), **provider API keys** (AWS, GitHub, Google, Slack, Stripe, OpenAI), **high-entropy secrets**, **embedded credentials** (Basic auth, `user:pass@` URLs, database connection strings, password fields in JSON/query values), and **PII** (emails, Luhn-valid payment cards, phone numbers, checksum-valid IBANs, Italian Codice Fiscale, EU VAT numbers).
- Detected secrets and PII are **redacted at the source** (in the content script) before anything leaves the page, so raw secrets are never cached or shown — except a whole-value JWT, which the Tokens tab needs intact to decode.

### Cookies

- Inspect and filter cookies for the active page, with `Secure`/`HttpOnly`/session/JWT badges.
- Create, edit, and delete cookies, or clear all cookies for the site — with validation for `SameSite=None`, `__Secure-`/`__Host-` prefixes, and partitioned cookies.
- Export the visible cookies as `curl` or Netscape `cookies.txt`.
- One-click jump from a cookie JWT value to the Tokens tab.

### Tokens

- Real-time JWT decode with `exp`/`nbf` indicators and manual token risk preview.
- Storage scan and manual rescan of the active tab.

### Response inspection

- Capture of document, iframe, and XHR responses observed from the active tab, with a security summary and missing-vs-weak OWASP header checks for the primary response.

### HTML report export

- One click produces a single **self-contained HTML file** (`owasp-assessment-<host>-<timestamp>.html`) generated entirely in the browser — no backend, no external requests. It inlines all styling, contains **zero JavaScript**, carries a restrictive `Content-Security-Policy` meta tag, and escapes every value, so it is safe to open and share. It honours the active filters and carries a stable `schemaVersion`.

## Runtime And Stack

- Manifest V3 (Chrome, Firefox, Edge)
- Side panel UI via `chrome.sidePanel` (Chromium) / `sidebar_action` (Firefox)
- React 18, TypeScript 5 (strict), Vite 5 with `@crxjs/vite-plugin`, Tailwind CSS 3

## Requirements

- Node.js 20+ and npm 10+
- Chrome/Edge 114+ (required by the side panel) or Firefox 115+

## Development Workflow

```bash
npm install
```

Recommended local validation sequence:

```bash
npm run test
npm run lint
npm run eslint
npm run build:all
```

Build a single target:

```bash
npm run build:chrome    # → dist/chrome  (also used by Edge)
npm run build:firefox   # → dist/firefox (Chromium manifest + Firefox transform)
```

Load the unpacked extension:

- **Chrome / Edge**: open `chrome://extensions` (or `edge://extensions`), enable Developer mode, and "Load unpacked" from `dist/chrome`.
- **Firefox**: open `about:debugging` → This Firefox → "Load Temporary Add-on" and pick `dist/firefox/manifest.json`. On first use, grant site access when the panel prompts.

## Packaging & Release

```bash
npm run build:all       # build Chrome/Edge + Firefox
npm run package         # → artifacts/owasp-web-security-inspector-<version>-{chrome,edge,firefox}.zip
```

Version bump + tag (keeps `package.json`, `package-lock.json`, and `manifest.json` in sync):

```bash
npm run release:patch
npm run release:minor
npm run release:major
git push --follow-tags
```

Pushing a `v*` tag triggers the **Release** GitHub Action, which builds all three targets, packages them, and attaches the zips to a GitHub Release. Store uploads (Chrome Web Store, Firefox AMO, Edge Add-ons) are provided as commented, credential-gated steps in `.github/workflows/release.yml`.

> **Firefox add-on id**: `scripts/postbuild-firefox.mjs` sets `browser_specific_settings.gecko.id`. This id is immutable once published to AMO — set it to your own before the first submission.

## Permissions

- `cookies`: read cookies for inspection, and write them for the user-initiated Cookies tab editor
- `storage`: persist local settings and cache observations in the ephemeral session store
- `activeTab`: resolve the active page context
- `webRequest`: capture response headers for inspection (non-blocking, observation only)
- `sidePanel`: render the review UI in the browser side panel (Chromium)
- `host_permissions: <all_urls>`: observe across sites (optional and user-granted on Firefox)

The extension holds **no** request/response modification capability; cookie writes happen only when you act in the Cookies tab.

## Privacy

- All processing stays in the browser. No backend or external API is used for token decoding, assessment logic, detection, or report generation.
- Cached observations live in `chrome.storage.session` (memory-only, cleared when the browser closes).
- Detected storage secrets and PII are redacted before they leave the page.

## OWASP References

- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP Top 10: https://owasp.org/Top10/2025/
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP HTTP Security Response Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Content Security Policy Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- OWASP HTTP Strict Transport Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component map and message flow, and [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
