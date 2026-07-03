# OWASP Web Security Inspector

OWASP Web Security Inspector is a Chrome extension for browser-side inspection, editing, and security assessment of cookies, JWTs, storage tokens, and HTTP headers.

The project started as a developer-oriented editor and inspector. It now also includes an assessment workflow oriented to OWASP-inspired browser-observable review and secure-by-default best practices for session handling, token storage, `Set-Cookie` delivery, browser hardening headers, caching, and cross-origin behavior.

Its findings are intended to help reviewers compare what an application exposes in the browser against OWASP guidance, especially from the OWASP Cheat Sheet Series and the broader OWASP Top 10 awareness model.

## What This Extension Is For

Use it when you want to review what the browser can actually observe and store during an application flow:

- cookies and session-related attributes
- tokens and JWTs found in cookies or web storage
- response headers captured from the active tab context
- request and response header overrides for debugging
- an aggregated assessment report that can be exported for QA or release review

The focus is practical browser-side verification of common OWASP-aligned best practices, such as:

- `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, and cookie lifetime choices
- use of non-persistent session cookies where appropriate
- avoiding risky token storage patterns in `localStorage` and `sessionStorage`
- security header posture such as CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP, COEP, CORP, and Permissions-Policy
- logout-related cleanup signals such as `Cache-Control: no-store` and `Clear-Site-Data`
- conservative CORS behavior for browser-consumed responses

## What It Does Not Prove

This extension is intentionally browser-side only. It helps surface useful findings and best-practice gaps, but it does not prove full application security or compliance.

It does not verify, for example:

- token revocation or session invalidation on the backend
- JWT signature trust unless the payload is inspected structurally only
- secret strength or key management quality
- session rotation correctness on the server
- full formal compliance with OWASP ASVS or other standards

## Main Capabilities

### Assessment

- Incremental assessment workspace with a second-level tab model, starting from `Assessment > Headers`.
- `Assessment > Transport & TLS` provides a passive browser-side review of HTTPS adoption, sensitive flow exposure, HSTS posture, downgrade signals, and transport evidence quality for the current session.
- The Transport & TLS module uses only browser-observed requests, response headers, storage hints, and current-document DOM metadata such as HTTP form actions or absolute HTTP links. It does not probe endpoints, force requests, or simulate attacks.
- `Assessment > Headers` validates the active page response against the OWASP Secure Headers project and the public validator test suite semantics.
- Deep per-directive **Content-Security-Policy** analysis surfaces dedicated findings for `unsafe-inline`/`unsafe-eval`, wildcard and insecure-scheme script sources, missing `object-src`/`base-uri`/`frame-ancestors`/`default-src`, and recognizes Trusted Types, violation reporting, nonce/hash mitigation, and report-only mode (aligned with the OWASP CSP Cheat Sheet).
- The Headers view is grouped into collapsible `Required`, `Advisory`, and `Should Be Absent` sections, each with per-section `Fail`, `Warn`, and `Pass` counters.
- Missing required headers are reported as `Fail`, while required headers that are present but use a value different from the OWASP recommendation are reported as `Warn`.
- `Advisory` checks for disclosure headers such as `Server` and `X-Powered-By` escalate to `Fail` when the observed value exposes an explicit version number, and remain `Warn` when they disclose only the product name.
- Exact header values are still checked where the OWASP validator expects exact matches, while `Clear-Site-Data` remains conditional on observing a logout-like response in the captured traffic.
- `Assessment > Cookies`, `Assessment > Tokens`, and `Assessment > Storage` surface the cookie, JWT/opaque-token, and web-storage findings produced by the same engine, each in its own subtab.
- **Local JWT signature verification** — the Tokens tab includes an opt-in "Verify signature" panel that runs entirely in the browser via the Web Crypto API. Paste an HMAC secret, an SPKI PEM public key, a JWK, or a JWKS; it supports HS/RS/PS/ES algorithms, chooses the algorithm explicitly to prevent algorithm-confusion attacks, always rejects `alg: none`, and clearly separates "decoded" from "signature verified". No key material ever leaves the browser.
- The exported report is emitted with a stable `schemaVersion` for CI/issue-template reuse, and can be scoped by severity (All / High + Medium / High only) in Markdown or JSON.
- Additional browser-observable controls under `Assessment > Transport`: **Subresource Integrity** (cross-origin `<script>`/`<link>` without `integrity`), **active/passive mixed content** and sensitive forms submitting over HTTP, insecure **`ws://` WebSockets** on HTTPS pages, and a best-effort **third-party origin/cookie inventory** (informational, using an eTLD+1 heuristic).

### Cookies

- Inspect, create, edit, delete, and export cookies for the active page.
- Validation for `SameSite=None`, `__Secure-*`, `__Host-*`, and partitioned cookies.
- Export as `curl` or Netscape `cookies.txt`.
- One-click jump from cookie JWT values to the Tokens tab.

### Tokens

- Real-time JWT decode.
- Expiration indicators for `exp`.
- Storage scan and manual rescan of the active tab.
- Manual token risk preview for JWT input.

### Headers

- Request and response header rule editing via Chrome `declarativeNetRequest`.
- Inline update, enable/disable, delete, and drag-and-drop reorder.
- Per-rule scope with `Global scope` or `Scoped domain`.
- Quick templates for common cases such as bearer auth and CORS debugging.
- Export enabled request-side rules as `curl -H` arguments.

### Response Inspection

- Capture of `DOC`, `IFR`, and `XHR` responses observed from the active tab.
- Security summary for the primary response.
- Missing vs weak OWASP-relevant header checks, including distinction between absent required headers and present-but-noncompliant values.
- Passive transport evidence used by the Transport & TLS assessment, including observed HTTP versus HTTPS requests and document-level HTTP references when available.

## Runtime And Stack

- Chrome Extension Manifest V3
- Side panel UI via the `chrome.sidePanel` API
- React 18
- TypeScript 5 with strict mode
- Vite 5 with `@crxjs/vite-plugin`
- Tailwind CSS 3

## Requirements

- Node.js 20+
- npm 10+
- Chrome 114+ (required by the side panel)

## Development Workflow

Install dependencies:

```bash
npm install
```

Recommended local validation sequence:

```bash
npm run test
npm run lint
npm run eslint
npm run build
```

Useful commands:

```bash
npm run dev
npm run generate-icons
```

Load the unpacked extension from `dist/` in `chrome://extensions` with Developer mode enabled, then click the toolbar icon to open the side panel.

## Release Flow

The repository includes an automated version bump and tagging flow for release preparation.

Available commands:

```bash
npm run release:patch
npm run release:minor
npm run release:major
```

Each release command:

- checks that the git working tree is clean
- bumps the version in `package.json`, `package-lock.json`, and `manifest.json`
- runs `npm run lint`, `npm run eslint`, and `npm run build`
- creates a git commit in the form `Release vX.Y.Z`
- creates the git tag `vX.Y.Z`

You can also run the script directly:

```bash
node scripts/release.mjs patch --dry-run
```

Optional flags:

- `--dry-run`
- `--allow-dirty`
- `--skip-checks`
- `--skip-tag`

After a successful release:

```bash
git push --follow-tags
```

## Project Structure

```text
manifest.json
package.json
package-lock.json
README.md
roadmap.md
public/
  icons/
scripts/
  generate-icons.mjs
  release.mjs
src/
  background/
    index.ts
  content/
    index.ts
  sidepanel/
    Panel.tsx
    AssessmentTab.tsx
    CookieEditorForm.tsx
    CookieTab.tsx
    CurrentHeadersTab.tsx
    FindingCard.tsx
    HeaderRuleRow.tsx
    HeadersTab.tsx
    TokensTab.tsx
    TransportTlsPanel.tsx
    index.css
    index.html
    main.tsx
    useDismissOnOutsideClick.ts
    ui/                 # shared design system primitives
  types/
    index.ts
  utils/
    assessment/         # pure assessment engine, split by concern
    transportTls/       # passive transport & TLS assessment
    assessment.test.ts
    cookieUtils.ts
    exporter.ts
    headerUtils.ts
    index.ts
    jwtUtils.test.ts
    jwtUtils.ts
    report.ts           # unified Markdown/JSON report across all categories
    storageUtils.ts
```

## Architectural Notes

- `src/background/index.ts`: background service worker for message routing, cached request/header data, and DNR rule coordination.
- `src/content/index.ts`: storage scan logic executed in the page context.
- `src/sidepanel/`: side panel UI, including cookies, headers, tokens, response inspection, and the Assessment tab; `ui/` holds the shared design system.
- `src/utils/assessment/`: pure assessment logic for cookies, `Set-Cookie`, headers, and token heuristics, split into focused modules behind a barrel.
- `src/utils/report.ts`: unified Markdown/JSON report across all assessment categories.
- `src/utils/jwtUtils.ts`: local JWT parsing and structural validation helpers.
- `src/utils/*.test.ts`: pure-module unit tests executed with Vitest.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component map and message flow, and [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## Permissions

- `cookies`: read and write cookies for the active context
- `declarativeNetRequest` and `declarativeNetRequestWithHostAccess`: apply header rules
- `storage`: persist rules and settings
- `activeTab`: resolve the active page context
- `webRequest`: capture response headers for inspection
- `sidePanel`: render the review UI in the browser side panel
- `host_permissions: <all_urls>`: operate across sites

## Privacy

- All processing stays in the browser.
- No backend or external API is used for token decoding, assessment logic, or rule handling.

## OWASP References

The assessment logic and product positioning are informed by OWASP documentation and related best-practice material. Useful starting points:

- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP Top 10: https://owasp.org/Top10/2025/
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP HTTP Security Response Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- OWASP Content Security Policy Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- OWASP HTTP Strict Transport Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP OAuth2 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

These references should be treated as the primary guidance for interpreting findings and deciding whether an observed browser-side configuration is aligned with current OWASP best practices.
