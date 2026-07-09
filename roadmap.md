# Roadmap

## Goal

Grow the extension as a **browser-side OWASP security assessment** tool with a
**passive analysis engine**, aligned with best practices for cookies and session
management, tokens/JWTs, storage secrets, security headers, and transport —
always staying within what the browser can observe (no backend, no external
calls). The assessment never mutates the inspected site; cookie editing in the
Cookies tab is the one explicit, user-initiated exception.

Remaining growth directions: comparative review (snapshot/diff), CI reporting
(SARIF), and configurability — while keeping the code pure, tested, and
publishable as an open-source project across Chrome, Firefox, and Edge.

## Current state (v0.5.0)

Already available:

- **passive assessment engine**: it observes only and no longer modifies
  request/response headers (the `declarativeNetRequest` editing feature and its
  permissions were removed). Cookie editing (create/edit/delete/clear-all) stays
  as an explicit, user-initiated tool in the Cookies tab
- **cross-browser** builds for Chrome, Firefox, and Edge (MV3), with a Firefox
  manifest transform (`scripts/postbuild-firefox.mjs`) and a tag-triggered
  release pipeline that packages store artifacts
- local JWT decode and **offline JWT signature verification** via Web Crypto —
  HS/RS/PS/ES with secret/PEM/JWK/JWKS, explicit algorithm (anti
  algorithm-confusion), `alg:none` always rejected (`src/utils/jwtVerify.ts`)
- OWASP Secure Headers assessment with **per-directive CSP analysis**
  (`src/utils/assessment/csp.ts`)
- passive Transport & TLS assessment with additional observable controls
  (`src/utils/assessment/pageResources.ts`): Subresource Integrity, mixed
  content, insecure forms, `ws://` on HTTPS pages, third-party inventory
- **storage secret & PII detection** (`src/utils/detection/`): private keys, API
  keys, high-entropy secrets, embedded credentials/connection strings, and PII
  (email, Luhn cards, phones, IBAN mod-97, Codice Fiscale, EU VAT) — ReDoS-safe
  patterns with checksum validation, and **source-side redaction** so raw
  secrets never leave the page
- unified assessment (Headers, Transport, Cookies, Tokens, Storage subtabs) with
  per-finding filters (severity, actionable-only, text search)
- **self-contained HTML report** export (`src/utils/reportHtml.ts`): one offline
  file, zero JavaScript, escaped output, meta CSP — replaces the previous
  Markdown/JSON exports
- unit tests with `vitest`, GitHub Actions CI, OSS scaffolding

For the chronological detail see `CHANGELOG.md` and the git history.

## Execution principles

For every change:

1. implement the smallest useful change
2. keep assessment/detection logic in pure modules, not in React components
3. keep the assessment passive; cookie editing is the only user-initiated write
4. validate with `npm run test`, `npm run lint`, `npm run eslint`, `npm run build:all`
5. verify manually in the side panel on at least one real site
6. update `README.md`, `ARCHITECTURE.md`, and `CHANGELOG.md` when user behaviour
   or structure changes

## Future directions (by priority)

### 1. Snapshot & Diff

The biggest quality jump for a reviewer, and the primary near-term goal.

- manual snapshots of the observable context: cookies, storage (with detection
  hits), captured headers, and findings — the `ContextSnapshot` type already
  exists (`src/types/index.ts`) to keep current work forward-compatible
- typical points: pre-login, post-login, post-logout
- a pure `diff(a, b)` producing added / removed / changed per category, keyed on
  cookie `name|domain|path`, storage `area|key`, and `finding.id`; the
  `valueFingerprint` recorded on each storage entry detects secret rotation even
  under redaction
- stored in `chrome.storage.session` (memory-only) per origin, capped and
  evicted oldest-first; explicit JSON download for cross-session keeping
- UI as a 6th Assessment subtab plus a "Snapshot" toolbar button; the HTML
  export gains a diff section
- reuses the `filterReport` seam so both sides are scoped before comparison
- finding IDs are already content-derived (no array indices) so diffs do not jitter

### 2. CI reporting: SARIF

- **SARIF 2.1.0** output of findings for pipelines and code scanning; the
  filtered renderer already exists (`filterReport`), so this is mapping severity
  → `level` and `finding.id` → `ruleId` with a rule catalog

### 3. Configurability and product maturity

- an **Options** page: configurable thresholds (cookie/JWT lifetime, what counts
  as "sensitive"), per-detector toggles, and per-origin finding
  suppression/acknowledge (today `ExtensionSettings` exposes only
  `autoDecodeTokens`)
- internationalization (`chrome.i18n`)
- keyboard navigation / ARIA accessibility for the side panel

### Enhancements (backlog, non-blocking)

- CSP: extend analysis to `form-action`, `frame-src`, `worker-src`,
  `connect-src`, `upgrade-insecure-requests`
- SRI on dynamically injected resources (today only DOM at scan time)
- key-aware entropy thresholds for the high-entropy detector
- JWKS via **URL** for signature verification: an explicit exception to the
  "no network" principle, so opt-in and off by default

## Out of scope (browser-side only)

Not to be introduced, because it requires TLS-layer access or network calls and
would break the project's core principle:

- certificate, cipher-suite, and TLS protocol-version verification
- HSTS preload-list membership, `security.txt`, OCSP/CT
- server-side token revocation or session invalidation
- JWT secret strength and key-management quality
- full formal compliance (e.g. OWASP ASVS)
