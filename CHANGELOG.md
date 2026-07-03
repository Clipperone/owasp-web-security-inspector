# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-07-04

### Added

- **Triage & readability (roadmap M1).** A synthetic **posture bar** (High · Medium ·
  Low · Info) sits atop the Assessment tab, plus per-finding **filters**: minimum
  severity, an "Actionable only" toggle (`isActionableFinding` = severity ≠ info),
  and a text **search** across finding fields. The filters drive both the displayed
  lists and the exported report, so the posture counts and the report always agree
  (`filterFindings`/`filterReport` in `src/utils/report.ts`).
- **Report download to file (roadmap M2).** A new **Download** button saves the
  report as `owasp-assessment-<host>-<timestamp>.md/.json` via a Blob download
  (`downloadTextFile`/`buildReportFilename` in `src/utils/exporter.ts`) — no new
  permission.
- **Automatic re-scan on navigation (roadmap M2).** The side panel listens to
  `chrome.tabs.onUpdated`/`onActivated` and refreshes the assessment when the active
  tab navigates (full load or SPA route change) or when the user switches tabs — no
  `webNavigation` permission required.
- **IndexedDB token scanning (roadmap M2).** The content script now also scans the
  origin's IndexedDB (Chrome 118+, graceful fallback), surfacing token-like values as
  `high`-severity storage findings. The Storage meta line shows a Local · Session ·
  IDB breakdown.
- **JWT `nbf` and cookie `Partitioned`/CHIPS checks (roadmap M2).** A not-yet-valid
  JWT (`nbf` in the future) raises an info finding and a "Not yet valid" badge
  (`checkNotBefore` in `src/utils/jwtUtils.ts`); a cross-site (`SameSite=None`) cookie
  without the Partitioned attribute raises a low finding, for both the live cookie jar
  and observed `Set-Cookie` responses.

### Changed

- The Assessment export replaces the separate severity-scope selector with the shared
  triage filters: **Copy** and **Download** honour the active filters. `MinSeverity`
  gains a `low` level.

## [0.3.0] - 2026-07-03

### Added

- **Deep Content-Security-Policy analysis (roadmap M2).** A new per-directive
  analyzer (`src/utils/assessment/csp.ts`, `assessCsp`) replaces the previous
  presence-of-`unsafe` heuristic. It raises dedicated findings for
  `unsafe-inline`/`unsafe-eval`, wildcard and `http:`/`data:`/`blob:` script
  sources, and missing `object-src`/`base-uri`/`frame-ancestors`/`default-src`,
  recognizes nonce/hash and `strict-dynamic` mitigation, flags Trusted Types and
  violation reporting as positive signals, and downgrades `Report-Only` policies.
  Findings surface in `Assessment > Headers` and the exported report.
- **Local JWT signature verification (roadmap M4).** The Tokens tab now offers an
  opt-in "Verify signature" panel powered by the Web Crypto API
  (`src/utils/jwtVerify.ts`). It supports HS/RS/PS/ES algorithms with a pasted
  HMAC secret, SPKI PEM public key, JWK, or JWKS — all offline, no network calls.
  The verification algorithm is chosen explicitly (never from the token header)
  to block algorithm-confusion attacks, and `alg: none` is always rejected. This
  is clearly distinguished from decoding.
- **Advanced reporting (roadmap M4).** The exported report now carries a stable
  `schemaVersion` (`1.0`) for CI/issue-template reuse, and the Assessment tab
  export lets you scope findings by severity (All / High + Medium / High only) in
  either Markdown or JSON (`filterFindings`/`filterReport` in
  `src/utils/report.ts`). SARIF output is deferred to a later milestone.
- **Additional browser-observable controls (roadmap M5).** New `transport`
  findings (`src/utils/assessment/pageResources.ts`) surface under the Transport
  tab: cross-origin `<script>`/`<link>` without Subresource Integrity, active and
  passive mixed content, sensitive forms submitting over HTTP, insecure `ws://`
  WebSockets on HTTPS pages, and a best-effort third-party origin/cookie
  inventory. Backed by a new content-script subresource scan and a background
  `webRequest.onBeforeRequest` WebSocket listener — no new permissions.

### Changed

- The generic missing/weak-header check no longer reports Content-Security-Policy;
  CSP is now owned entirely by the dedicated per-directive analyzer to avoid
  duplicate or contradictory findings.
- The Assessment tab's two `Copy MD`/`Copy JSON` buttons are replaced by a compact
  format + severity-scope selector with a single `Copy` action.

## [0.2.0] - 2026-06-30

### Changed

- **UI now runs in the Chrome side panel** instead of the toolbar popup, giving
  a tall, resizable, persistent surface for reviewing findings while browsing.
  Requires Chrome 114+ (`minimum_chrome_version`).
- **Unified Assessment tab.** The Cookies, Tokens, and Storage subtabs are now
  live — they surface findings the engine already produced — alongside Headers
  and Transport & TLS. The Headers subtab also shows CORS/cache/disclosure
  findings.
- **Single exported report.** `Copy MD` / `Copy JSON` now export one report
  covering every category (headers, transport, cookies, tokens, storage).
- Introduced a shared UI design system (`src/sidepanel/ui/`) with one
  status/severity → tone map and reusable primitives, replacing the duplicated
  colour helpers across views.

### Internal

- Split the 1700+ line `assessment.ts` into focused modules under
  `src/utils/assessment/` (no behaviour change; public API preserved).
- Added unified reporting in `src/utils/report.ts`.
- Added project scaffolding for open-source publishing: `LICENSE` (MIT),
  `CONTRIBUTING.md`, `ARCHITECTURE.md`, `.gitattributes`, and CI on GitHub
  Actions.

## [0.1.0]

- Initial release: cookie/token/header inspection and editing, OWASP Secure
  Headers assessment, Transport & TLS assessment, and Markdown/JSON export.
