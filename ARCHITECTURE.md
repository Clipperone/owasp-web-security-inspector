# Architecture

OWASP Web Security Inspector is a Manifest V3 Chrome extension that inspects and
assesses browser-observable session security: cookies, JWTs, web-storage tokens,
`Set-Cookie` delivery, HTTP security headers, and transport posture. All logic
runs locally in the browser — there is no backend and no external API.

## High-level layout

```
manifest.json            MV3 manifest (read directly by @crxjs/vite-plugin)
src/
  background/index.ts    Service worker: lifecycle, DNR rule sync, message router,
                         response-header cache, side-panel behaviour
  content/index.ts       Content script: scans web storage and observes transport
                         signals in the page, reports them to the background
  sidepanel/             React UI served through the chrome.sidePanel API
    Panel.tsx            Tab shell (Assessment, Cookies, Response Headers,
                         Modify Headers, Tokens)
    AssessmentTab.tsx    Assessment workspace with per-category subtabs
    *Tab.tsx             Inspector/editor surfaces
    FindingCard.tsx      Shared rendering for AssessmentFinding[]
    ui/                  Design system primitives (see below)
  utils/
    assessment/          Pure assessment engine, split by concern
    transportTls/        Passive transport & TLS assessment
    report.ts            Unified Markdown/JSON report across all categories
    jwtUtils.ts          Local JWT decode/validation (no external library)
    jwtVerify.ts         Local JWT signature verification via Web Crypto
    cookieUtils.ts       Cookie URL/id helpers
    headerUtils.ts       Header-rule validation helpers
    exporter.ts          Cookie export (curl, Netscape cookies.txt)
    storageUtils.ts      Typed wrapper around chrome.storage.local
  types/index.ts         Shared contracts: messages, assessment models, rules
```

## Surfaces and message flow

The UI runs inside the **side panel** (opened when the toolbar icon is clicked,
via `chrome.sidePanel.setPanelBehavior` in the background). It never calls
privileged Chrome APIs directly; instead it sends typed messages to the
background service worker:

```
side panel  ──sendMessage──▶  background  ──▶  chrome.cookies / DNR / tab info
content     ──sendMessage──▶  background  (cached per tab)  ──▶  side panel (on demand)
```

Key message types live in `src/types/index.ts` (`MessageType`). Examples:
`GET_COOKIES`, `GET_TAB_HEADERS`, `GET_STORAGE_TOKENS`, `RUN_STORAGE_SCAN`,
`GET_TRANSPORT_OBSERVATIONS`, and the `*_HEADER_RULE` rule-management messages.

The background captures response headers via `webRequest` and applies request/
response header overrides via `declarativeNetRequest` (no blocking webRequest).

## The assessment engine (`src/utils/assessment/`)

A folder of pure, side-effect-free modules behind an `index.ts` barrel. The
public API is unchanged whichever module a function lives in:

- `shared.ts` — finding factories, URL/header helpers, `getPrimaryRequest`
- `classification.ts` — cookie/token sensitivity classification
- `setCookie.ts` — `Set-Cookie` parsing and response-side analysis
- `headers.ts` — OWASP Secure Headers validator checks (`getOwaspHeaderAssessment`)
- `csp.ts` — per-directive Content-Security-Policy analysis (`assessCsp`)
- `pageResources.ts` — SRI, mixed content, insecure forms, `ws://`, and
  third-party inventory (`assessSubresourceIntegrity`, `assessMixedContent`,
  `assessWebSockets`, `assessThirdParties`); `site.ts` provides the eTLD+1 heuristic
- `cookies.ts` — cookie-jar findings and summaries
- `tokens.ts` — JWT/opaque token risk findings and summaries
- `findings.ts` — `assessHeaders` (CORS/cache/disclosure), `buildAssessmentFindings`
  (the aggregate, deduped, severity-sorted list) and `getFindingCounts`

Every finding is an `AssessmentFinding` tagged with a `category`
(`cookies` | `tokens` | `storage` | `headers` | `transport`) and a `severity`.
The Assessment subtabs render `buildAssessmentFindings(...)` filtered by category;
nothing is computed in React components.

`report.ts` assembles the header report, transport report, and findings into a
single `FullAssessmentReport` and serializes it to Markdown or JSON, so exports
stay consistent with what the UI shows. The report carries a stable
`schemaVersion` (`REPORT_SCHEMA_VERSION`) for CI consumers, and `filterFindings`
/`filterReport` scope the exported findings by minimum severity, category,
actionability (`isActionableFinding`), and text search — the same `ReportFilter`
that drives the Assessment tab's posture bar and filters, and the seam a future
snapshot diff will reuse. `exporter.ts` adds `downloadTextFile`/`buildReportFilename`
for saving the report to a file from the side panel (Blob download, no extra
permission).

`jwtVerify.ts` verifies JWT signatures locally with the Web Crypto API
(`crypto.subtle`). It takes the algorithm from an explicit caller choice (never
the token header) to defeat algorithm-confusion, always rejects `alg: none`, and
accepts a shared secret, SPKI PEM key, JWK, or pasted JWKS — no network calls.

## UI design system (`src/sidepanel/ui/`)

A small set of primitives gives every surface one visual language:

- `status.ts` — the single source of truth mapping each status/severity union to
  a shared `Tone` and its Tailwind classes (replaces per-view colour strings)
- `StatusBadge`, `Section`, `DisclosureCard`, `Field`, `Chevron`, `EmptyState`

Styling is Tailwind-only; `index.css` contains just the Tailwind directives.

## Scope and non-goals

Browser-side only. It surfaces best-practice gaps from what the browser can
observe. It does **not** verify backend session invalidation, JWT signature
trust, secret strength, server-side rotation, or formal OWASP ASVS compliance.
JWT handling is intentionally local and dependency-free.
