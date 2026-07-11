# Architecture

OWASP Web Security Inspector is a Manifest V3 extension (Chrome, Firefox, Edge)
that inspects and assesses browser-observable session security: cookies, JWTs,
web-storage tokens and secrets, `Set-Cookie` delivery, HTTP security headers,
transport posture, and chatbot / LLM / RAG surfaces. All logic runs locally in
the browser — there is no backend
and no external API. The **security assessment is passive** (it never probes
endpoints, forces requests, or auto-changes anything); the **Cookies tab** is the
one place with explicit, user-initiated writes (`chrome.cookies.set`/`remove`).
Request/response headers are never modifiable.

## High-level layout

```
manifest.json            MV3 (Chromium) manifest, read directly by @crxjs/vite-plugin
src/
  background/index.ts    Service worker: lifecycle/migration, message router,
                         response-header + WebSocket + LLM-prompt-body + scan
                         caches, panel behaviour
  content/index.ts       Content script: scans web storage and observes transport
                         signals in the page (read-only), reports to the background
  sidepanel/             React UI served through the side panel / sidebar
    Panel.tsx            Tab shell (Assessment, Cookies, Response Headers, Tokens)
    AssessmentTab.tsx    Assessment workspace with per-category subtabs
    *Tab.tsx             Inspector surfaces (the Cookies tab also edits cookies)
    FindingCard.tsx      Shared rendering for AssessmentFinding[]
    ui/                  Design system primitives (see below)
  utils/
    assessment/          Pure assessment engine, split by concern
    detection/           Pure secret/PII detection engine (ReDoS-safe)
    transportTls/        Passive transport & TLS assessment
    report.ts            Unified report model + shared label/limitations constants
    reportHtml.ts        Self-contained HTML report renderer (escaped, zero-JS)
    jwtUtils.ts          Local JWT decode/validation (no external library)
    jwtVerify.ts         Local JWT signature verification via Web Crypto
    requestBody.ts       Pure decode + background-side redaction of captured
                         outgoing LLM prompt bodies (CapturedRequestBody)
    cookieUtils.ts       Cookie URL/id helpers
    exporter.ts          Cookie export (curl, Netscape) + file download helper
    storageUtils.ts      Typed wrapper around chrome.storage.local
  types/
    index.ts             Shared contracts: messages, assessment/detection models
    webext.d.ts          Ambient decls for the Firefox-only browser.* surface
scripts/
  postbuild-firefox.mjs  Chromium → Firefox manifest transform
  package.mjs            Store zip packaging (chrome/edge/firefox)
```

## Surfaces and message flow

The UI runs inside the **side panel** on Chromium (opened via
`chrome.sidePanel.setPanelBehavior`) and the **sidebar** on Firefox (the same
page via `sidebar_action`, toggled from `chrome.action.onClicked` →
`browser.sidebarAction.toggle`). For anything needing a URL context or the
background's caches it sends typed messages to the service worker; the Cookies
tab additionally calls `chrome.cookies.set`/`remove` directly for user edits.

```
side panel  ──sendMessage──▶  background  ──▶  chrome.cookies.getAll / tab info
side panel  ──chrome.cookies.set/remove──▶  (direct, user-initiated cookie edits)
content     ──sendMessage──▶  background  (cached per tab)  ──▶  side panel (on demand)
```

Key message types live in `src/types/index.ts` (`MessageType`): `GET_COOKIES`,
`GET_TAB_HEADERS`, `GET_STORAGE_TOKENS`, `RUN_STORAGE_SCAN`,
`GET_TRANSPORT_OBSERVATIONS`, `GET_PAGE_RESOURCES`, `GET_TAB_WEBSOCKETS`,
`GET_TAB_REQUEST_BODIES`, `GET_ACTIVE_TAB_INFO`, and the `*_SCAN_RESULT`
ingestion messages. The background exposes only reads and scan triggers (no
header/request/response mutation); cookie writes bypass it and run directly from
the panel.

The background captures response headers and WebSocket handshakes via
non-blocking `webRequest` observers; it holds no request/response modification
capability. A second non-blocking `onBeforeRequest` observer captures outgoing
request bodies **only for known LLM provider endpoints** (scoped by URL match
patterns). Because these bodies are visible only in the background — the
page-side redaction never runs there — the worker runs them through the same
detection engine (`utils/requestBody.ts` → `runDetectors`) and caches only the
redacted `CapturedRequestBody`, keeping raw secrets/PII out of the clear. This is
the sole observation that reads request bodies; no new permission is required
(`webRequest` + `<all_urls>` already cover it).

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
- `storageSecrets.ts` — maps detection hits to findings (`assessStorageSecrets`)
- `llm.ts` — passive chatbot / LLM / RAG analysis (`assessLlm`): direct
  browser→provider API calls, sensitive data and system prompts in outgoing
  prompt bodies, conversation storage, AI chatbot widgets, and a CSP-inferred
  output-handling surface. Aligned with the OWASP Top 10 for LLM Applications
  2025 (LLM02/LLM07, partial LLM03/LLM05); softer inference-based findings are
  gated behind an `isLikelyLlmApp` signal
- `findings.ts` — `assessHeaders` (CORS/cache/disclosure), `buildAssessmentFindings`
  (the aggregate, deduped, severity-sorted list) and `getFindingCounts`

Every finding is an `AssessmentFinding` tagged with a `category`
(`cookies` | `tokens` | `storage` | `headers` | `transport` | `llm`) and a `severity`.
The Assessment subtabs render `buildAssessmentFindings(...)` filtered by category;
nothing is computed in React components. Finding IDs are content-derived (never
array indices) so they stay stable across re-scans and future snapshot diffs.

## The detection engine (`src/utils/detection/`)

A pure, ReDoS-safe engine shared by the content script and `assessStorageSecrets`:

- `detectors.ts` — the `DetectorSpec[]` catalog. Every pattern is bounded and
  linear-time (literal prefixes plus fixed/`{m,n}` classes, no nested or
  ambiguous quantifiers). Anything needing real disambiguation runs in
  `validate()` as plain code after a cheap prefilter.
- `validators.ts` — Luhn, IBAN mod-97, Codice Fiscale checksum, Shannon entropy,
  UUID, and the FNV-1a fingerprint.
- `redact.ts` — deterministic masks (same input → same output, a prerequisite
  for stable snapshot diffs).
- `engine.ts` — `runDetectors(key, value)`: prefilter → bounded exec → validate →
  overlap resolution (specific/validated detectors beat the generic entropy one)
  → splice masks → `{ hits, redactedValue, wasRedacted }`.

The content script runs `runDetectors` on each stored value and **redacts at the
source**, so raw secrets/PII never leave the page (a whole-value JWT is the sole
exception, kept intact for the Tokens tab). A `valueFingerprint` of the raw value
travels with each entry for change detection under redaction.

## Reporting (`report.ts` + `reportHtml.ts`)

`report.ts` assembles the header report, transport report, and findings into a
single `FullAssessmentReport` and owns the shared label/order/limitations
constants. `filterFindings`/`filterReport` scope findings by minimum severity,
category, actionability (`isActionableFinding`), and text search — the same
`ReportFilter` that drives the Assessment tab's filters, and the seam the future
snapshot diff will reuse.

`reportHtml.ts` renders the report as a single self-contained HTML document. A
tagged-template (`html\`\``) escapes every interpolation unless it is already a
`SafeHtml` from a nested `html` call — there is no exported raw-insertion path.
Untrusted data lands only in element text content; the document has zero
JavaScript and carries a restrictive `Content-Security-Policy` meta tag as
defense-in-depth. `exporter.ts` provides `downloadTextFile`/`buildReportFilename`
for the Blob download (no `downloads` permission).

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
JWT handling is intentionally local and dependency-free. The LLM/RAG review is
likewise limited to browser-observable signals: it does not test prompt-injection
robustness (LLM01), data/model poisoning (LLM04), server-side agent permissions
(LLM06), vector/embedding weaknesses (LLM08), misinformation (LLM09), or
consumption limits (LLM10) — those are server-side and out of scope.
