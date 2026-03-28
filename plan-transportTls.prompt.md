## Plan: Transport & TLS Module

Add a new `Transport & TLS` subtab under Assessment using the repo's existing MV3 + React + TypeScript + Tailwind patterns. Reuse the current popup -> background -> chrome.storage.session data flow, extend passive collection with DOM-only observations from the content script, and keep TLS/certificate fields explicitly `inconclusive` when browser APIs do not expose reliable data.

**Steps**
1. Extend shared models in `src/types/index.ts` with Transport & TLS report/check types, statuses, confidence/coverage enums, evidence reference shape, standard mapping shape, and message contracts for passive DOM transport observations. This blocks the rest because background, content script, UI, and tests need the shared types first.
2. Add passive collection in `src/content/index.ts` for current-document transport signals only: absolute `http://` links, forms with `http://` action, presence of password fields, and redacted sensitive-looking query/form metadata. Keep it read-only and bounded, then send a new cached result to background using the existing message-router pattern. This depends on step 1.
3. Extend `src/background/index.ts` to cache the new per-tab transport observations in `chrome.storage.session` and expose a retrieval message for the popup, mirroring the existing `STORAGE_SCAN_RESULT` / `GET_STORAGE_TOKENS` pattern. This depends on step 1 and can run in parallel with step 4 once message/type shapes are set.
4. Implement a dedicated pure assessment engine under a new focused utility area, recommended as `src/utils/transportTls/` with small modules for normalization, detectors, summary building, and internal mapping helpers. Export a single entry point such as `buildTransportTlsSection(flows, context)` from an index file so the popup only consumes one report object. This depends on step 1 and can begin before step 3 is finished if it works from typed fixtures.
5. Implement the required detectors inside the transport utility area:
   - `detectHttpsAdoption`: derive observed HTTP vs HTTPS traffic for the selected host, list observed HTTP endpoints, and note HTTP -> HTTPS redirects only when seen in captured flows.
   - `detectSensitiveDataOverEncryptedChannel`: use passive evidence only from observed URLs, existing browser-visible cookie/storage/token hints, and DOM metadata. Mask values and never expose full tokens or secrets.
   - `detectHstsPosture`: parse `Strict-Transport-Security` on HTTPS responses, extract `max-age`, `includeSubDomains`, `preload`, and classify as absent / incomplete / robust / inconclusive.
   - `detectDowngradeSignals`: use observed HTTP fetch/XHR from HTTPS pages, HTTP redirects, HTTP form actions, and absolute `http://` links captured from the current document.
   - `detectCertificateTrust` and `detectTlsPosture`: always return `inconclusive` unless reliable browser-exposed data is actually available from existing context. Do not add active probing or unsupported APIs.
6. Update `src/popup/AssessmentTab.tsx` to add a new enabled `Transport & TLS` subtab that follows the existing assessment loading pattern. Reuse the current local state style with async `chrome.runtime.sendMessage` calls and render a dedicated overview with overall status, 1-2 line summary, coverage, confidence, and six thematic rows/cards for HTTPS adoption, Sensitive flows, HSTS, Downgrade signals, Certificate trust, and TLS posture. This depends on steps 1, 3, and 4.
7. Keep the UI structured by theme and progressive disclosure: overview first, then expandable detail sections per check with separate `Observed facts`, `Assessment`, and `Guidance` blocks. Include evidence references in the detail view, and use cautious language such as `Observed good practice`, `Potential weakness`, `No sensitive unencrypted flow observed in current session`, and `Inconclusive due to limited evidence`.
8. Add unit tests in a new `src/utils/transportTls.test.ts` file using the existing Vitest style with fixture builders similar to `createRequest`. Cover at least: all HTTPS, login/form action over HTTP, token in query string over HTTP, robust HSTS, missing HSTS, partial evidence -> inconclusive, TLS/certificate details unavailable -> inconclusive, and masking of sensitive values. This depends on steps 1 and 4 and should be completed before final UI wiring is considered done.
9. Update `README.md` after implementation to document the new Assessment subtab, passive-only scope, and explicit inconclusive behavior for certificate/TLS posture where browser APIs do not expose those details. This depends on the implemented behavior being stable.
10. Verify with `npm run test`, `npm run lint`, `npm run eslint`, and `npm run build`. If DOM observation adds runtime constraints, also perform a manual popup check on one HTTPS page and one HTTP page to confirm the new subtab populates and that sensitive values are redacted.

**Relevant files**
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\manifest.json` — confirm the current MV3 shape and that no new framework or privileged API is introduced.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\package.json` — existing stack, scripts, and no-new-dependency constraint.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\background\index.ts` — existing per-tab `chrome.storage.session` cache pattern and popup message router to reuse for transport observations.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\content\index.ts` — existing passive, bounded content-script scan pattern to extend with DOM transport observations.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\popup\Popup.tsx` — confirms Assessment remains within the popup, with no side panel or devtools panel in the repo.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\popup\AssessmentTab.tsx` — existing subtab model and current header-assessment rendering pattern to mirror.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\types\index.ts` — shared message, cache, and report types that should be extended instead of creating parallel ad-hoc models.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\utils\assessment.ts` — useful reference for pure detection helpers, summary builders, and evidence/remediation wording patterns, but avoid further bloating this file for the new module.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\src\utils\assessment.test.ts` — fixture and assertion style to reuse for transport tests.
- `c:\Users\ffavara\Documents\Sviluppo\owasp-web-security-inspector\README.md` — document the new module after implementation.

**Verification**
1. Run `npm run test` and ensure new transport utility tests cover the required passive-only scenarios and redaction behavior.
2. Run `npm run lint` and `npm run eslint` to catch strict TypeScript and unused-symbol regressions from the new types/messages.
3. Run `npm run build` to validate the MV3 bundle after message/type/content-script updates.
4. Manually verify the popup on an HTTPS site with HSTS and on an HTTP page, checking the new Assessment subtab overview, counters, detail expansion, and `inconclusive` fallback for unavailable certificate/TLS details.
5. Manually verify that no full sensitive token or secret is shown in overview or detail evidence.

**Decisions**
- Include passive DOM observation in the content script for current-page form actions, password field presence, and absolute `http://` links.
- Implement `Transport & TLS` as a new Assessment subtab, not as a subsection of Headers.
- Keep certificate trust and TLS posture conservative: if the existing browser-observable context cannot prove them, return `inconclusive` instead of synthesizing data.
- Reuse the current popup local-state and background cache approach; do not introduce React context, Zustand, Redux, or another UI framework.
- Prefer a dedicated utility folder for Transport & TLS over growing `src/utils/assessment.ts`, because the module has multiple detectors and explicit mapping metadata.
- Do not include WSTG, ASVS, or OWASP document references in the plugin UI or module data model.

**Further Considerations**
1. Sensitive-flow detection can only be partial in this extension because current APIs do not expose request bodies or request headers. The implementation should state that coverage is limited to browser-observed URLs, DOM metadata, cookies, storage, and captured response context.
2. Redirect classification should rely only on actually observed flows, likely using response status codes plus `Location` headers where available. If the current cache misses redirect chains due to browser behavior, the result should degrade to `inconclusive` rather than overstate certainty.
3. No side panel or devtools panel exists in this repo; the module should remain popup-based unless the product direction changes later.
