# Copilot Agent Instructions

Trust these instructions. Only search the codebase if this file is incomplete or wrong.

## Repository Summary

**OWASP Web Security Inspector** is a small single-package, cross-browser extension (Chrome, Firefox, Edge) built with Manifest V3, React, TypeScript, Vite, and Tailwind. It inspects and assesses cookies, JWTs, storage tokens and secrets/PII, `Set-Cookie` responses, and browser-visible HTTP security headers. The **assessment is passive** (no probing, no request/response/header modification); the **Cookies tab** is the one explicit, user-initiated editing surface (`chrome.cookies.set/remove`). All logic is local; there is no backend and no external API.

Validated environment here: Node.js 24.x, npm 11.x. README targets Node.js 20.19+/22.12+ and npm 10+ (Vite 8 requirement).

## Build, Test, Run, Validate

Always run `npm install` before any npm script if `node_modules/` is missing or `package.json` changed. Without dependencies, Vite commands fail.

Working command order validated in this repo:

```bash
npm install
npm run test
npm run lint
npm run eslint
npm run build:all
```

What each command does and what was verified:

- `npm run test`
  Runs `vitest run`. Passes with 12 test files / 150 tests. It emits Vite/CRX deprecation warnings about `esbuild` and `rolldownOptions`, but the command succeeds.
- `npm run lint`
  Runs `tsc --noEmit`. Success is silent.
- `npm run eslint`
  Runs `eslint .`. Success is silent.
- `npm run build` / `npm run build:chrome`
  Runs `vite build --mode chrome` and writes `dist/chrome` (the Chrome/Edge artifact).
- `npm run build:firefox`
  Runs `vite build --mode firefox` then `node scripts/postbuild-firefox.mjs`, writing `dist/firefox` with a Firefox-adjusted manifest (sidebar_action, background.scripts, gecko settings).
- `npm run build:all`
  Builds both targets.
- `npm run package`
  Zips `dist/chrome`/`dist/firefox` into `artifacts/…-{chrome,edge,firefox}.zip` (requires a prior build).
- `npm run dev`
  Runs `vite build --watch` (writes `dist/chrome`). A watch rebuild, not a dev server.

Postcondition for manual testing: load `dist/chrome` (Chrome/Edge) or `dist/firefox` (Firefox `about:debugging`) as an unpacked/temporary extension.

Other scripted steps:

- `node scripts/release.mjs patch --dry-run`
  Fails on a dirty working tree by design: `Working tree is not clean...`.
- `node scripts/release.mjs patch --dry-run --allow-dirty`
  Works and re-runs `npm run lint`, `npm run eslint`, and `npm run build` before reporting the next version/tag.
- `npm run release:patch|minor|major`
  Real release flow. It edits `package.json`, `package-lock.json`, and `manifest.json`, commits, and tags. Do not run unless explicitly asked.
- `npm run generate-icons`
  Mutates files under `public/icons`, writing `<size>px.png` placeholder names that match the icons referenced in `manifest.json`. Replace them with real artwork before publishing.

CI runs `npm ci`, `npm run lint`, `npm run eslint`, `npm run test`, and `npm run build` on push and pull request via `.github/workflows/ci.yml`. Run the same sequence locally before checking in.

## Project Layout

Top-level files that matter most:

- `manifest.json`: MV3 source manifest read directly by `@crxjs/vite-plugin`.
- `package.json`: all scripts and dependency versions.
- `vite.config.ts`: React + CRX plugin, sourcemaps enabled in builds.
- `tsconfig.json`: strict TypeScript, `noUnusedLocals`, `noUnusedParameters`, bundler module resolution.
- `eslint.config.js`: flat ESLint config for TS/React Hooks and Node-side scripts.
- `tailwind.config.js` and `postcss.config.js`: Tailwind setup.
- `README.md`: user-facing product description and release workflow.
- `roadmap.md`: implementation history and expected validation sequence after feature work.

Important source directories:

- `src/background/index.ts`
  MV3 service worker. Owns install/update lifecycle (incl. removing the legacy `headerRules` key), non-blocking `webRequest` response-header + WebSocket caches, content-scan caches, the read-only message router (`GET_COOKIES`, `GET_*`, `RUN_*`), and opening the side panel (Chromium) / sidebar (Firefox).
- `src/content/index.ts`
  Content script injected on all pages (read-only). Scans `localStorage`/`sessionStorage`/IndexedDB via `requestIdleCallback`, runs the detection engine, and redacts secrets/PII at the source before reporting to background.
- `src/sidepanel/`
  React UI. `Panel.tsx` is the tab shell (Assessment, Cookies, Response Headers, Tokens). Main tabs are `AssessmentTab.tsx`, `CookieTab.tsx` (viewer + editor via `CookieEditorForm.tsx`), `CurrentHeadersTab.tsx`, and `TokensTab.tsx`. `ui/` holds the shared design system and `status.ts` tone map.
- `src/types/index.ts`
  Shared source of truth for message contracts, assessment/detection models, token/storage types, snapshot types, and settings. `src/types/webext.d.ts` declares the Firefox-only `browser.*` surface.
- `src/utils/assessment/`
  Pure assessment engine (`shared`, `classification`, `setCookie`, `headers`, `csp`, `cookies`, `tokens`, `storageSecrets`, `pageResources`, `findings`) behind an `index.ts` barrel.
- `src/utils/detection/`
  Pure, ReDoS-safe secret/PII detection engine (`detectors`, `validators`, `redact`, `engine`).
- `src/utils/report.ts` + `src/utils/reportHtml.ts`
  Report model + shared constants, and the self-contained escaped HTML renderer (the only export format).
- `src/utils/storageUtils.ts`
  Typed wrapper around `chrome.storage.local` for settings.
- `src/utils/jwtUtils.ts`
  Local JWT detection/decoding. No external JWT library is used.
- `src/utils/exporter.ts`
  Cookie export (curl/Netscape) and the `downloadTextFile`/`buildReportFilename` helpers.
- `scripts/postbuild-firefox.mjs`, `scripts/package.mjs`
  Firefox manifest transform and store zip packaging (both unit-tested / pure where possible).
- `src/utils/**/*.test.ts`
  Vitest tests for the pure modules; there are no browser E2E tests.

## Architecture Rules That Matter

1. **Passive assessment.** The assessment/detection engine only observes: no `declarativeNetRequest`, no blocking `webRequest`, no header/request/response modification. Cookie editing in `CookieTab.tsx` (`chrome.cookies.set/remove`) is the single intentional write surface; do not add other mutations.
2. **Cross-browser MV3.** Use the promise-flavoured `chrome.*` namespace (works in Firefox). Chrome-only manifest keys are transformed by `scripts/postbuild-firefox.mjs`; update it and its test when you change the manifest.
3. Keep JWT handling local and dependency-free. Do not add `jsonwebtoken`, `jwt-decode`, or similar libraries.
4. Background script errors are intentionally swallowed in catch blocks. Do not add noisy logging there.
5. Detection patterns must be ReDoS-safe: bounded/linear regexes, checksums in `validate()`. Secrets/PII are redacted at the source in the content script.
6. All UI styling is Tailwind-based; build UI from `src/sidepanel/ui/` primitives and the `status.ts` tone map. Do not introduce CSS modules or inline styles.
7. TypeScript is strict. Unused imports, locals, or parameters fail validation.
8. `chrome.cookies` timestamps are in seconds; `chrome.cookies.Cookie['sameSite']` uses Chrome's string union values.
9. The report HTML (`reportHtml.ts`) must stay injection-safe: interpolate only through the `html\`\`` tag; never add a raw-insertion path or untrusted `href`/`src`.

## Practical Guidance For Changes

- If you touch side panel behavior or copy, run at least `npm run lint`, `npm run eslint`, and `npm run build:all`.
- If you touch anything under `src/utils/`, run `npm run test` too.
- `dist/` and `artifacts/` are generated output and git-ignored. Do not commit them.
- The repo root is small; when searching, prefer the files above before broad codebase exploration.