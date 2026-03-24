# Copilot Agent Instructions

Trust these instructions. Only search the codebase if this file is incomplete or wrong.

## Repository Summary

**OWASP Web Security Inspector** is a small single-package Chrome extension built with Manifest V3, React, TypeScript, Vite, and Tailwind. It inspects and assesses cookies, JWTs, storage tokens, `Set-Cookie` responses, and browser-visible HTTP security headers. All logic is local; there is no backend and no external API for decoding or assessment.

Validated environment here: Node.js 24.x, npm 11.x. README targets Node.js 20+ and npm 10+.

## Build, Test, Run, Validate

Always run `npm install` before any npm script if `node_modules/` is missing or `package.json` changed. Without dependencies, Vite commands fail.

Working command order validated in this repo:

```bash
npm install
npm run test
npm run lint
npm run eslint
npm run build
```

What each command does and what was verified:

- `npm run test`
  Runs `vitest run`. This currently passes with 2 test files / 7 tests. It emits Vite/CRX deprecation warnings about `esbuild` and `rolldownOptions`, but the command succeeds.
- `npm run lint`
  Runs `tsc --noEmit`. Success is silent.
- `npm run eslint`
  Runs `eslint .`. Success is silent.
- `npm run build`
  Runs `vite build` and writes `dist/`. Validated successfully; current build completes in about 5 seconds and produces the unpacked extension.
- `npm run dev`
  Runs `vite build --watch`. This is a watch rebuild, not a dev server. It stays running until stopped.

Postcondition for manual testing: load `dist/` as an unpacked extension in `chrome://extensions` with Developer mode enabled.

Other scripted steps:

- `node scripts/release.mjs patch --dry-run`
  Fails on a dirty working tree by design: `Working tree is not clean...`.
- `node scripts/release.mjs patch --dry-run --allow-dirty`
  Works and re-runs `npm run lint`, `npm run eslint`, and `npm run build` before reporting the next version/tag.
- `npm run release:patch|minor|major`
  Real release flow. It edits `package.json`, `package-lock.json`, and `manifest.json`, commits, and tags. Do not run unless explicitly asked.
- `npm run generate-icons`
  Mutates files under `public/icons`. The script currently writes `icon16.png`-style names, while the manifest uses `16px.png`-style names. Do not assume it refreshes the icons actually referenced by the extension without checking filenames first.

There are no `.github/workflows` files and no remote CI definition in the repo. Pre-checkin validation is local.

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
  MV3 service worker. Owns install/update lifecycle, dynamic declarativeNetRequest rule sync, response-header cache, and the popup/content message router.
- `src/content/index.ts`
  Content script injected on all pages. Scans `localStorage` and `sessionStorage` via `requestIdleCallback` and reports findings back to background.
- `src/popup/`
  React popup UI. `Popup.tsx` is the tab shell. Main tabs are `AssessmentTab.tsx`, `CookieTab.tsx`, `CurrentHeadersTab.tsx`, `HeadersTab.tsx`, and `TokensTab.tsx`.
- `src/types/index.ts`
  Shared source of truth for message contracts, assessment models, header rules, token/storage types, and extension settings.
- `src/utils/assessment.ts`
  Pure browser-side assessment engine for cookies, `Set-Cookie`, headers, and tokens.
- `src/utils/storageUtils.ts`
  Typed wrapper around `chrome.storage.local` for rules/settings.
- `src/utils/jwtUtils.ts`
  Local JWT detection/decoding. No external JWT library is used.
- `src/utils/exporter.ts`
  Cookie export and curl export helpers.
- `src/utils/*.test.ts`
  Vitest tests for the pure utility modules only; there are no browser E2E tests.

## Architecture Rules That Matter

1. Manifest V3 only. Use `chrome.declarativeNetRequest` for header modification. Do not add blocking `chrome.webRequest` mutation logic.
2. Keep JWT handling local and dependency-free. Do not add `jsonwebtoken`, `jwt-decode`, or similar libraries.
3. Background script errors are intentionally swallowed in catch blocks. Do not add noisy logging there.
4. In `src/background/index.ts`, keep importing `storageUtils` directly from `../utils/storageUtils`, not the barrel.
5. Use `chrome.declarativeNetRequest.RuleActionType.MODIFY_HEADERS`, not the string `'modifyHeaders'`.
6. All popup styling is Tailwind-based; `src/popup/index.css` only contains Tailwind directives. Do not introduce CSS modules or inline styles unless the project style changes.
7. TypeScript is strict. Unused imports, locals, or parameters fail validation.
8. `chrome.cookies` timestamps are in seconds, and `chrome.cookies.SameSiteStatus` uses Chrome's string union values.

## Practical Guidance For Changes

- If you touch popup behavior or copy, run at least `npm run lint`, `npm run eslint`, and `npm run build`.
- If you touch `src/utils/assessment.ts` or `src/utils/jwtUtils.ts`, run `npm run test` too.
- `dist/` is generated output and git-ignored. Do not commit it.
- The repo root is small; when searching, prefer the files above before broad codebase exploration.