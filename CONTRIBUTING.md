# Contributing

Thanks for your interest in improving OWASP Web Security Inspector. This is a
browser-side-only extension for Chrome, Firefox, and Edge whose **security
assessment is passive** (the Cookies tab is the one explicit editing surface);
please keep contributions aligned with that scope (see
[ARCHITECTURE.md](ARCHITECTURE.md)).

## Prerequisites

- Node.js 20.19+ or 22.12+ (required by Vite 8)
- npm 10+
- Chrome/Edge 114+ or Firefox 115+

## Setup

```bash
npm install
```

## Develop

```bash
npm run dev      # vite build --watch (rebuilds dist/chrome on change)
```

Load the unpacked extension:

- **Chrome/Edge**: `chrome://extensions` → Developer mode → Load unpacked → `dist/chrome`.
- **Firefox**: run `npm run build:firefox`, then `about:debugging` → Load Temporary Add-on → `dist/firefox/manifest.json`.

## Validate before opening a PR

Run the full sequence; all must pass:

```bash
npm run test       # vitest — pure-module unit tests
npm run lint       # tsc --noEmit (strict; unused locals/params fail)
npm run eslint     # eslint .
npm run build:all  # vite build for Chrome/Edge + Firefox
```

CI runs the same sequence on every pull request.

## Conventions

- **Passive assessment.** The assessment engine only observes — no probing, no
  request/response/header modification, no `declarativeNetRequest`. Cookie
  editing in the Cookies tab is the one intentional, user-initiated write; keep
  any other new capability observation-only.
- **Manifest V3, cross-browser.** Code uses the promise-flavoured `chrome.*`
  namespace (works in Firefox too). Chrome-only manifest keys are handled by
  `scripts/postbuild-firefox.mjs`; update it when you touch the manifest.
- **No external JWT libraries.** Keep JWT decode/validation local in `jwtUtils`.
- **Detection patterns must be ReDoS-safe.** New detectors use bounded,
  linear-time regexes with checksums in `validate()`; add adversarial + checksum
  test vectors. Secrets/PII must be redacted at the source.
- **Keep assessment logic pure.** New checks go in `src/utils/assessment/` (or
  `transportTls/`) as pure functions with unit tests — not in React components.
- **Use the design system.** Build UI from `src/sidepanel/ui/` primitives and the
  `status.ts` tone map instead of hand-written colour strings. Styling is
  Tailwind-only.
- **Strict TypeScript.** No implicit `any`; unused imports/locals/params fail the
  build.
- **Background errors stay silent.** The service worker must never crash; keep
  its `catch` blocks quiet.
- Don't commit `dist/` or `artifacts/` (generated, git-ignored).

## Commit & PR

- Keep commits focused and describe the user-visible effect.
- Update `README.md`, `ARCHITECTURE.md`, and `CHANGELOG.md` when behaviour or
  structure changes.
- Add or update tests for any change to a pure module.
