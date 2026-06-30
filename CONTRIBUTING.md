# Contributing

Thanks for your interest in improving OWASP Web Security Inspector. This is a
browser-side-only Chrome extension; please keep contributions aligned with that
scope (see [ARCHITECTURE.md](ARCHITECTURE.md)).

## Prerequisites

- Node.js 20+
- npm 10+
- Chrome 114+ (the side panel requires it)

## Setup

```bash
npm install
```

## Develop

```bash
npm run dev      # vite build --watch (rebuilds dist/ on change)
```

Load the unpacked extension from `dist/` at `chrome://extensions` with Developer
mode enabled, then open the side panel from the toolbar icon.

## Validate before opening a PR

Run the full sequence; all four must pass:

```bash
npm run test     # vitest — pure-module unit tests
npm run lint     # tsc --noEmit (strict; unused locals/params fail)
npm run eslint   # eslint .
npm run build    # vite build
```

CI runs the same sequence on every pull request.

## Conventions

- **Manifest V3 only.** Use `chrome.declarativeNetRequest` for header changes;
  do not add blocking `chrome.webRequest` mutation logic.
- **No external JWT libraries.** Keep JWT decode/validation local in `jwtUtils`.
- **Keep assessment logic pure.** New checks go in `src/utils/assessment/` (or
  `transportTls/`) as pure functions with unit tests — not in React components.
- **Use the design system.** Build UI from `src/sidepanel/ui/` primitives and the
  `status.ts` tone map instead of hand-written colour strings. Styling is
  Tailwind-only.
- **Strict TypeScript.** No implicit `any`; unused imports/locals/params fail the
  build.
- **Background errors stay silent.** The service worker must never crash; keep
  its `catch` blocks quiet.
- Don't commit `dist/` (generated, git-ignored).

## Commit & PR

- Keep commits focused and describe the user-visible effect.
- Update `README.md`, `ARCHITECTURE.md`, and `CHANGELOG.md` when behaviour or
  structure changes.
- Add or update tests for any change to a pure module.
