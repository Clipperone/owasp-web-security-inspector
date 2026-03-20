# Copilot Agent Instructions

Trust these instructions. Only search the codebase if information here is incomplete or appears incorrect.

## What This Repository Does

**Cookie / Token / Header Editor** is a Chrome Extension (Manifest V3) that lets developers inspect and manipulate cookies, JWT tokens, and HTTP request/response headers on any page. It runs fully locally — no backend, no external API calls for data processing.

## Runtime & Tool Versions

| Tool | Version |
|------|---------|
| Node.js | 24.x |
| npm | 11.x |
| TypeScript | 5.x (`"strict": true`) |
| Vite | 5.x |
| React | 18.x |
| Tailwind CSS | 3.x |

## Build & Validation — Complete Command Sequence

**Always run `npm install` before any build command** if `node_modules/` is absent. Omitting this step causes a hard `"vite is not recognized"` failure.

```bash
# 1. Install dependencies (required once, and after any package.json change)
npm install

# 2. Type-check only — no output means zero errors (exit 0)
npm run lint          # runs: tsc --noEmit

# 3. Production build — output goes to dist/
npm run build         # runs: vite build
# Expected: "42 modules transformed", "built in ~7s", exit 0

# 4. Development watch mode (rebuilds on save)
npm run dev           # runs: vite build --watch
```

The **canonical validation sequence** before committing is: `npm run lint` (must produce no output) then `npm run build` (must succeed). There are no automated tests. There is no CI pipeline yet — validation is purely local.

`dist/` is generated output and is git-ignored. Never commit it.

## Architecture

```
src/
  types/index.ts          ← ALL shared TypeScript interfaces and enums (single source of truth)
  utils/
    jwtUtils.ts           ← JWT decode (Base64Url, pure TS, no libs). Exports: isJwt(), decodeJwt(), formatExpiry()
    storageUtils.ts       ← Typed chrome.storage.local wrapper. Exports: getRules(), saveRule(), deleteRule(), toggleRule(), nextRuleId(), getSettings(), updateSettings(), resetStorage()
    cookieUtils.ts        ← Stub (export {} only)
    headerUtils.ts        ← Stub (export {} only)
    index.ts              ← Barrel re-exporting all 4 utils
  background/index.ts     ← MV3 service worker. Handles onInstalled, updateNetworkRules(), and all MessageType cases
  content/index.ts        ← Injected into all pages. Scans localStorage/sessionStorage via requestIdleCallback, sends STORAGE_SCAN_RESULT message
  popup/
    main.tsx              ← ReactDOM.createRoot entry point
    App.tsx               ← Thin wrapper: renders <Popup />
    Popup.tsx             ← Tab shell (Cookies | Headers | Tokens), manages activeTab state
    CookieTab.tsx         ← Full cookie CRUD using chrome.cookies API directly
    HeadersTab.tsx        ← DNR rule editor; communicates with background via chrome.runtime.sendMessage
    TokensTab.tsx         ← JWT decoder; fetches storage scan via GET_STORAGE_TOKENS message
manifest.json             ← Manifest V3 source — @crxjs/vite-plugin reads this directly
vite.config.ts            ← Uses @crxjs/vite-plugin; output is dist/
tsconfig.json             ← Strict mode, bundler moduleResolution, noEmit: true, jsx: react-jsx
tailwind.config.js        ← darkMode: 'class', content glob: './src/**/*.{ts,tsx,html}'
postcss.config.js         ← tailwindcss + autoprefixer
scripts/generate-icons.mjs ← Run once with `node scripts/generate-icons.mjs` to regenerate placeholder PNGs in public/icons/
```

## Critical Architecture Rules

1. **Manifest V3 only** — Use `chrome.declarativeNetRequest` (DNR) for all header manipulation. Never use blocking `chrome.webRequest`.
2. **Local only** — JWT decoding uses native `atob()` + `decodeURIComponent`. Never install `jsonwebtoken`, `jwt-decode`, or any JWT library.
3. **Silent background errors** — All `catch` blocks in `src/background/index.ts` must swallow errors silently. No `console.log` in background scripts.
4. **No barrel import in background** — `src/background/index.ts` imports directly from `'../utils/storageUtils'` (not from `'../utils'`) to avoid an IDE resolution bug.
5. **DNR enum** — Use `chrome.declarativeNetRequest.RuleActionType.MODIFY_HEADERS` (enum value), never the string literal `'modifyHeaders'`.
6. **Cookie API type** — Use `chrome.cookies.Details` (not `chrome.cookies.CookieDetails`).
7. **`"type": "module"`** in `package.json` — required; removing it causes CJS warnings.
8. **All UI styled with Tailwind CSS** — No inline `style=` props, no CSS modules.

## Key Types (src/types/index.ts)

- `HeaderRule` — persisted DNR rule (id, priority, name, enabled, urlFilter, requestHeaders?, responseHeaders?, createdAt, updatedAt)
- `HeaderModification` — `{ header, operation: 'append'|'set'|'remove', value? }`
- `MessageType` — union of all 11 message strings handled by the background router
- `StorageScanResult` / `StorageEntry` — content script scan payload
- `STORAGE_KEYS` — const object with keys `HEADER_RULES`, `COOKIE_OVERRIDES`, `SETTINGS`
- `DEFAULT_SETTINGS` — default `ExtensionSettings` value

## Common TypeScript Pitfalls

- `"noUnusedLocals": true` and `"noUnusedParameters": true` are enforced — every import and parameter must be used.
- When a React component imports `React` only for `React.FC`, the import is used and required.
- The `exhaustive never` pattern is used in the background message router `default` branch — adding a new `MessageType` requires adding a matching `case`.
- `chrome.cookies.SameSiteStatus` = `"unspecified" | "no_restriction" | "lax" | "strict"`.
- `expirationDate` in `chrome.cookies` is Unix timestamp in **seconds**.

## .gitignore Summary

Ignored: `node_modules/`, `dist/`, `.vite/`, `*.tsbuildinfo`, `.vscode/`, `.idea/`, `.DS_Store`, `Thumbs.db`, `.env*`