# Cookie / Token / Header Editor

A Chrome Extension (Manifest V3) for developers to inspect and manipulate **cookies**, **JWT tokens**, and **HTTP request/response headers** on any web page — entirely locally, with no backend and no external API calls.

---

## Features

| Tab | What it does |
|-----|-------------|
| **Cookies** | List all cookies for the active page. Create, edit (name, value, domain, path, SameSite, expiry, Secure, HttpOnly flags), and delete cookies with inline confirmation. |
| **Headers** | Create declarativeNetRequest rules to add, set, append, or remove request/response headers on matching URLs. Toggle rules on/off or delete them without reloading the extension. Use the **Global / This Site** scope toggle to restrict a new rule to the current domain only. |
| **Tokens** | Decode any JWT manually (paste & decode) or automatically from tokens found by the page scanner in `localStorage` / `sessionStorage`. Displays a colour-coded JSON view of header and payload, expiry status, and raw segment breakdown. |

---

## Tech Stack

- **Chrome Extension Manifest V3**
- **Vite 5** + **@crxjs/vite-plugin** — bundles the extension directly from source
- **React 18** + **TypeScript 5** (strict mode)
- **Tailwind CSS 3** — dark devtools theme, `darkMode: 'class'`
- No runtime dependencies beyond React — JWT decoding is done natively with `atob()`

---

## Prerequisites

| Tool | Minimum version |
|------|----------------|
| Node.js | 20.x (tested on 24.x) |
| npm | 10.x (tested on 11.x) |
| Google Chrome | 109+ (Manifest V3 support) |

---

## Installation & Build

```bash
# 1. Clone the repository
git clone <repo-url>
cd cookie-token-header-editor

# 2. Install dependencies  ← always required before building
npm install

# 3. Production build — output goes to dist/
npm run build
```

> **Note:** If `node_modules/` is absent and you run `npm run build` directly, you will get  
> `"vite" is not recognized as an internal or external command` — always run `npm install` first.

### Other scripts

```bash
npm run dev       # watch mode — rebuilds dist/ automatically on every file save
npm run lint      # TypeScript type-check only (no output = zero errors)
npm run generate-icons  # regenerate placeholder PNGs in public/icons/ (run once)
```

---

## Loading the Extension in Chrome

1. Run `npm run build` — the `dist/` folder is the unpacked extension.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `dist/` folder.
5. The extension icon appears in the toolbar — click it to open the popup.

During development use `npm run dev` so `dist/` rebuilds on every save; Chrome picks up changes automatically after you press the **↺ refresh** button on the extensions page.

---

## Project Structure

```
├── manifest.json              # MV3 manifest (read by @crxjs/vite-plugin)
├── vite.config.ts             # Vite + crx plugin configuration
├── tsconfig.json              # TypeScript strict config (noEmit: true)
├── tailwind.config.js         # Tailwind — darkMode: 'class'
├── public/icons/              # Extension icons (16 / 32 / 48 / 128 px)
├── scripts/
│   └── generate-icons.mjs     # Generates placeholder icon PNGs
└── src/
    ├── types/index.ts         # All shared TypeScript interfaces & enums
    ├── utils/
    │   ├── jwtUtils.ts        # Pure-TS JWT decoder (isJwt, decodeJwt, formatExpiry)
    │   ├── storageUtils.ts    # chrome.storage.local typed wrapper
    │   ├── cookieUtils.ts     # Stub — future cookie helpers
    │   ├── headerUtils.ts     # Stub — future header helpers
    │   └── index.ts           # Barrel re-export
    ├── background/index.ts    # Service worker: DNR engine + message router
    ├── content/index.ts       # Page scanner: localStorage/sessionStorage → JWT hints
    └── popup/
        ├── main.tsx           # ReactDOM.createRoot entry point
        ├── App.tsx            # Root component → <Popup />
        ├── ScopeContext.tsx   # React context: Global / This Site scope toggle
        ├── Popup.tsx          # Tab shell (Cookies | Headers | Tokens) + scope header
        ├── CookieTab.tsx      # Cookie inspector & editor
        ├── HeadersTab.tsx     # Header rule editor (scope-aware)
        └── TokensTab.tsx      # JWT decoder & storage token viewer
```

---

## Permissions

| Permission | Reason |
|-----------|--------|
| `cookies` | Read and write cookies for any URL |
| `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` | Modify HTTP headers via DNR rules |
| `storage` | Persist header rules and settings in `chrome.storage.local` |
| `scripting` + `activeTab` | Inject the content script and query the active tab |
| `host_permissions: <all_urls>` | Required for cross-origin cookie and header access |

---

## Tab-Scoped Header Rules

The popup header contains a **Global / This Site** toggle that controls the scope of newly created header rules.

| Mode | Behaviour |
|------|-----------|
| **Global** (default) | The rule applies to all URLs matching the `urlFilter` pattern, regardless of which site you're on. |
| **This Site** | The rule is restricted to the hostname of the currently active tab (e.g. `example.com`). Chrome's DNR `requestDomains` condition is used under the hood — the rule fires only when the initiator domain matches. |

The toggle is disabled when the active tab is not a regular web page (e.g. `chrome://` or `about:` pages). The current hostname is displayed next to the toggle for clarity.

The `domainScope` field is stored alongside each `HeaderRule` in `chrome.storage.local`. Existing rules without `domainScope` continue to behave as global rules.

---

## Privacy

All processing happens **entirely in the browser**. No data is sent to any external server. JWT tokens are decoded locally using the built-in `atob()` function — no JWT libraries are used.
