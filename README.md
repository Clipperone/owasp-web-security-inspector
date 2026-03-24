# Cookie / Token / Header Editor

A Chrome Extension (Manifest V3) for developers to inspect and manipulate **cookies**, **JWT tokens**, and **HTTP request/response headers** on any web page — entirely locally, with no backend and no external API calls.

---

## Features

| Tab | What it does |
|-----|-------------|
| **Cookies** | List all cookies for the active page. Create, edit (name, value, domain, path, SameSite, expiry, Secure, HttpOnly flags), and delete cookies with inline confirmation. **Export** the visible cookie set as a `curl` command or a Netscape `cookies.txt` file (compatible with yt-dlp, wget, and curl). Cookies whose value is a JWT token show a **`JWT` badge**; clicking the badge instantly sends the value to the **Tokens** tab for analysis. A **Clear All** button (🗑) removes every cookie for the current site at once after an inline confirmation step. |
| **Response Headers** | Shows live HTTP response headers captured as you browse. Auto-refreshes every 3 seconds. Security-relevant headers (CSP, HSTS, X-Frame-Options, CORS, etc.) are highlighted with colour-coded badges. Filter requests by URL and expand any row to inspect the full header list. |
| **Modify Headers** | Create declarativeNetRequest rules to add, set, append, or remove request/response headers on matching URLs. Toggle rules on/off, edit existing rules inline, or delete them without reloading the extension. Use the **Global / This Site** scope toggle as a default and override scope per rule with **Global scope** or **Scoped domain** in the form. Apply **Quick Templates** (e.g. Bearer Token, CORS Bypass, Debug Header) with a single click. See a **live preview badge** of the matching URL before saving. **Reorder rules** by drag and drop. **Export** request-header rules as a `curl -H` command. |
| **Tokens** | **Real-time JWT decoder**: paste a token and it decodes instantly. Displays three collapsible sections (**Header**, **Payload**, **Signature**) with colour-coded JSON syntax highlighting. `exp`, `iat`, and `nbf` claims show the human-readable local date alongside the unix value. A prominent **⚠️ Token Expired** banner appears when `exp` is in the past. Also surfaces valid JWTs found automatically by the page scanner in `localStorage` / `sessionStorage`, and the refresh button triggers a real rescan of the active tab. |

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

## Usage Examples

### Cookies tab

#### Inspect and edit a session cookie

1. Navigate to the target site and open the extension.
2. The **Cookies** tab lists every cookie scoped to the current URL.
3. Click the **pencil** icon on a row to expand the inline editor — change the `value`, toggle `HttpOnly`, adjust the expiry, then click **Save**.
4. Reload the page; the site now sends the modified cookie.

#### Export cookies for CLI tools (yt-dlp, curl, wget)

1. Use the search box to filter to the cookies you need (e.g. type `session`).
2. Click **Export → Copy as Netscape cookies.txt**.
3. Paste the clipboard content into a `cookies.txt` file and use it:

```bash
yt-dlp --cookies cookies.txt "https://example.com/video"
curl --cookie cookies.txt "https://example.com/api/data"
```

#### Clean up before an authentication test

1. Click the **🗑 Clear All** button in the toolbar.
2. Confirm in the red banner — all cookies for the current site are deleted instantly.
3. Reload the page to verify the unauthenticated state.

#### Spot and analyse a JWT stored in a cookie

When a cookie value is a JWT, a sky-blue **`JWT`** badge appears in the Flags column. Click the badge — the extension switches to the **Tokens** tab with the value pre-loaded and decoded.

---

### Modify Headers tab

#### Inject a Bearer token into every API request

1. Open the extension on any page that calls your API.
2. Use the rule form at the top of the tab, or choose **Templates ▾ → Bearer Token** to pre-fill it.
3. Set:
   - **URL filter**: `*api.example.com/*`
   - **Operation**: `set`
   - **Header**: `Authorization`
   - **Value**: `Bearer <your-token>`
  - **Target**: `Request`
4. Click **Add rule**. Every request matching the pattern now carries the header — no code change required.

#### Bypass CORS errors during local development

1. Click **Templates ▾ → CORS Bypass**.
2. The form pre-fills `Access-Control-Allow-Origin: *` as a **response** header on `*://*/*`.
3. Restrict the rule to your dev server only: set the URL filter to `*localhost*` and choose **Scoped domain** in the form.
4. Save — browser CORS checks now pass for responses from localhost.

#### Remove a response header

1. Fill in the rule form manually:
   - **Header**: `X-Frame-Options`
   - **Operation**: `remove`
  - **Target**: `Response`
2. Save. The header is stripped from every matching response, allowing the page to be embedded in an iframe.

#### Reorder and toggle rules

- Drag rules up or down to change priority (higher in the list = evaluated first by Chrome's DNR engine).
- Use the toggle switch on each row to enable/disable a rule without deleting it.

#### Edit an existing rule

- Click the pencil icon on any rule row to load it back into the main form.
- Update the name, URL filter, target, operation, header, value, or scope.
- Click **Update rule** to save changes while preserving the same rule ID and priority.

#### Export all active request rules as cURL

Click **Export → Copy as cURL** to get a ready-to-run shell command with all enabled request-side `-H` flags:

```bash
curl 'https://api.example.com/endpoint' \
  -H 'Authorization: Bearer eyJ...' \
  -H 'X-Debug: true'
```

---

### Tokens tab

#### Decode a JWT instantly

1. Paste any JWT string into the text area at the top — decoding happens in real time, no button needed.
2. Three collapsible sections appear: **Header** (algorithm, type), **Payload** (claims), **Signature** (raw base64url).
3. Claims `exp`, `iat`, and `nbf` show both the unix timestamp and the human-readable local date/time.

#### Check whether a token is expired

A prominent **⚠️ Token Expired** banner appears at the top of the card when the `exp` claim is in the past, together with the exact expiry date. Useful for debugging 401 errors without opening jwt.io.

Example expired token output:
```
⚠️ Token Expired
Expired on 15/01/2024, 09:32:00
alg: HS256 · typ: JWT · expired 14 months ago
```

#### Find JWTs stored in localStorage / sessionStorage

The extension automatically scans the page's web storage on load. Any valid JWT values found are listed below the manual input area with a **Storage** badge showing the storage key they came from (e.g. `access_token`, `auth`). Use the refresh button to trigger a new scan without reloading the page.

---

### Response Headers tab

#### Inspect live HTTP response headers

1. With the extension open, browse or reload a page — the **Response Headers** tab captures headers as requests complete.
2. Each row shows URL, method, status code, resource type, and timestamp.
3. Click a row to expand the full header list.

#### Check security posture of a site

Security-relevant headers are highlighted with colour-coded badges:

| Badge | Header | Meaning |
|-------|--------|---------|
| 🟢 | `Strict-Transport-Security` | HSTS configured |
| 🟡 | `Content-Security-Policy` | CSP present |
| 🔴 | `X-Frame-Options` | Clickjacking protection |
| 🔵 | `Access-Control-Allow-Origin` | CORS policy |

Missing headers are immediately visible by their absence — useful for quick security reviews.

#### Filter by URL

Use the search box in the **Response Headers** tab to show only requests matching a hostname or path segment (e.g. type `api` to focus on XHR calls).

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
    │   ├── exporter.ts        # exportToCurl() and exportToNetscape() utilities
    │   ├── cookieUtils.ts     # Cookie helpers (URL building, identity keys, local datetime conversion)
    │   ├── headerUtils.ts     # Header validation and default naming helpers
    │   └── index.ts           # Barrel re-export
    ├── background/index.ts    # Service worker: DNR engine + message router
    ├── content/index.ts       # Page scanner: localStorage/sessionStorage → valid JWT hints
    └── popup/
        ├── main.tsx           # ReactDOM.createRoot entry point
        ├── App.tsx            # Root component → <Popup />
        ├── ScopeContext.tsx   # React context: Global / This Site scope toggle
        ├── Popup.tsx          # Tab shell (Cookies | Response Headers | Modify Headers | Tokens) + scope header
        ├── CookieTab.tsx          # Cookie inspector & editor
        ├── HeadersTab.tsx         # Header rule editor (scope-aware, templates, inline editing, DnD reorder)
        ├── TokensTab.tsx          # Real-time JWT decoder, storage token viewer, and manual rescan
        └── CurrentHeadersTab.tsx  # Response Headers tab — live HTTP response header cache
```

---

## Permissions

| Permission | Reason |
|-----------|--------|
| `cookies` | Read and write cookies for any URL |
| `declarativeNetRequest` + `declarativeNetRequestWithHostAccess` | Modify HTTP headers via DNR rules |
| `storage` | Persist header rules and settings in `chrome.storage.local`; cache response headers in `chrome.storage.session` |
| `activeTab` | Query the active tab URL (used by the Cookies and Modify Headers tabs) |
| `webRequest` | Intercept HTTP responses to populate the Response Headers tab cache |
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

## Cookie & Header Export

Both the **Cookies** and **Modify Headers** tabs include an **Export** dropdown button that copies data to the clipboard in formats consumed by common CLI tools.

### Copy as cURL

Available in both tabs. Produces a bash `curl` command that can be pasted directly into a terminal.

```bash
# Example output (Cookies tab)
curl 'https://example.com' \
  -b 'session_id=abc123; user=alice'

# Example output (Modify Headers tab — enabled request rules only)
curl 'https://example.com' \
  -H 'Authorization: Bearer eyJ...' \
  -H 'X-Custom-Header: value'
```

All arguments are **single-quoted** and internal single quotes are properly escaped (`'\''`) to prevent bash injection. In the **Modify Headers** tab, the export includes only request headers that `curl` can actually send.

### Copy as Netscape cookies.txt

Available in the **Cookies** tab. Produces the classic Netscape HTTP Cookie File format read by `curl --cookie <file>`, **yt-dlp**, wget, and other CLI tools.

```
# Netscape HTTP Cookie File
# Generated by Cookie / Token / Header Editor

.example.com	TRUE	/	TRUE	1893456000	session_id	abc123
example.com	FALSE	/	FALSE	0	user	alice
```

The seven tab-separated fields are: `domain`, `include_subdomains`, `path`, `https_only`, `expiry_unix`, `name`, `value`. Session cookies (no expiry date) use `0` as the expiry value.

Exporting applies to the **currently visible** (filtered) cookie list — use the search box to narrow the export to a specific subset.

---

## Privacy

All processing happens **entirely in the browser**. No data is sent to any external server. JWT tokens are decoded locally using the built-in `atob()` function — no JWT libraries are used.
