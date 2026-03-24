# Cookie / Token / Header Editor

Chrome extension for inspecting cookies, JWTs, and HTTP headers locally in the browser.

## What It Does

- Inspect, create, edit, delete, and export cookies for the active page.
- Decode JWTs from manual input or values found in cookies, `localStorage`, and `sessionStorage`.
- Create request and response header rules with Chrome `declarativeNetRequest`.
- Inspect recent response headers for the active tab and surface OWASP-oriented warnings.

## Main Features

### Cookies

- Inline create and edit flow.
- Validation for `SameSite=None`, `__Secure-*`, `__Host-*`, and partitioned cookies.
- Export as `curl` or Netscape `cookies.txt`.
- One-click jump from cookie JWT values to the Tokens tab.

### Modify Headers

- Request and response rule editing.
- Inline update, enable/disable, delete, and drag-and-drop reorder.
- Per-rule scope with `Global scope` or `Scoped domain`.
- Quick templates for common cases such as bearer auth and CORS debugging.
- Export enabled request-side rules as `curl -H` arguments.

### Tokens

- Real-time JWT decode.
- Expiration indicators for `exp`.
- Storage scan and manual rescan of the active tab.

### Response Headers

- Captures `DOC`, `IFR`, and `XHR` responses.
- Security summary for the primary response.
- Missing vs weak OWASP-relevant header checks.

## Stack

- Chrome Extension Manifest V3
- React 18
- TypeScript 5 with strict mode
- Vite 5 with `@crxjs/vite-plugin`
- Tailwind CSS 3

## Requirements

- Node.js 20+
- npm 10+
- Chrome 109+

## Development

```bash
npm install
npm run lint
npm run eslint
npm run build
```

Useful commands:

```bash
npm run dev
npm run generate-icons
```

Load the extension from `dist/` in `chrome://extensions` with Developer mode enabled.

## Release Flow

The repository includes an automated version bump and tagging flow for release preparation.

Available commands:

```bash
npm run release:patch
npm run release:minor
npm run release:major
```

Each release command:

- checks that the git working tree is clean
- bumps the version in `package.json`, `package-lock.json`, and `manifest.json`
- runs `npm run lint`, `npm run eslint`, and `npm run build`
- creates a git commit in the form `Release vX.Y.Z`
- creates the git tag `vX.Y.Z`

You can also run the script directly:

```bash
node scripts/release.mjs patch --dry-run
```

Optional flags:

- `--dry-run`
- `--allow-dirty`
- `--skip-checks`
- `--skip-tag`

After a successful release:

```bash
git push --follow-tags
```

## Project Structure

```text
manifest.json
package.json
package-lock.json
scripts/
  generate-icons.mjs
  release.mjs
src/
  background/
  content/
  popup/
    CookieEditorForm.tsx
    CookieTab.tsx
    CurrentHeadersTab.tsx
    HeaderRuleRow.tsx
    HeadersTab.tsx
    Popup.tsx
    TokensTab.tsx
    useDismissOnOutsideClick.ts
  types/
  utils/
```

## Permissions

- `cookies`: read and write cookies for the active context
- `declarativeNetRequest` and `declarativeNetRequestWithHostAccess`: apply header rules
- `storage`: persist rules and settings
- `activeTab`: resolve the active page context
- `webRequest`: capture response headers for inspection
- `host_permissions: <all_urls>`: operate across sites

## Privacy

- All processing stays in the browser.
- No backend or external API is used for token decoding or rule handling.
