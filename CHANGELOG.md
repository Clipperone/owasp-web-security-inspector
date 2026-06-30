# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-30

### Changed

- **UI now runs in the Chrome side panel** instead of the toolbar popup, giving
  a tall, resizable, persistent surface for reviewing findings while browsing.
  Requires Chrome 114+ (`minimum_chrome_version`).
- **Unified Assessment tab.** The Cookies, Tokens, and Storage subtabs are now
  live — they surface findings the engine already produced — alongside Headers
  and Transport & TLS. The Headers subtab also shows CORS/cache/disclosure
  findings.
- **Single exported report.** `Copy MD` / `Copy JSON` now export one report
  covering every category (headers, transport, cookies, tokens, storage).
- Introduced a shared UI design system (`src/sidepanel/ui/`) with one
  status/severity → tone map and reusable primitives, replacing the duplicated
  colour helpers across views.

### Internal

- Split the 1700+ line `assessment.ts` into focused modules under
  `src/utils/assessment/` (no behaviour change; public API preserved).
- Added unified reporting in `src/utils/report.ts`.
- Added project scaffolding for open-source publishing: `LICENSE` (MIT),
  `CONTRIBUTING.md`, `ARCHITECTURE.md`, `.gitattributes`, and CI on GitHub
  Actions.

## [0.1.0]

- Initial release: cookie/token/header inspection and editing, OWASP Secure
  Headers assessment, Transport & TLS assessment, and Markdown/JSON export.
