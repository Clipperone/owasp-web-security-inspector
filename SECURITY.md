# Security Policy

## Supported versions

The extension is developed on a rolling basis; only the latest released version
receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
go to the repository's **Security** tab → **Report a vulnerability**. (Repository
maintainers: enable this under *Settings → Code security and analysis → Private
vulnerability reporting*.)

When reporting, please include:

- affected version and browser (Chrome / Firefox / Edge),
- a description of the issue and its impact,
- clear reproduction steps or a proof of concept,
- any relevant logs (with secrets redacted).

You can expect an initial acknowledgement on a best-effort basis. Coordinated
disclosure is appreciated — please give us a reasonable window to ship a fix
before any public write-up.

## Scope and design notes

This is a **browser-side, zero-backend** extension. Understanding its threat
model helps focus reports:

- The **security assessment engine is passive** — it only observes what the
  browser exposes and never probes endpoints or modifies requests, responses, or
  headers. Cookie editing in the Cookies tab is the one explicit, user-initiated
  write.
- All processing stays local. There is **no backend and no external/network
  call** for token decoding, assessment, detection, or report generation.
- Storage **secrets and PII are redacted at the source** (in the content script)
  before anything is cached or displayed; raw values do not leave the page
  (whole-value JWTs are the documented exception, needed by the Tokens tab).
- The exported HTML report is a **self-contained, zero-JavaScript** document with
  every value HTML-escaped and a restrictive `Content-Security-Policy` meta tag.

Reports that would be especially valuable include: a way to make the extension
mutate a site's state without an explicit user action, an XSS/HTML-injection path
in the side panel or the exported report, a raw secret/PII value leaking past the
source-side redaction, or a ReDoS in a detection pattern.

## Out of scope

- The extension does not verify TLS certificates/ciphers, backend session
  invalidation, secret strength, or server-side behavior — these are documented
  non-goals, not vulnerabilities.
- Placeholder icons shipped in the repository are not a security issue.
