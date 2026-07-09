/**
 * Self-contained HTML report renderer.
 *
 * Produces a single offline HTML document (inline CSS, zero JavaScript, no
 * external fonts/scripts/images) from a `FullAssessmentReport`. This is the only
 * export format the panel offers.
 *
 * Security model — the report embeds untrusted page-derived data (header values,
 * URLs, cookie/storage key names, JWT claims), so injection safety is the
 * priority:
 *   1. The `html` tagged template escapes EVERY interpolation unless it is
 *      already a `SafeHtml` produced by a nested `html` call. There is no
 *      exported raw-insertion escape hatch — the single trusted insertion (the
 *      static stylesheet) uses a module-private helper.
 *   2. Untrusted data lands only in element text content; class/attribute values
 *      come from closed enum→literal maps.
 *   3. The document carries a restrictive meta CSP as defense-in-depth and
 *      contains no scripts, no event handlers, and no `href`/`src` sinks.
 */
import type {
  AssessmentFinding,
  AssessmentSeverity,
  HeaderAssessmentCheck,
  HeaderAssessmentKind,
  HeaderAssessmentStatus,
  TransportTlsCheck,
  TransportTlsStatus,
} from '../types';
import type { FullAssessmentReport } from './report';
import {
  FINDING_CATEGORY_LABEL,
  FINDING_CATEGORY_ORDER,
  HEADER_KIND_LABEL,
  HEADER_KIND_ORDER,
  HEADER_STATUS_LABEL,
  REPORT_LIMITATIONS,
  SEVERITY_LABEL,
  TRANSPORT_CONFIDENCE_LABEL,
  TRANSPORT_COVERAGE_LABEL,
  TRANSPORT_STATUS_LABEL,
} from './report';

// ─────────────────────────────────────────────────────────────────────────────
// Escaping primitive + secure-by-default templating
// ─────────────────────────────────────────────────────────────────────────────

const ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/**
 * Escapes `& < > " '` for safe embedding in HTML element and quoted-attribute
 * contexts. Ampersand is handled first by the single-pass character class.
 */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, ch => ESCAPE_MAP[ch]);
}

/** A string marked as already-safe HTML. Only `html` and the private `raw` produce it. */
interface SafeHtml {
  readonly __safeHtml: true;
  readonly value: string;
}

type HtmlValue = string | number | boolean | null | undefined | SafeHtml | SafeHtml[];

function isSafeHtml(value: unknown): value is SafeHtml {
  return typeof value === 'object' && value !== null && (value as SafeHtml).__safeHtml === true;
}

/** Module-private: wraps a TRUSTED static string (the stylesheet) as SafeHtml. Never exported. */
function raw(value: string): SafeHtml {
  return { __safeHtml: true, value };
}

function coerce(value: HtmlValue): string {
  if (value == null || value === false || value === true) return '';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return escapeHtml(value);
  if (Array.isArray(value)) return value.map(item => (isSafeHtml(item) ? item.value : coerce(item))).join('');
  return value.value; // SafeHtml
}

/**
 * Tagged template that auto-escapes every interpolation. Nested `html` results
 * (and arrays of them) pass through unescaped; plain strings are escaped;
 * numbers/booleans stringify; null/undefined render as an empty string.
 */
function html(strings: TemplateStringsArray, ...values: HtmlValue[]): SafeHtml {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += coerce(values[i]) + strings[i + 1];
  }
  return { __safeHtml: true, value: out };
}

// ─────────────────────────────────────────────────────────────────────────────
// Closed enum → literal class maps (never derived from untrusted input)
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_CLASS: Record<AssessmentSeverity, string> = {
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  info: 'sev-info',
};

const HEADER_STATUS_CLASS: Record<HeaderAssessmentStatus, string> = {
  pass: 'st-pass',
  fail: 'st-fail',
  warn: 'st-warn',
  'not-applicable': 'st-na',
};

const TRANSPORT_STATUS_CLASS: Record<TransportTlsStatus, string> = {
  pass: 'st-pass',
  fail: 'st-fail',
  warn: 'st-warn',
  inconclusive: 'st-na',
};

const OPEN_ATTR = raw('open');

// ─────────────────────────────────────────────────────────────────────────────
// Composition helpers (all return SafeHtml)
// ─────────────────────────────────────────────────────────────────────────────

function severityBadge(severity: AssessmentSeverity): SafeHtml {
  return html`<span class="badge ${SEVERITY_CLASS[severity]}">${SEVERITY_LABEL[severity]}</span>`;
}

function headerStatusBadge(status: HeaderAssessmentStatus): SafeHtml {
  return html`<span class="badge ${HEADER_STATUS_CLASS[status]}">${HEADER_STATUS_LABEL[status]}</span>`;
}

function transportStatusBadge(status: TransportTlsStatus): SafeHtml {
  return html`<span class="badge ${TRANSPORT_STATUS_CLASS[status]}">${TRANSPORT_STATUS_LABEL[status]}</span>`;
}

function findingCard(finding: AssessmentFinding): SafeHtml {
  const open = finding.severity === 'high' || finding.severity === 'medium';
  return html`
    <details class="card ${SEVERITY_CLASS[finding.severity]}" ${open ? OPEN_ATTR : ''}>
      <summary>${severityBadge(finding.severity)} <span class="card-title">${finding.title}</span></summary>
      <dl>
        <dt>Summary</dt><dd>${finding.summary}</dd>
        ${finding.whyItMatters ? html`<dt>Why it matters</dt><dd>${finding.whyItMatters}</dd>` : ''}
        <dt>Evidence</dt><dd><code>${finding.evidence}</code></dd>
        <dt>Remediation</dt><dd>${finding.remediation}</dd>
      </dl>
    </details>`;
}

function findingsGroup(report: FullAssessmentReport): SafeHtml {
  if (report.findings.length === 0) {
    return html`<p class="empty">No cookie, token, storage, header, or transport findings were raised in the captured context.</p>`;
  }
  const groups = FINDING_CATEGORY_ORDER.map(category => {
    const items = report.findings.filter(finding => finding.category === category);
    if (items.length === 0) return html``;
    return html`
      <h3>${FINDING_CATEGORY_LABEL[category]} <span class="count">${items.length}</span></h3>
      ${items.map(findingCard)}`;
  });
  return html`${groups}`;
}

function headerCheckRow(check: HeaderAssessmentCheck): SafeHtml {
  const observed = check.observedValues.length > 0 ? check.observedValues.join(' | ') : 'Not observed';
  return html`
    <tr>
      <td>${headerStatusBadge(check.status)}</td>
      <td class="mono">${check.headerName}</td>
      <td class="mono wrap">${observed}</td>
      <td>
        <div class="cell-note"><span class="note-label">Expected</span> ${check.expected}</div>
        <div class="cell-note"><span class="note-label">Remediation</span> ${check.remediation}</div>
      </td>
    </tr>`;
}

function headerChecksTable(kind: HeaderAssessmentKind, checks: HeaderAssessmentCheck[]): SafeHtml {
  if (checks.length === 0) return html``;
  return html`
    <h3>${HEADER_KIND_LABEL[kind]} <span class="count">${checks.length}</span></h3>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Status</th><th>Header</th><th>Observed</th><th>Notes</th></tr></thead>
        <tbody>${checks.map(headerCheckRow)}</tbody>
      </table>
    </div>`;
}

function transportCheckCard(check: TransportTlsCheck): SafeHtml {
  const open = check.status === 'fail' || check.status === 'warn';
  return html`
    <details class="card" ${open ? OPEN_ATTR : ''}>
      <summary>${transportStatusBadge(check.status)} <span class="card-title">${check.title}</span></summary>
      <dl>
        <dt>Summary</dt><dd>${check.summary}</dd>
        <dt>Assessment</dt><dd>${check.assessment}</dd>
        ${check.guidance.length > 0
          ? html`<dt>Guidance</dt><dd><ul>${check.guidance.map(item => html`<li>${item}</li>`)}</ul></dd>`
          : ''}
      </dl>
    </details>`;
}

function summarySection(report: FullAssessmentReport): SafeHtml {
  const { severityCounts, headers, transport } = report;
  return html`
    <div class="summary">
      <div class="summary-group">
        <span class="summary-label">Findings</span>
        <span class="badge sev-high">High ${severityCounts.high}</span>
        <span class="badge sev-medium">Medium ${severityCounts.medium}</span>
        <span class="badge sev-low">Low ${severityCounts.low}</span>
        <span class="badge sev-info">Info ${severityCounts.info}</span>
      </div>
      <div class="summary-group">
        <span class="summary-label">Secure headers</span>
        <span class="badge st-pass">Pass ${headers.summary.pass}</span>
        <span class="badge st-fail">Fail ${headers.summary.fail}</span>
        <span class="badge st-warn">Warn ${headers.summary.warn}</span>
        <span class="badge st-na">N/A ${headers.summary['not-applicable']}</span>
      </div>
      <div class="summary-group">
        <span class="summary-label">Transport &amp; TLS</span>
        ${transportStatusBadge(transport.overallStatus)}
        <span class="summary-meta">${TRANSPORT_COVERAGE_LABEL[transport.coverage]} · ${TRANSPORT_CONFIDENCE_LABEL[transport.confidence]}</span>
      </div>
    </div>`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url || 'unknown';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stylesheet (static, trusted) — inline, offline, light + dark + print
// ─────────────────────────────────────────────────────────────────────────────

const REPORT_CSS = `
:root {
  --bg: #f7f8fa; --panel: #ffffff; --border: #e2e5ea; --text: #1b2029;
  --muted: #5c6470; --code-bg: #f0f2f5; --accent: #2563eb;
  --high-bg: #fdecec; --high-fg: #b42318; --medium-bg: #fef3e2; --medium-fg: #b25a00;
  --low-bg: #e8f0fe; --low-fg: #1a56c4; --info-bg: #eef0f3; --info-fg: #5c6470;
  --pass-bg: #e6f4ec; --pass-fg: #1a7f45; --na-bg: #eef0f3; --na-fg: #5c6470;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #2a313c; --text: #e6edf3;
    --muted: #9aa4b2; --code-bg: #1c222b; --accent: #58a6ff;
    --high-bg: #3a1a1a; --high-fg: #ff9a8f; --medium-bg: #3a2c14; --medium-fg: #f0b866;
    --low-bg: #142440; --low-fg: #8fb6ff; --info-bg: #21272f; --info-fg: #9aa4b2;
    --pass-bg: #12301f; --pass-fg: #6fd39a; --na-bg: #21272f; --na-fg: #9aa4b2;
  }
}
:root[data-theme="light"] {
  --bg: #f7f8fa; --panel: #ffffff; --border: #e2e5ea; --text: #1b2029;
  --muted: #5c6470; --code-bg: #f0f2f5; --accent: #2563eb;
  --high-bg: #fdecec; --high-fg: #b42318; --medium-bg: #fef3e2; --medium-fg: #b25a00;
  --low-bg: #e8f0fe; --low-fg: #1a56c4; --info-bg: #eef0f3; --info-fg: #5c6470;
  --pass-bg: #e6f4ec; --pass-fg: #1a7f45; --na-bg: #eef0f3; --na-fg: #5c6470;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 1rem 3rem; background: var(--bg); color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  font-size: 14px; line-height: 1.55;
}
main { max-width: 960px; margin: 0 auto; }
header { padding: 1.5rem 0 1rem; border-bottom: 1px solid var(--border); }
h1 { font-size: 1.4rem; margin: 0 0 .35rem; }
h2 { font-size: 1.1rem; margin: 2rem 0 .75rem; padding-bottom: .35rem; border-bottom: 1px solid var(--border); }
h3 { font-size: .95rem; margin: 1.25rem 0 .5rem; color: var(--muted); font-weight: 600; }
.url code { font-size: .85rem; word-break: break-all; }
.meta { color: var(--muted); font-size: .8rem; margin: .1rem 0; }
code { background: var(--code-bg); padding: .1em .35em; border-radius: 4px; font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size: .85em; }
.mono { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size: .82rem; }
.wrap { overflow-wrap: anywhere; word-break: break-word; }
.count { display: inline-block; min-width: 1.2em; padding: 0 .35em; margin-left: .25rem; border-radius: 999px; background: var(--info-bg); color: var(--info-fg); font-size: .7rem; text-align: center; }
.badge { display: inline-block; padding: .12em .55em; border-radius: 999px; font-size: .72rem; font-weight: 600; white-space: nowrap; }
.sev-high, .st-fail { background: var(--high-bg); color: var(--high-fg); }
.sev-medium, .st-warn { background: var(--medium-bg); color: var(--medium-fg); }
.sev-low { background: var(--low-bg); color: var(--low-fg); }
.sev-info, .st-na { background: var(--info-bg); color: var(--info-fg); }
.st-pass { background: var(--pass-bg); color: var(--pass-fg); }
.summary { display: flex; flex-wrap: wrap; gap: 1.25rem; margin-top: 1rem; }
.summary-group { display: flex; align-items: center; gap: .4rem; flex-wrap: wrap; }
.summary-label { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-right: .15rem; }
.summary-meta { color: var(--muted); font-size: .8rem; }
.card { background: var(--panel); border: 1px solid var(--border); border-left-width: 3px; border-radius: 6px; margin: .5rem 0; padding: .1rem .8rem; }
.card.sev-high { border-left-color: var(--high-fg); }
.card.sev-medium { border-left-color: var(--medium-fg); }
.card.sev-low { border-left-color: var(--low-fg); }
.card.sev-info { border-left-color: var(--info-fg); }
.card > summary { cursor: pointer; padding: .55rem 0; list-style: none; display: flex; align-items: center; gap: .5rem; }
.card > summary::-webkit-details-marker { display: none; }
.card-title { font-weight: 600; }
.card dl { margin: 0 0 .7rem; display: grid; grid-template-columns: max-content 1fr; gap: .2rem .9rem; }
.card dt { color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; padding-top: .15rem; }
.card dd { margin: 0; }
.card dd ul { margin: .1rem 0; padding-left: 1.1rem; }
.table-scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin: .25rem 0 .5rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: .7rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
.cell-note { font-size: .82rem; margin: .1rem 0; }
.note-label { color: var(--muted); font-size: .68rem; text-transform: uppercase; letter-spacing: .05em; margin-right: .3rem; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: .82rem; }
@media print {
  body { padding: 0; font-size: 11px; background: #fff; color: #000; }
  .card, table { break-inside: avoid; }
  .card > summary { list-style: none; }
}
`;

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

/** Render the full report as a single self-contained HTML document. */
export function renderReportHtml(report: FullAssessmentReport): string {
  const { headers, transport } = report;
  const primary = headers.primaryRequest
    ? `${headers.primaryRequest.method} ${headers.primaryRequest.url} (${headers.primaryRequest.statusCode})`
    : 'not captured';

  const doc = html`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP Web Security Assessment — ${hostOf(report.activeUrl)}</title>
<style>${raw(REPORT_CSS)}</style>
</head>
<body>
<main>
  <header>
    <h1>OWASP Web Security Assessment</h1>
    <p class="url"><code>${report.activeUrl || 'unknown'}</code></p>
    <p class="meta">Generated ${report.generatedAt} · Schema ${report.schemaVersion}</p>
    <p class="meta">Primary response: ${primary} · Captured requests: ${headers.capturedRequestCount}</p>
    ${summarySection(report)}
  </header>

  <section>
    <h2>OWASP Secure Headers</h2>
    ${headers.primaryRequest
      ? html`${HEADER_KIND_ORDER.map(kind => headerChecksTable(kind, headers.checks.filter(check => check.kind === kind)))}`
      : html`<p class="empty">No document response was captured, so header checks could not run.</p>`}
  </section>

  <section>
    <h2>Transport &amp; TLS</h2>
    <p>${transport.overview}</p>
    ${transport.checks.map(transportCheckCard)}
  </section>

  <section>
    <h2>Findings</h2>
    ${findingsGroup(report)}
  </section>

  <footer>
    <h2>Limitations</h2>
    <p>${REPORT_LIMITATIONS[0]}</p>
    <p>${REPORT_LIMITATIONS[1]}</p>
  </footer>
</main>
</body>
</html>`;

  return doc.value;
}
