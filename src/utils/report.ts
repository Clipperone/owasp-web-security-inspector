/**
 * Unified assessment report.
 *
 * One report model and one set of serializers (Markdown + JSON) covering every
 * assessment category — OWASP secure headers, transport & TLS, and the
 * cookie / token / storage findings — so the panel exports a single coherent
 * document instead of per-subtab fragments.
 */
import type {
  AssessmentCategory,
  AssessmentFinding,
  AssessmentSeverity,
  HeaderAssessmentKind,
  HeaderAssessmentReport,
  HeaderAssessmentStatus,
  TransportTlsConfidence,
  TransportTlsCoverage,
  TransportTlsReport,
  TransportTlsStatus,
} from '../types';
import { getFindingCounts, isActionableFinding } from './assessment';

/**
 * Version of the exported report shape, so CI consumers and issue templates can
 * pin against a stable contract. Bump the minor for additive changes and the
 * major for any rename/removal/type change of an existing field.
 */
export const REPORT_SCHEMA_VERSION = '1.0' as const;

export interface FullAssessmentReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  generatedAt: string;
  activeUrl: string;
  headers: HeaderAssessmentReport;
  transport: TransportTlsReport;
  findings: AssessmentFinding[];
  severityCounts: Record<AssessmentSeverity, number>;
}

/** Assemble the cross-category report from already-computed pieces. */
export function buildFullAssessmentReport(params: {
  generatedAt: string;
  activeUrl: string;
  headers: HeaderAssessmentReport;
  transport: TransportTlsReport;
  findings: AssessmentFinding[];
}): FullAssessmentReport {
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: params.generatedAt,
    activeUrl: params.activeUrl,
    headers: params.headers,
    transport: params.transport,
    findings: params.findings,
    severityCounts: getFindingCounts(params.findings),
  };
}

/** Minimum severity to include when exporting/displaying. `medium` means High + Medium. */
export type MinSeverity = 'all' | 'high' | 'medium' | 'low';

export interface ReportFilter {
  minSeverity?: MinSeverity;
  categories?: AssessmentCategory[];
  /** Keep only actionable findings (severity !== 'info'). */
  onlyActionable?: boolean;
  /** Case-insensitive substring matched against a finding's text fields. */
  search?: string;
}

const SEVERITY_RANK: Record<AssessmentSeverity, number> = { high: 3, medium: 2, low: 1, info: 0 };
const MIN_SEVERITY_RANK: Record<MinSeverity, number> = { all: 0, low: 1, medium: 2, high: 3 };

function findingMatchesSearch(finding: AssessmentFinding, needle: string): boolean {
  return (
    finding.title.toLowerCase().includes(needle)
    || finding.summary.toLowerCase().includes(needle)
    || finding.evidence.toLowerCase().includes(needle)
    || finding.remediation.toLowerCase().includes(needle)
    || (finding.whyItMatters?.toLowerCase().includes(needle) ?? false)
  );
}

/** Filter findings by minimum severity, category, actionability, and text search. */
export function filterFindings(findings: AssessmentFinding[], filter?: ReportFilter): AssessmentFinding[] {
  const minRank = MIN_SEVERITY_RANK[filter?.minSeverity ?? 'all'];
  const categories = filter?.categories;
  const onlyActionable = filter?.onlyActionable ?? false;
  const search = filter?.search?.trim().toLowerCase() ?? '';

  return findings.filter(finding => {
    if (SEVERITY_RANK[finding.severity] < minRank) return false;
    if (categories !== undefined && !categories.includes(finding.category)) return false;
    if (onlyActionable && !isActionableFinding(finding)) return false;
    if (search !== '' && !findingMatchesSearch(finding, search)) return false;
    return true;
  });
}

/**
 * Return a copy of the report with its findings filtered and `severityCounts`
 * recomputed. The header and transport check sections are left intact (they are
 * pass/fail/warn checks, not severity-typed findings). This is also the seam a
 * future snapshot diff (M3) reuses to scope both sides before comparing.
 */
export function filterReport(report: FullAssessmentReport, filter?: ReportFilter): FullAssessmentReport {
  const findings = filterFindings(report.findings, filter);
  return { ...report, findings, severityCounts: getFindingCounts(findings) };
}

const HEADER_STATUS_LABEL: Record<HeaderAssessmentStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  'not-applicable': 'N/A',
};

const HEADER_KIND_LABEL: Record<HeaderAssessmentKind, string> = {
  required: 'Required',
  advisory: 'Advisory',
  deprecated: 'Should Be Absent',
};

const HEADER_KIND_ORDER: HeaderAssessmentKind[] = ['required', 'advisory', 'deprecated'];

const TRANSPORT_STATUS_LABEL: Record<TransportTlsStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  inconclusive: 'Inconclusive',
};

const TRANSPORT_COVERAGE_LABEL: Record<TransportTlsCoverage, string> = {
  broad: 'Broad coverage',
  partial: 'Partial coverage',
  limited: 'Limited coverage',
};

const TRANSPORT_CONFIDENCE_LABEL: Record<TransportTlsConfidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
};

const SEVERITY_LABEL: Record<AssessmentSeverity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const FINDING_CATEGORY_LABEL: Record<AssessmentCategory, string> = {
  cookies: 'Cookies',
  tokens: 'Tokens',
  storage: 'Storage',
  headers: 'Headers',
  transport: 'Transport',
};

const FINDING_CATEGORY_ORDER: AssessmentCategory[] = ['cookies', 'tokens', 'storage', 'headers', 'transport'];

/** Render the full report as a reviewer-friendly Markdown document. */
export function renderReportMarkdown(report: FullAssessmentReport): string {
  const lines: string[] = [];
  const { headers, transport } = report;

  lines.push('# OWASP Web Security Assessment');
  lines.push('');
  lines.push(`- Generated: ${report.generatedAt}`);
  lines.push(`- Active URL: ${report.activeUrl || 'unknown'}`);
  lines.push(
    `- Primary response: ${headers.primaryRequest ? `${headers.primaryRequest.method} ${headers.primaryRequest.url} (${headers.primaryRequest.statusCode})` : 'not captured'}`,
  );
  lines.push(`- Captured requests: ${headers.capturedRequestCount}`);
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push(`- Findings — High: ${report.severityCounts.high}, Medium: ${report.severityCounts.medium}, Low: ${report.severityCounts.low}, Info: ${report.severityCounts.info}`);
  lines.push(`- Secure headers — Pass: ${headers.summary.pass}, Fail: ${headers.summary.fail}, Warn: ${headers.summary.warn}, N/A: ${headers.summary['not-applicable']}`);
  lines.push(`- Transport & TLS — Overall: ${TRANSPORT_STATUS_LABEL[transport.overallStatus]} (${TRANSPORT_COVERAGE_LABEL[transport.coverage]}, ${TRANSPORT_CONFIDENCE_LABEL[transport.confidence]})`);
  lines.push('');

  // OWASP Secure Headers
  lines.push('## OWASP Secure Headers');
  lines.push('');
  if (!headers.primaryRequest) {
    lines.push('No document response was captured, so header checks could not run.');
    lines.push('');
  } else {
    HEADER_KIND_ORDER.forEach(kind => {
      const checks = headers.checks.filter(check => check.kind === kind);
      if (checks.length === 0) return;
      lines.push(`### ${HEADER_KIND_LABEL[kind]}`);
      lines.push('');
      checks.forEach(check => {
        lines.push(`- [${HEADER_STATUS_LABEL[check.status].toUpperCase()}] ${check.headerName} — ${check.summary}`);
        lines.push(`  - Expected: ${check.expected}`);
        lines.push(`  - Observed: ${check.observedValues.length > 0 ? check.observedValues.join(' | ') : 'Not observed'}`);
        lines.push(`  - Remediation: ${check.remediation}`);
      });
      lines.push('');
    });
  }

  // Transport & TLS
  lines.push('## Transport & TLS');
  lines.push('');
  lines.push(transport.overview);
  lines.push('');
  transport.checks.forEach(check => {
    lines.push(`### [${TRANSPORT_STATUS_LABEL[check.status].toUpperCase()}] ${check.title}`);
    lines.push(`- ${check.summary}`);
    lines.push(`- Assessment: ${check.assessment}`);
    if (check.guidance.length > 0) {
      lines.push('- Guidance:');
      check.guidance.forEach(item => lines.push(`  - ${item}`));
    }
    lines.push('');
  });

  // Cookie / token / storage / header findings
  lines.push('## Findings');
  lines.push('');
  if (report.findings.length === 0) {
    lines.push('No cookie, token, or storage findings were raised in the captured context.');
    lines.push('');
  } else {
    FINDING_CATEGORY_ORDER.forEach(category => {
      const items = report.findings.filter(finding => finding.category === category);
      if (items.length === 0) return;
      lines.push(`### ${FINDING_CATEGORY_LABEL[category]}`);
      lines.push('');
      items.forEach(finding => {
        lines.push(`- [${SEVERITY_LABEL[finding.severity].toUpperCase()}] ${finding.title}`);
        lines.push(`  - Summary: ${finding.summary}`);
        if (finding.whyItMatters) lines.push(`  - Why it matters: ${finding.whyItMatters}`);
        lines.push(`  - Evidence: ${finding.evidence}`);
        lines.push(`  - Remediation: ${finding.remediation}`);
      });
      lines.push('');
    });
  }

  lines.push('## Limitations');
  lines.push('');
  lines.push('This assessment is browser-side only. It reviews what the browser can observe — cookies, web storage, response headers, and transport signals — and does not verify backend session invalidation, secret strength, server-side session rotation, or formal OWASP ASVS compliance. JWT signatures can be verified on demand in the Tokens tab but are not part of this report.');
  lines.push('Subresource Integrity is checked against the document DOM captured at scan time (dynamically injected resources may be missed), WebSockets opened before the extension started observing are not seen, and the third-party inventory uses an approximate eTLD+1 heuristic rather than a full public-suffix list.');
  lines.push('');

  return lines.join('\n');
}

/** Render the full report as pretty-printed JSON. */
export function renderReportJson(report: FullAssessmentReport): string {
  return JSON.stringify(report, null, 2);
}
