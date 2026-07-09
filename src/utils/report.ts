/**
 * Unified assessment report.
 *
 * One report model covering every assessment category — OWASP secure headers,
 * transport & TLS, and the cookie / token / storage findings — so the panel
 * exports a single coherent document instead of per-subtab fragments. The sole
 * serializer is the self-contained HTML renderer in `reportHtml.ts`, which
 * reuses the label/order/limitations constants exported here.
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

export const HEADER_STATUS_LABEL: Record<HeaderAssessmentStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  'not-applicable': 'N/A',
};

export const HEADER_KIND_LABEL: Record<HeaderAssessmentKind, string> = {
  required: 'Required',
  advisory: 'Advisory',
  deprecated: 'Should Be Absent',
};

export const HEADER_KIND_ORDER: HeaderAssessmentKind[] = ['required', 'advisory', 'deprecated'];

export const TRANSPORT_STATUS_LABEL: Record<TransportTlsStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  inconclusive: 'Inconclusive',
};

export const TRANSPORT_COVERAGE_LABEL: Record<TransportTlsCoverage, string> = {
  broad: 'Broad coverage',
  partial: 'Partial coverage',
  limited: 'Limited coverage',
};

export const TRANSPORT_CONFIDENCE_LABEL: Record<TransportTlsConfidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
};

export const SEVERITY_LABEL: Record<AssessmentSeverity, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const FINDING_CATEGORY_LABEL: Record<AssessmentCategory, string> = {
  cookies: 'Cookies',
  tokens: 'Tokens',
  storage: 'Storage',
  headers: 'Headers',
  transport: 'Transport',
};

export const FINDING_CATEGORY_ORDER: AssessmentCategory[] = ['cookies', 'tokens', 'storage', 'headers', 'transport'];

/**
 * The fixed limitations disclaimer, as discrete paragraphs so every serializer
 * renders the same scope caveats.
 */
export const REPORT_LIMITATIONS: readonly [string, string] = [
  'This assessment is browser-side only. It reviews what the browser can observe — cookies, web storage, response headers, and transport signals — and does not verify backend session invalidation, secret strength, server-side session rotation, or formal OWASP ASVS compliance. JWT signatures can be verified on demand in the Tokens tab but are not part of this report.',
  'Subresource Integrity is checked against the document DOM captured at scan time (dynamically injected resources may be missed), WebSockets opened before the extension started observing are not seen, and the third-party inventory uses an approximate eTLD+1 heuristic rather than a full public-suffix list. Detected storage secrets and PII are redacted before display and export.',
];
