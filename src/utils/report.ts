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
import { getFindingCounts } from './assessment';

export interface FullAssessmentReport {
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
    generatedAt: params.generatedAt,
    activeUrl: params.activeUrl,
    headers: params.headers,
    transport: params.transport,
    findings: params.findings,
    severityCounts: getFindingCounts(params.findings),
  };
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

const FINDING_CATEGORY_ORDER: AssessmentCategory[] = ['cookies', 'tokens', 'storage', 'headers'];

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
  lines.push('This assessment is browser-side only. It reviews what the browser can observe — cookies, web storage, response headers, and transport signals — and does not verify backend session invalidation, JWT signature trust, secret strength, server-side session rotation, or formal OWASP ASVS compliance.');
  lines.push('');

  return lines.join('\n');
}

/** Render the full report as pretty-printed JSON. */
export function renderReportJson(report: FullAssessmentReport): string {
  return JSON.stringify(report, null, 2);
}
