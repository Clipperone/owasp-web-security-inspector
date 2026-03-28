import React, { useState } from 'react';
import type {
  TransportTlsCheck,
  TransportTlsConfidence,
  TransportTlsCoverage,
  TransportTlsReport,
  TransportTlsStatus,
  TransportTlsTheme,
} from '../types';

const STATUS_LABELS: Record<TransportTlsStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  inconclusive: 'Inconclusive',
};

const THEME_LABELS: Record<TransportTlsTheme, string> = {
  'https-adoption': 'HTTPS adoption',
  'sensitive-flows': 'Sensitive flows',
  hsts: 'HSTS',
  'downgrade-signals': 'Downgrade signals',
  'certificate-trust': 'Certificate trust',
  'tls-posture': 'TLS posture',
};

const THEME_ORDER: TransportTlsTheme[] = [
  'https-adoption',
  'sensitive-flows',
  'hsts',
  'downgrade-signals',
  'certificate-trust',
  'tls-posture',
];

function statusClasses(status: TransportTlsStatus): string {
  switch (status) {
    case 'pass':
      return 'text-emerald-300 bg-emerald-950/40 border-emerald-900/60';
    case 'fail':
      return 'text-red-300 bg-red-950/40 border-red-900/60';
    case 'warn':
      return 'text-amber-300 bg-amber-950/40 border-amber-900/60';
    case 'inconclusive':
      return 'text-sky-300 bg-sky-950/40 border-sky-900/60';
  }
}

function confidenceLabel(confidence: TransportTlsConfidence): string {
  switch (confidence) {
    case 'high':
      return 'High confidence';
    case 'medium':
      return 'Medium confidence';
    case 'low':
      return 'Low confidence';
  }
}

function coverageLabel(coverage: TransportTlsCoverage): string {
  switch (coverage) {
    case 'broad':
      return 'Broad coverage';
    case 'partial':
      return 'Partial coverage';
    case 'limited':
      return 'Limited coverage';
  }
}

function sortChecks(checks: TransportTlsCheck[]): TransportTlsCheck[] {
  const rank: Record<TransportTlsStatus, number> = {
    fail: 0,
    warn: 1,
    pass: 2,
    inconclusive: 3,
  };
  const order = new Map(THEME_ORDER.map((theme, index) => [theme, index]));

  return [...checks].sort((left, right) => {
    const themeDelta = (order.get(left.theme) ?? 99) - (order.get(right.theme) ?? 99);
    if (themeDelta !== 0) return themeDelta;

    const statusDelta = rank[left.status] - rank[right.status];
    if (statusDelta !== 0) return statusDelta;

    return left.title.localeCompare(right.title);
  });
}

function TransportTlsCheckCard({ check }: { check: TransportTlsCheck }): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);

  return (
    <section className="border border-gray-800 rounded overflow-hidden bg-gray-950/20">
      <button
        type="button"
        onClick={() => setExpanded(current => !current)}
        className="w-full px-3 py-2 text-left hover:bg-gray-900/20 transition-colors"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h3 className="text-[12px] text-gray-100 font-semibold">{THEME_LABELS[check.theme]}</h3>
          </div>
          <div className="flex items-center gap-2 shrink-0 pt-px">
            <span className={`px-1.5 py-px text-[9px] font-bold border rounded shrink-0 ${statusClasses(check.status)}`}>
              {STATUS_LABELS[check.status].toUpperCase()}
            </span>
            <p className="text-[11px] text-gray-500">{expanded ? '−' : '+'}</p>
          </div>
        </div>
      </button>
      {expanded && (
        <div className="px-3 pb-3 pt-2 border-t border-gray-800 space-y-3">
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Observed facts</p>
            <ul className="space-y-1">
              {check.observedFacts.map(fact => (
                <li key={fact} className="text-[11px] text-gray-300 leading-relaxed">{fact}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Assessment</p>
            <p className="text-[11px] text-gray-300 leading-relaxed">{check.assessment}</p>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Guidance</p>
            <ul className="space-y-1">
              {check.guidance.map(item => (
                <li key={item} className="text-[11px] text-gray-400 leading-relaxed">{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Evidence references</p>
            {check.evidenceRefs.length === 0 ? (
              <p className="text-[11px] text-gray-500 leading-relaxed">No direct browser-visible evidence reference was available for this check.</p>
            ) : (
              <ul className="space-y-1">
                {check.evidenceRefs.map(reference => (
                  <li key={`${reference.kind}-${reference.label}-${reference.detail}`} className="text-[11px] text-gray-300 break-words">
                    <span className="text-gray-500 uppercase text-[10px] tracking-widest mr-2">{reference.kind}</span>
                    <span className="text-gray-100">{reference.label}</span>
                    <span className="text-gray-500"> · </span>
                    <span className="font-mono text-gray-400">{reference.detail}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export function buildTransportTlsMarkdownReport(report: TransportTlsReport): string {
  const lines = [
    '# Transport & TLS Assessment',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Active URL: ${report.activeUrl || 'unknown'}`,
    `Overall status: ${STATUS_LABELS[report.overallStatus]}`,
    `Coverage: ${coverageLabel(report.coverage)}`,
    `Confidence: ${confidenceLabel(report.confidence)}`,
    '',
    report.overview,
    '',
    `- Pass: ${report.summary.pass}`,
    `- Fail: ${report.summary.fail}`,
    `- Warn: ${report.summary.warn}`,
    `- Inconclusive: ${report.summary.inconclusive}`,
    '',
  ];

  sortChecks(report.checks).forEach((check, index) => {
    lines.push(`## ${index + 1}. ${THEME_LABELS[check.theme]}`);
    lines.push(`Status: ${STATUS_LABELS[check.status]}`);
    lines.push(`Confidence: ${confidenceLabel(check.confidence)}`);
    lines.push(`Coverage: ${coverageLabel(check.coverage)}`);
    lines.push(`Summary: ${check.summary}`);
    lines.push('Observed facts:');
    check.observedFacts.forEach(fact => lines.push(`- ${fact}`));
    lines.push(`Assessment: ${check.assessment}`);
    lines.push('Guidance:');
    check.guidance.forEach(item => lines.push(`- ${item}`));
    lines.push('Evidence references:');
    if (check.evidenceRefs.length === 0) {
      lines.push('- No direct browser-visible evidence reference was available.');
    } else {
      check.evidenceRefs.forEach(reference => lines.push(`- [${reference.kind}] ${reference.label}: ${reference.detail}`));
    }
    lines.push('');
  });

  return lines.join('\n');
}

export function TransportTlsPanel({ report }: { report: TransportTlsReport }): React.JSX.Element {
  const checks = sortChecks(report.checks);

  return (
    <div className="p-2.5 space-y-3">
      {checks.map(check => <TransportTlsCheckCard key={check.id} check={check} />)}
    </div>
  );
}