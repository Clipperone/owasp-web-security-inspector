import React from 'react';
import type { TransportTlsCheck, TransportTlsReport, TransportTlsStatus, TransportTlsTheme } from '../types';
import { DisclosureCard, Field, StatusBadge, transportStatusLabel, transportStatusTone } from './ui';

const THEME_LABELS: Record<TransportTlsTheme, string> = {
  'https-adoption': 'HTTPS adoption',
  'sensitive-flows': 'Sensitive flows',
  hsts: 'HSTS',
  'downgrade-signals': 'Downgrade signals',
};

const THEME_ORDER: TransportTlsTheme[] = [
  'https-adoption',
  'sensitive-flows',
  'hsts',
  'downgrade-signals',
];

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
  return (
    <DisclosureCard
      badge={<StatusBadge tone={transportStatusTone(check.status)}>{transportStatusLabel(check.status).toUpperCase()}</StatusBadge>}
      title={THEME_LABELS[check.theme]}
    >
      <Field label="Observed facts">
        {check.observedFacts.length === 0 ? (
          <span className="text-gray-500">No browser-visible facts were captured for this check.</span>
        ) : (
          <ul className="space-y-1">
            {check.observedFacts.map(fact => <li key={fact}>{fact}</li>)}
          </ul>
        )}
      </Field>
      <Field label="Assessment">{check.assessment}</Field>
      {check.guidance.length > 0 && (
        <Field label="Guidance">
          <ul className="space-y-1">
            {check.guidance.map(item => <li key={item}>{item}</li>)}
          </ul>
        </Field>
      )}
      <Field label="Evidence references">
        {check.evidenceRefs.length === 0 ? (
          <span className="text-gray-500">No direct browser-visible evidence reference was available for this check.</span>
        ) : (
          <ul className="space-y-1">
            {check.evidenceRefs.map(reference => (
              <li key={`${reference.kind}-${reference.label}-${reference.detail}`} className="break-words">
                <span className="text-gray-500 uppercase text-[10px] tracking-widest mr-2">{reference.kind}</span>
                <span className="text-gray-100">{reference.label}</span>
                <span className="text-gray-500"> · </span>
                <span className="font-mono text-gray-400">{reference.detail}</span>
              </li>
            ))}
          </ul>
        )}
      </Field>
    </DisclosureCard>
  );
}

export function TransportTlsPanel({ report }: { report: TransportTlsReport }): React.JSX.Element {
  const checks = sortChecks(report.checks);

  return (
    <div className="border border-gray-800 rounded overflow-hidden bg-gray-950/20">
      {checks.map(check => <TransportTlsCheckCard key={check.id} check={check} />)}
    </div>
  );
}
