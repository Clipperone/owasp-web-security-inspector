import React from 'react';
import type { AssessmentFinding } from '../types';
import {
  DisclosureCard,
  EmptyState,
  Field,
  StatusBadge,
  severityLabel,
  severityTone,
} from './ui';

/** A single assessment finding rendered with the shared disclosure layout. */
export function FindingCard({ finding }: { finding: AssessmentFinding }): React.JSX.Element {
  return (
    <DisclosureCard
      badge={<StatusBadge tone={severityTone(finding.severity)}>{severityLabel(finding.severity).toUpperCase()}</StatusBadge>}
      title={finding.title}
    >
      <Field label="Summary">{finding.summary}</Field>
      {finding.whyItMatters && <Field label="Why it matters">{finding.whyItMatters}</Field>}
      <Field label="Evidence" mono>{finding.evidence}</Field>
      <Field label="Remediation">{finding.remediation}</Field>
    </DisclosureCard>
  );
}

/** A list of findings, or a consistent empty state when there are none. */
export function FindingList({
  findings,
  emptyTitle,
  emptyHint,
}: {
  findings: AssessmentFinding[];
  emptyTitle: string;
  emptyHint?: string;
}): React.JSX.Element {
  if (findings.length === 0) {
    return <EmptyState tone="ok" title={emptyTitle}>{emptyHint}</EmptyState>;
  }

  return (
    <div className="border border-gray-800 rounded overflow-hidden bg-gray-950/20">
      {findings.map(finding => <FindingCard key={finding.id} finding={finding} />)}
    </div>
  );
}
