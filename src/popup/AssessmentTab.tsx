import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  ActiveTabInfo,
  CachedRequest,
  HeaderAssessmentCheck,
  HeaderAssessmentKind,
  HeaderAssessmentReport,
  HeaderAssessmentStatus,
} from '../types';
import { getOwaspHeaderAssessment } from '../utils/assessment';

type AssessmentSubtabId = 'headers' | 'cookies' | 'tokens' | 'storage';

const ASSESSMENT_SUBTABS: Array<{
  id: AssessmentSubtabId;
  label: string;
  enabled: boolean;
}> = [
  {
    id: 'headers',
    label: 'Headers',
    enabled: true,
  },
  {
    id: 'cookies',
    label: 'Cookies',
    enabled: false,
  },
  {
    id: 'tokens',
    label: 'Tokens',
    enabled: false,
  },
  {
    id: 'storage',
    label: 'Storage',
    enabled: false,
  },
];

const STATUS_LABELS: Record<HeaderAssessmentStatus, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warn: 'Warn',
  'not-applicable': 'N/A',
};

const KIND_LABELS: Record<HeaderAssessmentKind, string> = {
  required: 'Required',
  deprecated: 'Should Be Absent',
  advisory: 'Advisory',
};

const STATUS_SORT_WEIGHT: Record<HeaderAssessmentStatus, number> = {
  fail: 0,
  warn: 1,
  pass: 2,
  'not-applicable': 3,
};

function statusClasses(status: HeaderAssessmentStatus): string {
  switch (status) {
    case 'pass':
      return 'text-emerald-300 bg-emerald-950/40 border-emerald-900/60';
    case 'fail':
      return 'text-red-300 bg-red-950/40 border-red-900/60';
    case 'warn':
      return 'text-amber-300 bg-amber-950/40 border-amber-900/60';
    case 'not-applicable':
      return 'text-gray-300 bg-gray-900/60 border-gray-700';
  }
}

function groupChecks(report: HeaderAssessmentReport): Record<HeaderAssessmentKind, HeaderAssessmentCheck[]> {
  return report.checks.reduce<Record<HeaderAssessmentKind, HeaderAssessmentCheck[]>>((acc, check) => {
    acc[check.kind].push(check);
    return acc;
  }, {
    required: [],
    deprecated: [],
    advisory: [],
  });
}

function sortChecks(checks: HeaderAssessmentCheck[]): HeaderAssessmentCheck[] {
  return [...checks].sort((left, right) => {
    const statusDelta = STATUS_SORT_WEIGHT[left.status] - STATUS_SORT_WEIGHT[right.status];
    if (statusDelta !== 0) return statusDelta;
    return left.headerName.localeCompare(right.headerName);
  });
}

function buildMarkdownReport(report: HeaderAssessmentReport): string {
  const lines = [
    '# OWASP Secure Headers Assessment',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Active URL: ${report.activeUrl || 'unknown'}`,
    `Captured requests: ${report.capturedRequestCount}`,
    `Logout-like requests: ${report.logoutRequestCount}`,
    `Primary response: ${report.primaryRequest ? `${report.primaryRequest.method} ${report.primaryRequest.url} (${report.primaryRequest.statusCode})` : 'not captured'}`,
    '',
    '## Summary',
    '',
    `- Pass: ${report.summary.pass}`,
    `- Fail: ${report.summary.fail}`,
    `- Warn: ${report.summary.warn}`,
    `- Not applicable: ${report.summary['not-applicable']}`,
    '',
  ];

  const grouped = groupChecks(report);
  const sections: HeaderAssessmentKind[] = ['required', 'deprecated', 'advisory'];

  sections.forEach(section => {
    lines.push(`## ${KIND_LABELS[section]}`);
    lines.push('');

    if (grouped[section].length === 0) {
      lines.push('- No checks in this section.');
      lines.push('');
      return;
    }

    grouped[section].forEach((check, index) => {
      lines.push(`${index + 1}. [${STATUS_LABELS[check.status].toUpperCase()}] ${check.headerName}`);
      lines.push(`Summary: ${check.summary}`);
      lines.push(`Expected: ${check.expected}`);
      lines.push(`Observed: ${check.observedValues.length > 0 ? check.observedValues.join(' | ') : 'Not observed'}`);
      lines.push(`Evidence: ${check.evidence}`);
      lines.push(`Remediation: ${check.remediation}`);
      lines.push('');
    });
  });

  return lines.join('\n');
}

function HeaderCheckCard({ check }: { check: HeaderAssessmentCheck }): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-gray-800/60 last:border-b-0">
      <button
        type="button"
        onClick={() => setExpanded(current => !current)}
        className="w-full px-3 py-2 text-left hover:bg-gray-900/20 transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className={`px-1.5 py-px text-[9px] font-bold border rounded ${statusClasses(check.status)}`}>
            {STATUS_LABELS[check.status].toUpperCase()}
          </span>
          <h3 className="text-[12px] text-gray-100 font-semibold flex-1 min-w-0">{check.headerName}</h3>
          <span className="text-[11px] text-gray-500 shrink-0">{expanded ? '−' : '+'}</span>
        </div>
      </button>
      {expanded && (
        <div className="px-3 pb-2 space-y-1.5">
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Summary</p>
            <p className="text-[11px] text-gray-300 leading-relaxed">{check.summary}</p>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Expected</p>
            <p className="text-[11px] text-gray-400 leading-relaxed">{check.expected}</p>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Observed</p>
            <p className="text-[11px] text-gray-300 font-mono break-words">
              {check.observedValues.length > 0 ? check.observedValues.join(' | ') : 'Not observed'}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Evidence</p>
            <p className="text-[11px] text-gray-300 leading-relaxed">{check.evidence}</p>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Remediation</p>
            <p className="text-[11px] text-gray-400 leading-relaxed">{check.remediation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function HeaderCheckSection({
  kind,
  checks,
}: {
  kind: HeaderAssessmentKind;
  checks: HeaderAssessmentCheck[];
}): React.JSX.Element {
  const orderedChecks = sortChecks(checks);

  return (
    <section className="border border-gray-800 rounded overflow-hidden bg-gray-950/20">
      <div className="px-3 py-2 border-b border-gray-800 bg-gray-950/40">
        <div className="flex items-center justify-between gap-3">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium">{KIND_LABELS[kind]}</p>
          <span className="text-[10px] text-gray-500">{checks.length} checks</span>
        </div>
      </div>
      <div>
        {orderedChecks.map(check => <HeaderCheckCard key={check.id} check={check} />)}
      </div>
    </section>
  );
}

export const AssessmentTab: React.FC = () => {
  const [activeSubtab, setActiveSubtab] = useState<AssessmentSubtabId>('headers');
  const [tabInfo, setTabInfo] = useState<ActiveTabInfo | null>(null);
  const [requests, setRequests] = useState<CachedRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copyToast, setCopyToast] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const tabResponse = await chrome.runtime.sendMessage({ type: 'GET_ACTIVE_TAB_INFO' });
      if (!tabResponse?.success || !tabResponse.data) {
        throw new Error(tabResponse?.error ?? 'Failed to load the active tab context.');
      }

      const info = tabResponse.data as ActiveTabInfo;
      setTabInfo(info);

      const headersResponse = await chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: info.tabId });
      setRequests(headersResponse?.success ? (headersResponse.data as CachedRequest[] ?? []) : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assessment failed to load.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const headerReport = useMemo(
    () => getOwaspHeaderAssessment(tabInfo?.url ?? '', requests),
    [requests, tabInfo?.url],
  );

  const groupedChecks = useMemo(() => groupChecks(headerReport), [headerReport]);

  const copyReport = useCallback(async (format: 'markdown' | 'json') => {
    const payload = format === 'markdown'
      ? buildMarkdownReport(headerReport)
      : JSON.stringify(headerReport, null, 2);

    try {
      await navigator.clipboard.writeText(payload);
      setCopyToast(format === 'markdown' ? 'Markdown report copied.' : 'JSON report copied.');
      window.setTimeout(() => setCopyToast(null), 2200);
    } catch {
      setCopyToast('Clipboard copy failed.');
      window.setTimeout(() => setCopyToast(null), 2200);
    }
  }, [headerReport]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-800 bg-gray-900/30 shrink-0">
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
            Browser security assessment
          </p>
          <p className="text-[11px] text-gray-400 font-mono truncate" title={tabInfo?.url ?? ''}>
            {tabInfo?.url ?? 'Loading active tab...'}
          </p>
        </div>
        <button
          onClick={() => { void load(); }}
          className="px-1.5 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-blue-400 hover:border-blue-800/50 rounded transition-colors shrink-0"
        >
          Refresh
        </button>
        <button
          onClick={() => { void copyReport('markdown'); }}
          className="px-1.5 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-emerald-400 hover:border-emerald-800/50 rounded transition-colors shrink-0"
          title="Copy the current OWASP Secure Headers report in Markdown"
        >
          Copy MD
        </button>
        <button
          onClick={() => { void copyReport('json'); }}
          className="px-1.5 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-purple-400 hover:border-purple-800/50 rounded transition-colors shrink-0"
          title="Copy the current OWASP Secure Headers report in JSON"
        >
          Copy JSON
        </button>
      </div>

      <div className="px-2.5 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0 space-y-2">
        <div className="grid grid-cols-4 gap-1">
          {ASSESSMENT_SUBTABS.map(tab => (
            <button
              key={tab.id}
              type="button"
              disabled={!tab.enabled}
              onClick={() => tab.enabled && setActiveSubtab(tab.id)}
              className={[
                'rounded border px-1.5 py-1 text-center transition-colors min-w-0',
                tab.enabled
                  ? activeSubtab === tab.id
                    ? 'border-blue-800/60 bg-blue-950/30 text-blue-200'
                    : 'border-gray-700 bg-gray-900/60 text-gray-300 hover:text-white hover:border-gray-600'
                  : 'border-gray-800 bg-gray-950/40 text-gray-600 cursor-not-allowed',
              ].join(' ')}
            >
              <div className="flex items-center justify-center gap-1 min-w-0">
                <span className="text-[11px] font-medium truncate">{tab.label}</span>
                {!tab.enabled && (
                  <span className="px-1 py-px text-[8px] uppercase tracking-widest border border-gray-800 rounded text-gray-500 shrink-0">
                    Soon
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-[10px] text-gray-500">
          <span>Captured requests: <span className="text-gray-300">{headerReport.capturedRequestCount}</span></span>
          <span>Logout-like requests: <span className="text-gray-300">{headerReport.logoutRequestCount}</span></span>
          <span>Observed primary headers: <span className="text-gray-300">{headerReport.observedHeaderNames.length}</span></span>
          {copyToast && <span className="text-emerald-400">{copyToast}</span>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center h-full text-gray-700 text-[11px]">
            Building assessment...
          </div>
        ) : error ? (
          <div className="p-4 text-[11px] text-red-300">
            {error}
          </div>
        ) : activeSubtab !== 'headers' ? (
          <div className="p-4 space-y-2 text-[11px]">
            <p className="text-gray-200 font-semibold">This subtab is reserved for a later rollout.</p>
            <p className="text-gray-500">
              The Assessment area now exposes checks incrementally. Headers is the first active subtab; cookie, token, and storage checks will move here in the next steps.
            </p>
          </div>
        ) : !headerReport.primaryRequest ? (
          <div className="p-4 space-y-2 text-[11px]">
            <p className="text-amber-300 font-semibold">No captured response headers yet.</p>
            <p className="text-gray-500">
              Reload or navigate the page so the extension can capture the document response before running the OWASP Secure Headers checks.
            </p>
          </div>
        ) : (
          <div className="p-2.5 space-y-3">
            <HeaderCheckSection kind="required" checks={groupedChecks.required} />
            <HeaderCheckSection kind="deprecated" checks={groupedChecks.deprecated} />
            <HeaderCheckSection kind="advisory" checks={groupedChecks.advisory} />
          </div>
        )}
      </div>
    </div>
  );
};