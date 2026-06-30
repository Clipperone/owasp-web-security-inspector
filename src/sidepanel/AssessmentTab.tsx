import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  ActiveTabInfo,
  CachedRequest,
  HeaderAssessmentCheck,
  HeaderAssessmentKind,
  HeaderAssessmentReport,
  HeaderAssessmentStatus,
  StorageScanResult,
  TransportDomObservation,
} from '../types';
import { buildAssessmentFindings, getOwaspHeaderAssessment } from '../utils/assessment';
import { buildTransportTlsSection } from '../utils/transportTls';
import { buildFullAssessmentReport, renderReportJson, renderReportMarkdown } from '../utils/report';
import { TransportTlsPanel } from './TransportTlsPanel';
import { FindingList } from './FindingCard';
import {
  DisclosureCard,
  EmptyState,
  Field,
  Section,
  StatusBadge,
  headerStatusLabel,
  headerStatusTone,
  toneTextClasses,
} from './ui';

type AssessmentSubtabId = 'headers' | 'transport' | 'cookies' | 'tokens' | 'storage';

const ASSESSMENT_SUBTABS: Array<{ id: AssessmentSubtabId; label: string }> = [
  { id: 'headers', label: 'Headers' },
  { id: 'transport', label: 'Transport' },
  { id: 'cookies', label: 'Cookies' },
  { id: 'tokens', label: 'Tokens' },
  { id: 'storage', label: 'Storage' },
];

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

const HEADER_SECTION_ORDER: HeaderAssessmentKind[] = ['required', 'advisory', 'deprecated'];

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

function summarizeChecks(checks: HeaderAssessmentCheck[]): { fail: number; warn: number; pass: number } {
  return checks.reduce((acc, check) => {
    if (check.status === 'fail' || check.status === 'warn' || check.status === 'pass') {
      acc[check.status] += 1;
    }
    return acc;
  }, { fail: 0, warn: 0, pass: 0 });
}

function HeaderCheckCard({ check }: { check: HeaderAssessmentCheck }): React.JSX.Element {
  return (
    <DisclosureCard
      badge={<StatusBadge tone={headerStatusTone(check.status)}>{headerStatusLabel(check.status).toUpperCase()}</StatusBadge>}
      title={check.headerName}
    >
      <Field label="Summary">{check.summary}</Field>
      <Field label="Expected">{check.expected}</Field>
      <Field label="Observed" mono>
        {check.observedValues.length > 0 ? check.observedValues.join(' | ') : 'Not observed'}
      </Field>
      <Field label="Evidence">{check.evidence}</Field>
      <Field label="Remediation">{check.remediation}</Field>
    </DisclosureCard>
  );
}

function HeaderCheckSection({
  kind,
  checks,
  defaultOpen,
}: {
  kind: HeaderAssessmentKind;
  checks: HeaderAssessmentCheck[];
  defaultOpen?: boolean;
}): React.JSX.Element {
  const orderedChecks = sortChecks(checks);
  const summary = summarizeChecks(checks);

  return (
    <Section
      title={KIND_LABELS[kind]}
      defaultOpen={defaultOpen}
      meta={
        <>
          <span className="text-gray-500">{checks.length} checks</span>
          <span className={toneTextClasses('bad')}>Fail {summary.fail}</span>
          <span className={toneTextClasses('warn')}>Warn {summary.warn}</span>
          <span className={toneTextClasses('ok')}>Pass {summary.pass}</span>
        </>
      }
    >
      {orderedChecks.map(check => <HeaderCheckCard key={check.id} check={check} />)}
    </Section>
  );
}

export const AssessmentTab: React.FC = () => {
  const [activeSubtab, setActiveSubtab] = useState<AssessmentSubtabId>('headers');
  const [tabInfo, setTabInfo] = useState<ActiveTabInfo | null>(null);
  const [requests, setRequests] = useState<CachedRequest[]>([]);
  const [cookies, setCookies] = useState<chrome.cookies.Cookie[]>([]);
  const [transportObservation, setTransportObservation] = useState<TransportDomObservation | null>(null);
  const [storageScan, setStorageScan] = useState<StorageScanResult | null>(null);
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

      await Promise.all([
        chrome.runtime.sendMessage({ type: 'RUN_TRANSPORT_SCAN' }).catch(() => null),
        chrome.runtime.sendMessage({ type: 'RUN_STORAGE_SCAN' }).catch(() => null),
      ]);

      const [headersResponse, transportResponse, storageResponse, cookiesResponse] = await Promise.all([
        chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: info.tabId }),
        chrome.runtime.sendMessage({ type: 'GET_TRANSPORT_OBSERVATIONS' }),
        chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' }),
        chrome.runtime.sendMessage({ type: 'GET_COOKIES', payload: info.url }),
      ]);

      setRequests(headersResponse?.success ? (headersResponse.data as CachedRequest[] ?? []) : []);
      setTransportObservation(transportResponse?.success ? (transportResponse.data as TransportDomObservation | null ?? null) : null);
      setStorageScan(storageResponse?.success ? (storageResponse.data as StorageScanResult | null ?? null) : null);
      setCookies(cookiesResponse?.success ? (cookiesResponse.data as chrome.cookies.Cookie[] ?? []) : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assessment failed to load.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeUrl = tabInfo?.url ?? '';
  const storageEntries = useMemo(() => storageScan?.entries ?? [], [storageScan]);

  const headerReport = useMemo(() => getOwaspHeaderAssessment(activeUrl, requests), [activeUrl, requests]);
  const groupedChecks = useMemo(() => groupChecks(headerReport), [headerReport]);
  const transportReport = useMemo(
    () => buildTransportTlsSection({
      activeUrl,
      requests,
      domObservation: transportObservation,
      storageScan,
    }),
    [activeUrl, requests, storageScan, transportObservation],
  );

  const findings = useMemo(
    () => buildAssessmentFindings({ activeUrl, cookies, storageEntries, requests }),
    [activeUrl, cookies, storageEntries, requests],
  );

  const cookieFindings = useMemo(() => findings.filter(f => f.category === 'cookies'), [findings]);
  const tokenFindings = useMemo(() => findings.filter(f => f.category === 'tokens'), [findings]);
  const storageFindings = useMemo(() => findings.filter(f => f.category === 'storage'), [findings]);
  const headerFindings = useMemo(() => findings.filter(f => f.category === 'headers'), [findings]);

  const copyReport = useCallback(async (format: 'markdown' | 'json') => {
    const report = buildFullAssessmentReport({
      generatedAt: new Date().toISOString(),
      activeUrl,
      headers: headerReport,
      transport: transportReport,
      findings,
    });
    const payload = format === 'markdown' ? renderReportMarkdown(report) : renderReportJson(report);

    try {
      await navigator.clipboard.writeText(payload);
      setCopyToast(format === 'markdown' ? 'Full Markdown report copied.' : 'Full JSON report copied.');
      window.setTimeout(() => setCopyToast(null), 2200);
    } catch {
      setCopyToast('Clipboard copy failed.');
      window.setTimeout(() => setCopyToast(null), 2200);
    }
  }, [activeUrl, headerReport, transportReport, findings]);

  const metaLine = (() => {
    switch (activeSubtab) {
      case 'transport':
        return `HTTPS requests: ${transportReport.observedHttpsRequestCount} · HTTP requests: ${transportReport.observedHttpRequestCount} · HTTP links in DOM: ${transportObservation?.absoluteHttpLinks.length ?? 0}`;
      case 'cookies':
        return `Cookies in jar: ${cookies.length} · Cookie findings: ${cookieFindings.length}`;
      case 'tokens':
        return `Token findings: ${tokenFindings.length}`;
      case 'storage':
        return `Storage entries scanned: ${storageEntries.length} · Storage findings: ${storageFindings.length}`;
      case 'headers':
      default:
        return `Captured requests: ${headerReport.capturedRequestCount} · Logout-like: ${headerReport.logoutRequestCount} · Observed headers: ${headerReport.observedHeaderNames.length}`;
    }
  })();

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-800 bg-gray-900/30 shrink-0">
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
            Browser security assessment
          </p>
          <p className="text-[11px] text-gray-400 font-mono truncate" title={activeUrl}>
            {activeUrl || 'Loading active tab...'}
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
          title="Copy the full assessment report (all categories) in Markdown"
        >
          Copy MD
        </button>
        <button
          onClick={() => { void copyReport('json'); }}
          className="px-1.5 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-purple-400 hover:border-purple-800/50 rounded transition-colors shrink-0"
          title="Copy the full assessment report (all categories) in JSON"
        >
          Copy JSON
        </button>
      </div>

      <div className="px-2.5 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0 space-y-2">
        <div className="grid grid-cols-5 gap-1">
          {ASSESSMENT_SUBTABS.map(tab => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveSubtab(tab.id)}
              className={[
                'rounded border px-1.5 py-1 text-center text-[11px] font-medium transition-colors min-w-0 truncate',
                activeSubtab === tab.id
                  ? 'border-blue-800/60 bg-blue-950/30 text-blue-200'
                  : 'border-gray-700 bg-gray-900/60 text-gray-300 hover:text-white hover:border-gray-600',
              ].join(' ')}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-[10px] text-gray-500">
          <span>{metaLine}</span>
          {copyToast && <span className="text-emerald-400">{copyToast}</span>}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-2.5 space-y-3">
        {loading ? (
          <div className="flex items-center justify-center h-full text-gray-700 text-[11px]">
            Building assessment...
          </div>
        ) : error ? (
          <div className="text-[11px] text-red-300">{error}</div>
        ) : activeSubtab === 'headers' ? (
          !headerReport.primaryRequest ? (
            <EmptyState tone="warn" title="No captured response headers yet">
              Reload or navigate the page so the extension can capture the document response before running the OWASP Secure Headers checks.
            </EmptyState>
          ) : (
            <>
              {HEADER_SECTION_ORDER.map(kind => (
                <HeaderCheckSection
                  key={kind}
                  kind={kind}
                  checks={groupedChecks[kind]}
                  defaultOpen={kind === 'required'}
                />
              ))}
              {headerFindings.length > 0 && (
                <Section title="Additional header & CORS findings" meta={<span className="text-gray-500">{headerFindings.length}</span>}>
                  <FindingList findings={headerFindings} emptyTitle="No additional header findings" />
                </Section>
              )}
            </>
          )
        ) : activeSubtab === 'transport' ? (
          <TransportTlsPanel report={transportReport} />
        ) : activeSubtab === 'cookies' ? (
          <FindingList
            findings={cookieFindings}
            emptyTitle="No cookie findings"
            emptyHint="No risky cookie attributes or Set-Cookie patterns were observed in the captured context."
          />
        ) : activeSubtab === 'tokens' ? (
          <FindingList
            findings={tokenFindings}
            emptyTitle="No token findings"
            emptyHint="No JWT or opaque token risks were observed in cookies or web storage for this context."
          />
        ) : (
          <FindingList
            findings={storageFindings}
            emptyTitle="No storage findings"
            emptyHint="No sensitive tokens were observed in localStorage or sessionStorage for this context."
          />
        )}
      </div>
    </div>
  );
};
