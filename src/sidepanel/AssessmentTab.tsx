import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  ActiveTabInfo,
  CachedRequest,
  CapturedRequestBody,
  HeaderAssessmentCheck,
  HeaderAssessmentKind,
  HeaderAssessmentReport,
  HeaderAssessmentStatus,
  ObservedWebSocket,
  PageResourceObservation,
  StorageScanResult,
  TransportDomObservation,
} from '../types';
import { buildAssessmentFindings, getOwaspHeaderAssessment } from '../utils/assessment';
import { buildTransportTlsSection } from '../utils/transportTls';
import { buildFullAssessmentReport, filterFindings, filterReport } from '../utils/report';
import { renderReportHtml } from '../utils/reportHtml';
import type { MinSeverity, ReportFilter } from '../utils/report';
import { buildReportFilename, downloadTextFile } from '../utils/exporter';
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

type AssessmentSubtabId = 'headers' | 'transport' | 'cookies' | 'tokens' | 'storage' | 'llm';

const ASSESSMENT_SUBTABS: Array<{ id: AssessmentSubtabId; label: string }> = [
  { id: 'headers', label: 'Headers' },
  { id: 'transport', label: 'Transport' },
  { id: 'cookies', label: 'Cookies' },
  { id: 'tokens', label: 'Tokens' },
  { id: 'storage', label: 'Storage' },
  { id: 'llm', label: 'LLM/AI' },
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

const SEVERITY_FILTER_OPTIONS: Array<{ value: MinSeverity; label: string }> = [
  { value: 'all', label: 'All severities' },
  { value: 'high', label: 'High only' },
  { value: 'medium', label: 'High + Medium' },
  { value: 'low', label: 'High + Med + Low' },
];

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
  const [pageResources, setPageResources] = useState<PageResourceObservation | null>(null);
  const [webSockets, setWebSockets] = useState<ObservedWebSocket[]>([]);
  const [requestBodies, setRequestBodies] = useState<CapturedRequestBody[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copyToast, setCopyToast] = useState<string | null>(null);
  const [minSeverity, setMinSeverity] = useState<MinSeverity>('all');
  const [onlyActionable, setOnlyActionable] = useState(false);
  const [search, setSearch] = useState('');

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
        chrome.runtime.sendMessage({ type: 'RUN_PAGE_RESOURCE_SCAN' }).catch(() => null),
      ]);

      const [headersResponse, transportResponse, storageResponse, cookiesResponse, pageResourcesResponse, webSocketsResponse, requestBodiesResponse] = await Promise.all([
        chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: info.tabId }),
        chrome.runtime.sendMessage({ type: 'GET_TRANSPORT_OBSERVATIONS' }),
        chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' }),
        chrome.runtime.sendMessage({ type: 'GET_COOKIES', payload: info.url }),
        chrome.runtime.sendMessage({ type: 'GET_PAGE_RESOURCES' }),
        chrome.runtime.sendMessage({ type: 'GET_TAB_WEBSOCKETS', payload: info.tabId }),
        chrome.runtime.sendMessage({ type: 'GET_TAB_REQUEST_BODIES', payload: info.tabId }),
      ]);

      setRequests(headersResponse?.success ? (headersResponse.data as CachedRequest[] ?? []) : []);
      setTransportObservation(transportResponse?.success ? (transportResponse.data as TransportDomObservation | null ?? null) : null);
      setStorageScan(storageResponse?.success ? (storageResponse.data as StorageScanResult | null ?? null) : null);
      setCookies(cookiesResponse?.success ? (cookiesResponse.data as chrome.cookies.Cookie[] ?? []) : []);
      setPageResources(pageResourcesResponse?.success ? (pageResourcesResponse.data as PageResourceObservation | null ?? null) : null);
      setWebSockets(webSocketsResponse?.success ? (webSocketsResponse.data as ObservedWebSocket[] ?? []) : []);
      setRequestBodies(requestBodiesResponse?.success ? (requestBodiesResponse.data as CapturedRequestBody[] ?? []) : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Assessment failed to load.');
    } finally {
      setLoading(false);
    }
  }, []);

  // eslint-disable-next-line react-hooks/set-state-in-effect -- initial data load via chrome runtime messaging (external system); the sync setLoading(true) is a no-op on mount
  useEffect(() => { void load(); }, [load]);

  // Auto-refresh when the active tab navigates (full load or SPA route change) or
  // when the user switches tabs. Uses chrome.tabs events only — no extra permission
  // (changeInfo.url is available via the existing <all_urls> host access).
  useEffect(() => {
    const currentTabId = tabInfo?.tabId;
    let timer: number | undefined;
    const scheduleReload = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => { void load(); }, 500);
    };
    const onUpdated = (updatedTabId: number, changeInfo: chrome.tabs.OnUpdatedInfo) => {
      if (updatedTabId === currentTabId && (changeInfo.status === 'complete' || changeInfo.url !== undefined)) {
        scheduleReload();
      }
    };
    const onActivated = () => { scheduleReload(); };
    chrome.tabs.onUpdated.addListener(onUpdated);
    chrome.tabs.onActivated.addListener(onActivated);
    return () => {
      window.clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      chrome.tabs.onActivated.removeListener(onActivated);
    };
  }, [tabInfo?.tabId, load]);

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
    () => buildAssessmentFindings({
      activeUrl,
      cookies,
      storageEntries,
      requests,
      pageResources,
      domObservation: transportObservation,
      webSockets,
      requestBodies,
    }),
    [activeUrl, cookies, storageEntries, requests, pageResources, transportObservation, webSockets, requestBodies],
  );

  const activeFilter = useMemo<ReportFilter>(
    () => ({ minSeverity, onlyActionable, search }),
    [minSeverity, onlyActionable, search],
  );
  const filteredFindings = useMemo(() => filterFindings(findings, activeFilter), [findings, activeFilter]);

  const cookieFindings = useMemo(() => filteredFindings.filter(f => f.category === 'cookies'), [filteredFindings]);
  const tokenFindings = useMemo(() => filteredFindings.filter(f => f.category === 'tokens'), [filteredFindings]);
  const storageFindings = useMemo(() => filteredFindings.filter(f => f.category === 'storage'), [filteredFindings]);
  const headerFindings = useMemo(() => filteredFindings.filter(f => f.category === 'headers'), [filteredFindings]);
  const transportFindings = useMemo(() => filteredFindings.filter(f => f.category === 'transport'), [filteredFindings]);
  const llmFindings = useMemo(() => filteredFindings.filter(f => f.category === 'llm'), [filteredFindings]);

  // The exported report honours the same filters shown in the UI, so "what you
  // see is what you export"; severityCounts are recomputed on the filtered set.
  const buildReport = useCallback(() => {
    const base = buildFullAssessmentReport({
      generatedAt: new Date().toISOString(),
      activeUrl,
      headers: headerReport,
      transport: transportReport,
      findings,
    });
    return filterReport(base, activeFilter);
  }, [activeUrl, headerReport, transportReport, findings, activeFilter]);

  const flashToast = useCallback((message: string) => {
    setCopyToast(message);
    window.setTimeout(() => setCopyToast(null), 2200);
  }, []);

  const downloadReport = useCallback(() => {
    const report = buildReport();
    const iso = new Date().toISOString();
    let host = 'unknown-host';
    try { host = new URL(activeUrl).hostname || host; } catch { /* keep fallback */ }
    downloadTextFile(buildReportFilename(host, iso, 'html'), 'text/html;charset=utf-8', renderReportHtml(report));
    flashToast('Downloaded HTML report.');
  }, [buildReport, activeUrl, flashToast]);

  const metaLine = (() => {
    switch (activeSubtab) {
      case 'transport':
        return `HTTPS requests: ${transportReport.observedHttpsRequestCount} · HTTP requests: ${transportReport.observedHttpRequestCount} · Transport findings: ${transportFindings.length} · WebSockets: ${webSockets.length}`;
      case 'cookies':
        return `Cookies in jar: ${cookies.length} · Cookie findings: ${cookieFindings.length}`;
      case 'tokens':
        return `Token findings: ${tokenFindings.length}`;
      case 'storage': {
        const local = storageEntries.filter(e => e.area === 'localStorage').length;
        const session = storageEntries.filter(e => e.area === 'sessionStorage').length;
        const idb = storageEntries.filter(e => e.area === 'indexedDB').length;
        return `Local: ${local} · Session: ${session} · IDB: ${idb} · Storage findings: ${storageFindings.length}`;
      }
      case 'llm':
        return `LLM/AI findings: ${llmFindings.length}`;
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
          onClick={downloadReport}
          className="px-1.5 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-amber-400 hover:border-amber-800/50 rounded transition-colors shrink-0"
          title="Download the assessment report as a self-contained HTML file (honours the active filters)"
        >
          Download HTML
        </button>
      </div>

      <div className="px-2.5 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0 space-y-2">
        <div className="grid grid-cols-6 gap-1">
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

        <div className="flex items-center gap-1.5">
          <select
            value={minSeverity}
            onChange={e => setMinSeverity(e.target.value as MinSeverity)}
            title="Minimum severity to show and export"
            className="px-1 py-0.5 text-[10px] border border-gray-700 bg-gray-800 text-gray-400 rounded shrink-0 focus:outline-none focus:border-blue-800/50"
          >
            {SEVERITY_FILTER_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <button
            type="button"
            onClick={() => setOnlyActionable(v => !v)}
            title="Show only actionable findings (exclude info)"
            className={[
              'px-1.5 py-0.5 text-[10px] border rounded shrink-0 transition-colors',
              onlyActionable
                ? 'border-blue-800/60 bg-blue-950/30 text-blue-200'
                : 'border-gray-700 bg-gray-800 text-gray-400 hover:text-white hover:border-gray-600',
            ].join(' ')}
          >
            Actionable
          </button>
          <div className="relative flex-1 min-w-0">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search findings…"
              className="w-full pl-2 pr-5 py-0.5 text-[10px] bg-gray-800 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                title="Clear search"
                className="absolute top-1/2 right-1 -translate-y-1/2 leading-none text-gray-600 hover:text-gray-300"
              >
                ×
              </button>
            )}
          </div>
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
          <>
            <TransportTlsPanel report={transportReport} />
            {transportFindings.length > 0 && (
              <Section title="Resource, mixed-content & third-party findings" meta={<span className="text-gray-500">{transportFindings.length}</span>}>
                <FindingList findings={transportFindings} emptyTitle="No additional transport findings" />
              </Section>
            )}
          </>
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
        ) : activeSubtab === 'storage' ? (
          <FindingList
            findings={storageFindings}
            emptyTitle="No storage findings"
            emptyHint="No sensitive tokens were observed in localStorage, sessionStorage, or IndexedDB for this context."
          />
        ) : (
          <FindingList
            findings={llmFindings}
            emptyTitle="No LLM/RAG signals observed"
            emptyHint="No LLM provider endpoints, AI chatbot widgets, exposed provider keys, or prompt payloads were observed for this page."
          />
        )}
      </div>
    </div>
  );
};
