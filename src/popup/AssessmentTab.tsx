import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  ActiveTabInfo,
  AssessmentCategory,
  AssessmentFinding,
  CachedRequest,
  CookieAssessmentCategory,
  SetCookieAssessmentSummary,
  StorageScanResult,
  TokenAssessmentOrigin,
} from '../types';
import { buildAssessmentFindings, getCookieAssessmentSummary, getFindingCounts, getSetCookieAssessmentSummary, getTokenAssessmentSummary } from '../utils/assessment';

const CATEGORY_LABELS: Record<AssessmentCategory, string> = {
  cookies: 'Cookies',
  tokens: 'Tokens',
  headers: 'Headers',
  storage: 'Storage',
};

const COOKIE_CATEGORY_LABELS: Record<CookieAssessmentCategory, string> = {
  'session/auth': 'Session/Auth',
  csrf: 'CSRF',
  preference: 'Preference',
  'analytics/other': 'Analytics/Other',
};

const TOKEN_ORIGIN_LABELS: Record<TokenAssessmentOrigin, string> = {
  cookie: 'Cookie',
  localStorage: 'localStorage',
  sessionStorage: 'sessionStorage',
  manual: 'Manual',
};

function severityClasses(severity: AssessmentFinding['severity']): string {
  switch (severity) {
    case 'high':
      return 'text-red-300 bg-red-950/40 border-red-900/60';
    case 'medium':
      return 'text-amber-300 bg-amber-950/40 border-amber-900/60';
    case 'low':
      return 'text-sky-300 bg-sky-950/40 border-sky-900/60';
    case 'info':
      return 'text-gray-300 bg-gray-900/60 border-gray-700';
  }
}

function categoryClasses(category: AssessmentCategory): string {
  switch (category) {
    case 'cookies':
      return 'text-amber-400 bg-amber-900/30 border-amber-800/50';
    case 'tokens':
      return 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50';
    case 'headers':
      return 'text-blue-400 bg-blue-900/30 border-blue-800/50';
    case 'storage':
      return 'text-purple-400 bg-purple-900/30 border-purple-800/50';
  }
}

export const AssessmentTab: React.FC = () => {
  const [tabInfo, setTabInfo] = useState<ActiveTabInfo | null>(null);
  const [cookies, setCookies] = useState<chrome.cookies.Cookie[]>([]);
  const [scanResult, setScanResult] = useState<StorageScanResult | null>(null);
  const [requests, setRequests] = useState<CachedRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<AssessmentFinding['severity'] | 'all'>('all');
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

      const cookieList = await chrome.cookies.getAll({ url: info.url });
      setCookies(cookieList);

      try {
        await chrome.runtime.sendMessage({ type: 'RUN_STORAGE_SCAN' });
      } catch {
        // Best effort only — the cached result can still be useful.
      }

      const [storageResponse, headersResponse] = await Promise.all([
        chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' }),
        chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: info.tabId }),
      ]);

      setScanResult(storageResponse?.success ? (storageResponse.data as StorageScanResult | null) : null);
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

  const findings = useMemo(() => {
    if (!tabInfo) return [];
    return buildAssessmentFindings({
      activeUrl: tabInfo.url,
      cookies,
      storageEntries: scanResult?.entries ?? [],
      requests,
    });
  }, [cookies, requests, scanResult?.entries, tabInfo]);

  const counts = useMemo(() => getFindingCounts(findings), [findings]);
  const cookieSummary = useMemo(() => getCookieAssessmentSummary(cookies, tabInfo?.url ?? '/'), [cookies, tabInfo?.url]);
  const setCookieSummary: SetCookieAssessmentSummary = useMemo(
    () => getSetCookieAssessmentSummary(tabInfo?.url ?? '/', requests, cookies),
    [cookies, requests, tabInfo?.url],
  );
  const tokenSummary = useMemo(
    () => getTokenAssessmentSummary(cookies, scanResult?.entries ?? []),
    [cookies, scanResult?.entries],
  );
  const sessionAuthCookieCount = cookieSummary.counts['session/auth'];
  const csrfCookieCount = cookieSummary.counts.csrf;
  const visibleFindings = useMemo(() => {
    if (filter === 'all') return findings;
    return findings.filter(finding => finding.severity === filter);
  }, [filter, findings]);

  const visibleCounts = useMemo(() => getFindingCounts(visibleFindings), [visibleFindings]);

  const markdownReport = useMemo(() => {
    const lines = [
      '# OWASP-Oriented Browser Assessment',
      '',
      `Generated: ${new Date().toISOString()}`,
      `URL: ${tabInfo?.url ?? 'unknown'}`,
      `Cookies observed: ${cookies.length}`,
      `Session/Auth cookies: ${sessionAuthCookieCount}`,
      `CSRF cookies: ${csrfCookieCount}`,
      `Set-Cookie observed on responses: ${setCookieSummary.observedCount}`,
      `Relevant Set-Cookie responses: ${setCookieSummary.relevantRequestCount}`,
      `Token candidates observed: ${tokenSummary.observedCount}`,
      `JWT candidates: ${tokenSummary.jwtCount}`,
      `Opaque token candidates: ${tokenSummary.opaqueCount}`,
      `Storage entries observed: ${scanResult?.entries.length ?? 0}`,
      `Captured requests: ${requests.length}`,
      `Applied filter: ${filter}`,
      '',
      '## Severity Summary',
      '',
      `- High: ${visibleCounts.high}`,
      `- Medium: ${visibleCounts.medium}`,
      `- Low: ${visibleCounts.low}`,
      `- Info: ${visibleCounts.info}`,
      '',
      '## Findings',
      '',
    ];

    if (visibleFindings.length === 0) {
      lines.push('- No findings in the current browser-visible context.');
    } else {
      visibleFindings.forEach((finding, index) => {
        lines.push(`${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`);
        lines.push(`Category: ${CATEGORY_LABELS[finding.category]}`);
        lines.push(`Summary: ${finding.summary}`);
        if (finding.whyItMatters) {
          lines.push(`Why it matters: ${finding.whyItMatters}`);
        }
        lines.push(`Evidence: ${finding.evidence}`);
        lines.push(`Remediation: ${finding.remediation}`);
        lines.push('');
      });
    }

    return lines.join('\n');
  }, [cookies.length, csrfCookieCount, filter, requests.length, scanResult?.entries.length, sessionAuthCookieCount, setCookieSummary.observedCount, setCookieSummary.relevantRequestCount, tabInfo?.url, tokenSummary.jwtCount, tokenSummary.observedCount, tokenSummary.opaqueCount, visibleCounts.high, visibleCounts.info, visibleCounts.low, visibleCounts.medium, visibleFindings]);

  const copyReport = useCallback(async (format: 'markdown' | 'json') => {
    const payload = format === 'markdown'
      ? markdownReport
      : JSON.stringify({
          generatedAt: new Date().toISOString(),
          filter,
          tab: tabInfo,
          counts: visibleCounts,
          findings: visibleFindings,
        }, null, 2);

    try {
      await navigator.clipboard.writeText(payload);
      setCopyToast(format === 'markdown' ? 'Markdown report copied.' : 'JSON report copied.');
      window.setTimeout(() => setCopyToast(null), 2200);
    } catch {
      setCopyToast('Clipboard copy failed.');
      window.setTimeout(() => setCopyToast(null), 2200);
    }
  }, [filter, markdownReport, tabInfo, visibleCounts, visibleFindings]);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 bg-gray-900/30 shrink-0">
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
            OWASP-focused assessment
          </p>
          <p className="text-[11px] text-gray-400 font-mono truncate" title={tabInfo?.url ?? ''}>
            {tabInfo?.url ?? 'Loading active tab...'}
          </p>
        </div>
        <button
          onClick={() => { void load(); }}
          className="px-2 py-1 text-[11px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-blue-400 hover:border-blue-800/50 rounded transition-colors shrink-0"
        >
          Refresh
        </button>
        <button
          onClick={() => { void copyReport('markdown'); }}
          className="px-2 py-1 text-[11px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-emerald-400 hover:border-emerald-800/50 rounded transition-colors shrink-0"
          title="Copy the currently visible assessment report in Markdown"
        >
          Copy MD
        </button>
        <button
          onClick={() => { void copyReport('json'); }}
          className="px-2 py-1 text-[11px] border border-gray-700 bg-gray-800 text-gray-400 hover:text-purple-400 hover:border-purple-800/50 rounded transition-colors shrink-0"
          title="Copy the currently visible assessment report in JSON"
        >
          Copy JSON
        </button>
      </div>

      <div className="grid grid-cols-4 gap-2 px-3 py-3 border-b border-gray-800 bg-gray-900/20 shrink-0">
        {(['high', 'medium', 'low', 'info'] as const).map(severity => (
          <button
            key={severity}
            onClick={() => setFilter(current => current === severity ? 'all' : severity)}
            className={`rounded border px-2 py-2 text-left transition-colors ${severityClasses(severity)} ${filter === severity ? 'ring-1 ring-current' : ''}`}
          >
            <p className="text-[10px] uppercase tracking-widest font-bold">{severity}</p>
            <p className="text-xl leading-none mt-1 font-semibold">{counts[severity]}</p>
          </button>
        ))}
      </div>

      <div className="px-3 py-2 border-b border-gray-800 bg-gray-900/10 shrink-0">
        <div className="flex flex-wrap items-center gap-2 text-[10px] text-gray-500">
          <span>Cookies: <span className="text-gray-300">{cookies.length}</span></span>
          <span>Storage entries: <span className="text-gray-300">{scanResult?.entries.length ?? 0}</span></span>
          <span>Captured requests: <span className="text-gray-300">{requests.length}</span></span>
          {filter !== 'all' && <span>Filter: <span className="text-gray-300 uppercase">{filter}</span></span>}
          {copyToast && <span className="text-emerald-400">{copyToast}</span>}
        </div>
      </div>

      <div className="px-3 py-3 border-b border-gray-800 bg-gray-900/10 shrink-0 space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
              Cookie summary
            </p>
            <p className="text-[11px] text-gray-400">
              Automatic classification of the currently observed cookie jar.
            </p>
          </div>
          <span className="text-[10px] text-gray-600">
            Critical cookies: <span className="text-gray-300">{cookieSummary.criticalCookies.length}</span>
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(Object.keys(COOKIE_CATEGORY_LABELS) as CookieAssessmentCategory[]).map(category => (
            <span key={category} className="px-2 py-1 text-[10px] border rounded bg-gray-900/60 border-gray-700 text-gray-300">
              {COOKIE_CATEGORY_LABELS[category]}: <span className="text-white">{cookieSummary.counts[category]}</span>
            </span>
          ))}
        </div>
        <div>
          <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">
            Critical cookie names
          </p>
          <div className="flex flex-wrap gap-1.5">
            {cookieSummary.criticalCookies.length > 0 ? cookieSummary.criticalCookies.map(name => (
              <span key={name} className="px-1.5 py-px text-[10px] font-mono border rounded bg-red-950/30 border-red-900/40 text-red-300">
                {name}
              </span>
            )) : (
              <span className="text-[11px] text-gray-500">No high or medium cookie findings detected.</span>
            )}
          </div>
        </div>
      </div>

      <div className="px-3 py-3 border-b border-gray-800 bg-gray-900/10 shrink-0 space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
              Response Set-Cookie summary
            </p>
            <p className="text-[11px] text-gray-400">
              Cookies observed directly in relevant document, auth callback, and session-related API responses.
            </p>
          </div>
          <span className="text-[10px] text-gray-600">
            Sensitive observed: <span className="text-gray-300">{setCookieSummary.sensitiveObservedCount}</span>
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5 text-[10px] text-gray-400">
          <span className="px-2 py-1 border rounded bg-gray-900/60 border-gray-700 text-gray-300">
            Relevant responses: <span className="text-white">{setCookieSummary.relevantRequestCount}</span>
          </span>
          <span className="px-2 py-1 border rounded bg-gray-900/60 border-gray-700 text-gray-300">
            Set-Cookie observed: <span className="text-white">{setCookieSummary.observedCount}</span>
          </span>
          <span className="px-2 py-1 border rounded bg-gray-900/60 border-gray-700 text-gray-300">
            Browser jar cookies: <span className="text-white">{cookies.length}</span>
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">
              Observed in responses
            </p>
            <div className="flex flex-wrap gap-1.5">
              {setCookieSummary.observedNames.length > 0 ? setCookieSummary.observedNames.map(name => (
                <span key={name} className="px-1.5 py-px text-[10px] font-mono border rounded bg-blue-950/30 border-blue-900/40 text-blue-300">
                  {name}
                </span>
              )) : (
                <span className="text-[11px] text-gray-500">No relevant Set-Cookie response observed yet.</span>
              )}
            </div>
          </div>
          <div>
            <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">
              Sensitive names in browser jar
            </p>
            <div className="flex flex-wrap gap-1.5">
              {setCookieSummary.persistedSensitiveNames.length > 0 ? setCookieSummary.persistedSensitiveNames.map(name => (
                <span key={name} className="px-1.5 py-px text-[10px] font-mono border rounded bg-amber-950/30 border-amber-900/40 text-amber-300">
                  {name}
                </span>
              )) : (
                <span className="text-[11px] text-gray-500">No sensitive cookie currently persisted in the browser jar.</span>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="px-3 py-3 border-b border-gray-800 bg-gray-900/10 shrink-0 space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
              Token summary
            </p>
            <p className="text-[11px] text-gray-400">
              Browser-observed token and JWT candidates by origin. Manual token input is evaluated separately in the Tokens tab.
            </p>
          </div>
          <span className="text-[10px] text-gray-600">
            JWTs: <span className="text-gray-300">{tokenSummary.jwtCount}</span> · Opaque: <span className="text-gray-300">{tokenSummary.opaqueCount}</span>
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(Object.keys(TOKEN_ORIGIN_LABELS) as TokenAssessmentOrigin[]).map(origin => (
            <span key={origin} className="px-2 py-1 text-[10px] border rounded bg-gray-900/60 border-gray-700 text-gray-300">
              {TOKEN_ORIGIN_LABELS[origin]}: <span className="text-white">{tokenSummary.counts[origin]}</span>
            </span>
          ))}
        </div>
        <div>
          <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">
            Observed token sources
          </p>
          <div className="flex flex-wrap gap-1.5">
            {tokenSummary.labels.length > 0 ? tokenSummary.labels.map(label => (
              <span key={label} className="px-1.5 py-px text-[10px] font-mono border rounded bg-emerald-950/30 border-emerald-900/40 text-emerald-300">
                {label}
              </span>
            )) : (
              <span className="text-[11px] text-gray-500">No browser-observed token candidates yet.</span>
            )}
          </div>
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
        ) : visibleFindings.length === 0 ? (
          <div className="p-4 space-y-2 text-[11px]">
            <p className="text-emerald-400 font-semibold">No findings in the current filter.</p>
            <p className="text-gray-500">
              This does not prove compliance. It means the extension did not observe cookie, token, or header issues from the current browser-visible context.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800/60">
            {visibleFindings.map(finding => (
              <div key={finding.id} className="px-4 py-3 space-y-2">
                <div className="flex items-start gap-2 flex-wrap">
                  <span className={`px-1.5 py-px text-[9px] font-bold border rounded ${severityClasses(finding.severity)}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <span className={`px-1.5 py-px text-[9px] font-bold border rounded ${categoryClasses(finding.category)}`}>
                    {CATEGORY_LABELS[finding.category]}
                  </span>
                  <h3 className="text-[12px] text-gray-100 font-semibold">{finding.title}</h3>
                </div>
                <p className="text-[11px] text-gray-400 leading-relaxed">{finding.summary}</p>
                {finding.category === 'headers' && finding.whyItMatters && (
                  <div>
                    <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Why it matters</p>
                    <p className="text-[11px] text-gray-300 leading-relaxed">{finding.whyItMatters}</p>
                  </div>
                )}
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Evidence</p>
                  <p className="text-[11px] text-gray-300 font-mono break-words">{finding.evidence}</p>
                </div>
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">Remediation</p>
                  <p className="text-[11px] text-gray-400 leading-relaxed">{finding.remediation}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};