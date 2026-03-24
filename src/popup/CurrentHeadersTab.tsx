import React, { useCallback, useEffect, useState } from 'react';
import type { CachedRequest } from '../types';

type SecurityStatus = 'ok' | 'warning' | 'missing';

interface SecurityHeaderRule {
  name: string;
  badge: string;
  fullName: string;
  cls: string;
  warningCls: string;
  missingCls: string;
  appliesTo?: (req: CachedRequest) => boolean;
  evaluate?: (value: string, req: CachedRequest) => string | null;
}

interface EvaluatedSecurityHeader {
  rule: SecurityHeaderRule;
  status: SecurityStatus;
  value?: string;
  warning?: string;
}

const SECURITY_HEADERS: Record<string, { badge: string; fullName: string; cls: string }> = {
  'content-security-policy':      { badge: 'CSP', fullName: 'Content-Security-Policy', cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50' },
  'strict-transport-security':    { badge: 'HSTS', fullName: 'Strict-Transport-Security', cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50' },
  'x-frame-options':              { badge: 'XFO', fullName: 'X-Frame-Options', cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' },
  'x-content-type-options':       { badge: 'XCTO', fullName: 'X-Content-Type-Options', cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' },
  'referrer-policy':              { badge: 'RP', fullName: 'Referrer-Policy', cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' },
  'permissions-policy':           { badge: 'PP', fullName: 'Permissions-Policy', cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' },
  'set-cookie':                   { badge: 'Cookie', fullName: 'Set-Cookie', cls: 'text-amber-400 bg-amber-900/30 border-amber-800/50' },
  'access-control-allow-origin':  { badge: 'CORS', fullName: 'Access-Control-Allow-Origin', cls: 'text-orange-400 bg-orange-900/30 border-orange-800/50' },
  'cross-origin-opener-policy':   { badge: 'COOP', fullName: 'Cross-Origin-Opener-Policy', cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50' },
  'cross-origin-embedder-policy': { badge: 'COEP', fullName: 'Cross-Origin-Embedder-Policy', cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50' },
  'cross-origin-resource-policy': { badge: 'CORP', fullName: 'Cross-Origin-Resource-Policy', cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50' },
};

const TRACKED_DOCUMENT_HEADERS: SecurityHeaderRule[] = [
  {
    name: 'content-security-policy',
    badge: 'CSP',
    fullName: 'Content-Security-Policy',
    cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: (value) => {
      const normalized = value.toLowerCase();
      const warnings: string[] = [];
      if (normalized.includes("'unsafe-inline'")) warnings.push("contains 'unsafe-inline'");
      if (normalized.includes("'unsafe-eval'")) warnings.push("contains 'unsafe-eval'");
      return warnings.length > 0
        ? `OWASP recommends a stricter CSP; ${warnings.join(' and ')}.`
        : null;
    },
  },
  {
    name: 'strict-transport-security',
    badge: 'HSTS',
    fullName: 'Strict-Transport-Security',
    cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    appliesTo: req => req.url.startsWith('https://'),
    evaluate: (value) => {
      const directives = value.split(';').map(part => part.trim().toLowerCase()).filter(Boolean);
      const maxAgeDirective = directives.find(part => part.startsWith('max-age='));
      const maxAge = maxAgeDirective ? Number.parseInt(maxAgeDirective.slice(8), 10) : NaN;
      const warnings: string[] = [];
      if (!Number.isFinite(maxAge) || maxAge < 63072000) warnings.push('max-age is below the OWASP example value of 63072000');
      if (!directives.includes('includesubdomains')) warnings.push('includeSubDomains is missing');
      if (!directives.includes('preload')) warnings.push('preload is missing');
      return warnings.length > 0 ? warnings.join('; ') : null;
    },
  },
  {
    name: 'x-frame-options',
    badge: 'XFO',
    fullName: 'X-Frame-Options',
    cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: (value) => {
      const normalized = value.trim().toUpperCase();
      if (normalized === 'DENY') return null;
      if (normalized === 'SAMEORIGIN') {
        return 'OWASP recommends DENY when possible and prefers CSP frame-ancestors for modern browsers.';
      }
      return 'Value differs from the OWASP recommendation of DENY.';
    },
  },
  {
    name: 'x-content-type-options',
    badge: 'XCTO',
    fullName: 'X-Content-Type-Options',
    cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => value.trim().toLowerCase() === 'nosniff'
      ? null
      : 'OWASP recommends nosniff.',
  },
  {
    name: 'referrer-policy',
    badge: 'RP',
    fullName: 'Referrer-Policy',
    cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => value.trim().toLowerCase() === 'strict-origin-when-cross-origin'
      ? null
      : 'OWASP recommends strict-origin-when-cross-origin.',
  },
  {
    name: 'permissions-policy',
    badge: 'PP',
    fullName: 'Permissions-Policy',
    cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => {
      const normalized = value.trim().toLowerCase();
      if (!normalized) return 'OWASP recommends explicitly disabling unneeded features or limiting them to trusted origins.';
      if (normalized.includes('*')) return 'OWASP recommends restricting features to trusted origins instead of using wildcards.';
      return null;
    },
  },
  {
    name: 'cross-origin-opener-policy',
    badge: 'COOP',
    fullName: 'Cross-Origin-Opener-Policy',
    cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => value.trim().toLowerCase() === 'same-origin'
      ? null
      : 'OWASP recommends same-origin.',
  },
  {
    name: 'cross-origin-embedder-policy',
    badge: 'COEP',
    fullName: 'Cross-Origin-Embedder-Policy',
    cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => value.trim().toLowerCase() === 'require-corp'
      ? null
      : 'OWASP recommends require-corp.',
  },
  {
    name: 'cross-origin-resource-policy',
    badge: 'CORP',
    fullName: 'Cross-Origin-Resource-Policy',
    cls: 'text-sky-400 bg-sky-900/30 border-sky-800/50',
    warningCls: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
    missingCls: 'text-red-300 bg-red-950/40 border-red-900/60',
    evaluate: value => value.trim().toLowerCase() === 'same-site'
      ? null
      : 'OWASP recommends same-site.',
  },
];

function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function getTrackedHeadersForRequest(req: CachedRequest, treatAsDocument = false): SecurityHeaderRule[] {
  if (!treatAsDocument && req.resourceType !== 'main_frame') return [];
  return TRACKED_DOCUMENT_HEADERS.filter(rule => rule.appliesTo ? rule.appliesTo(req) : true);
}

function getRequestSecuritySummary(req: CachedRequest, treatAsDocument = false): {
  tracked: SecurityHeaderRule[];
  ok: EvaluatedSecurityHeader[];
  warning: EvaluatedSecurityHeader[];
  missing: EvaluatedSecurityHeader[];
} {
  const tracked = getTrackedHeadersForRequest(req, treatAsDocument);
  const headerValues = new Map<string, string[]>(
    req.responseHeaders.reduce<Array<[string, string[]]>>((acc, header) => {
      const name = header.name.toLowerCase();
      const existing = acc.find(([candidate]) => candidate === name);
      if (existing) {
        existing[1].push(header.value);
      } else {
        acc.push([name, [header.value]]);
      }
      return acc;
    }, []),
  );

  const ok: EvaluatedSecurityHeader[] = [];
  const warning: EvaluatedSecurityHeader[] = [];
  const missing: EvaluatedSecurityHeader[] = [];

  for (const rule of tracked) {
    const values = headerValues.get(rule.name);
    if (!values || values.length === 0) {
      missing.push({ rule, status: 'missing' });
      continue;
    }

    const value = values.join(', ');
    const warningMessage = rule.evaluate?.(value, req) ?? null;
    if (warningMessage) {
      warning.push({ rule, status: 'warning', value, warning: warningMessage });
    } else {
      ok.push({ rule, status: 'ok', value });
    }
  }

  return { tracked, ok, warning, missing };
}

function securityBadgeTitle(result: EvaluatedSecurityHeader): string {
  if (result.status === 'missing') return `${result.rule.fullName} — Missing`;
  if (result.status === 'warning') return `${result.rule.fullName} — Warning: ${result.warning}`;
  return result.rule.fullName;
}

function securityBadgeClass(result: EvaluatedSecurityHeader): string {
  if (result.status === 'warning') return result.rule.warningCls;
  if (result.status === 'missing') return result.rule.missingCls;
  return result.rule.cls;
}

function headerRowBadge(name: string, value: string, req: CachedRequest): EvaluatedSecurityHeader | null {
  const rule = TRACKED_DOCUMENT_HEADERS.find(candidate => candidate.name === name);
  if (!rule) return null;
  const warning = rule.evaluate?.(value, req);
  return warning
    ? { rule, status: 'warning', value, warning }
    : { rule, status: 'ok', value };
}

function methodBadge(method: string): { label: string; cls: string } {
  switch (method.toUpperCase()) {
    case 'GET':
      return { label: 'GET', cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50' };
    case 'POST':
      return { label: 'POST', cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' };
    case 'PUT':
    case 'PATCH':
      return { label: method.toUpperCase(), cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' };
    case 'DELETE':
      return { label: 'DEL', cls: 'text-red-400 bg-red-900/30 border-red-800/50' };
    default:
      return { label: method.toUpperCase().slice(0, 5), cls: 'text-gray-500 bg-gray-800/60 border-gray-700' };
  }
}

function statusColor(code: number): string {
  if (code === 0) return 'text-gray-600';
  if (code < 300) return 'text-emerald-400';
  if (code < 400) return 'text-amber-400';
  if (code < 500) return 'text-orange-400';
  return 'text-red-400';
}

function resourceBadge(type: string): { label: string; cls: string } {
  switch (type) {
    case 'main_frame':
      return { label: 'DOC', cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' };
    case 'sub_frame':
      return { label: 'IFR', cls: 'text-cyan-400 bg-cyan-900/30 border-cyan-800/50' };
    case 'xmlhttprequest':
      return { label: 'XHR', cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' };
    default:
      return { label: type.toUpperCase().slice(0, 4), cls: 'text-gray-500 bg-gray-800/60 border-gray-700' };
  }
}

function requestKey(req: CachedRequest): string {
  return `${req.timestamp}:${req.resourceType}:${req.method}:${req.url}`;
}

export const CurrentHeadersTab: React.FC = () => {
  const [tabId, setTabId] = useState<number | null>(null);
  const [tabUrl, setTabUrl] = useState('');
  const [requests, setRequests] = useState<CachedRequest[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchHeaders = useCallback(async (id: number) => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: id });
      if (res?.success) setRequests((res.data as CachedRequest[]) ?? []);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id === undefined) return;
        setTabId(tab.id);
        setTabUrl(tab.url ?? '');
        await fetchHeaders(tab.id);
      } finally {
        setLoading(false);
      }
    })();
  }, [fetchHeaders]);

  useEffect(() => {
    if (tabId === null) return;
    const interval = setInterval(() => {
      void fetchHeaders(tabId);
    }, 3000);
    return () => clearInterval(interval);
  }, [tabId, fetchHeaders]);

  const handleClear = () => {
    if (tabId === null) return;
    void chrome.storage.session.remove(`tabHeaders:${tabId}`).then(() => {
      setRequests([]);
      setExpanded(null);
    });
  };

  const visible = filter.trim()
    ? requests.filter(r => r.url.toLowerCase().includes(filter.toLowerCase()))
    : requests;
  const activeHostname = hostnameFromUrl(tabUrl);
  const primaryRequest = visible.find(r => r.resourceType === 'main_frame')
    ?? visible.find(r => r.resourceType === 'sub_frame' && hostnameFromUrl(r.url) === activeHostname)
    ?? visible.find(r => hostnameFromUrl(r.url) === activeHostname)
    ?? visible[0]
    ?? null;
  const primaryRequestIsInferred = primaryRequest?.resourceType !== 'main_frame';
  const recentRequests = primaryRequest
    ? visible.filter(req => req !== primaryRequest)
    : visible;
  const primarySummary = primaryRequest
    ? getRequestSecuritySummary(primaryRequest, primaryRequestIsInferred)
    : null;

  const renderRequestRow = (req: CachedRequest, sectionKey: string) => {
    const badge = resourceBadge(req.resourceType);
    const method = methodBadge(req.method);
    const key = `${sectionKey}:${requestKey(req)}`;
    const isOpen = expanded === key;
    const securitySummary = getRequestSecuritySummary(req);

    return (
      <div key={key} className="border-b border-gray-800/50 last:border-b-0">
        <button
          onClick={() => setExpanded(prev => prev === key ? null : key)}
          className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-900/60 transition-colors text-left group"
          title={req.url}
        >
          <span className={`px-1.5 py-px text-[9px] font-bold border rounded shrink-0 ${badge.cls}`}>
            {badge.label}
          </span>
          <span className={`w-10 text-[11px] font-mono font-bold shrink-0 ${statusColor(req.statusCode)}`}>
            {req.statusCode || '-'}
          </span>
          <span className={`px-1.5 py-px text-[9px] font-bold border rounded shrink-0 ${method.cls}`}>
            {method.label}
          </span>
          <span className="flex-1 min-w-0 text-[11px] text-gray-400 font-mono truncate">
            {req.url}
          </span>
          <span className="text-[10px] text-gray-700 shrink-0">
            {new Date(req.timestamp).toLocaleTimeString()}
          </span>
          <svg
            className={`w-3 h-3 text-gray-700 shrink-0 transition-transform duration-150 ${isOpen ? 'rotate-180' : ''}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="m19 9-7 7-7-7" />
          </svg>
        </button>

        {isOpen && (
          <div className="bg-gray-900/40 border-t border-gray-800/40 px-4 pt-2 pb-3">
            {securitySummary.tracked.length > 0 && (
              <div className="mb-3 space-y-2">
                <div>
                  <p className="text-[10px] text-gray-700 uppercase tracking-widest mb-1 font-medium select-none">
                    OWASP-aligned headers
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {securitySummary.ok.map(result => (
                      <span key={`row-ok-${key}-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                        {result.rule.badge}
                      </span>
                    ))}
                    {securitySummary.ok.length === 0 && (
                      <span className="text-[10px] text-gray-700">No tracked headers fully align with OWASP guidance.</span>
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] text-gray-700 uppercase tracking-widest mb-1 font-medium select-none">
                    OWASP warnings
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {securitySummary.warning.map(result => (
                      <span key={`row-warning-${key}-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                        {result.rule.badge}
                      </span>
                    ))}
                    {securitySummary.warning.length === 0 && (
                      <span className="text-[10px] text-gray-700">No OWASP configuration warnings.</span>
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] text-gray-700 uppercase tracking-widest mb-1 font-medium select-none">
                    Missing tracked headers
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {securitySummary.missing.map(result => (
                      <span key={`row-missing-${key}-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                        {result.rule.badge}
                      </span>
                    ))}
                    {securitySummary.missing.length === 0 && (
                      <span className="text-[10px] text-emerald-400">No tracked security headers are missing.</span>
                    )}
                  </div>
                </div>
              </div>
            )}
            <p className="text-[10px] text-gray-700 uppercase tracking-widest mb-2 font-medium select-none">
              Response Headers ({req.responseHeaders.length})
            </p>
            {req.responseHeaders.length === 0 ? (
              <p className="text-[10px] text-gray-800">No headers were captured for this request.</p>
            ) : (
              <div className="space-y-1">
                {req.responseHeaders.map((h, i) => {
                  const sec = SECURITY_HEADERS[h.name.toLowerCase()];
                  const evaluation = headerRowBadge(h.name.toLowerCase(), h.value, req);
                  return (
                    <div key={i} className="grid grid-cols-[180px_1fr] gap-x-3 text-[10px]">
                      <div className="flex items-center gap-1.5 min-w-0">
                        {sec && (
                          <span
                            title={evaluation ? securityBadgeTitle(evaluation) : sec.fullName}
                            className={`px-1 py-px text-[8px] font-bold border rounded shrink-0 ${evaluation ? securityBadgeClass(evaluation) : sec.cls}`}
                          >
                            {sec.badge}
                          </span>
                        )}
                        <span className={`font-mono truncate ${sec ? 'text-gray-200 font-semibold' : 'text-gray-500'}`}>
                          {h.name}
                        </span>
                      </div>
                      <span className="text-gray-600 font-mono break-all">
                        {h.value}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 bg-gray-900/30 shrink-0">
        <p className="flex-1 min-w-0 text-[10px] text-gray-600 font-mono truncate" title={tabUrl}>
          {tabUrl || 'No active tab'}
        </p>
        <button
          onClick={handleClear}
          disabled={requests.length === 0}
          className="px-2 py-1 text-[11px] border border-gray-700 bg-gray-800 text-gray-500 hover:text-red-400 hover:border-red-800/50 disabled:opacity-40 disabled:cursor-not-allowed rounded transition-colors shrink-0"
        >
          Clear
        </button>
        {requests.length > 0 && (
          <span className="text-[10px] text-gray-700 shrink-0">{visible.length}/{requests.length}</span>
        )}
      </div>

      <div className="px-3 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0">
        <div className="relative">
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by URL..."
            className="w-full pl-2 pr-6 py-1 text-[11px] bg-gray-800 border border-gray-700 rounded font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
          {filter && (
            <button
              onClick={() => setFilter('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 text-base leading-none"
              aria-label="Clear filter"
            >
              x
            </button>
          )}
        </div>
      </div>

      {!loading && primaryRequest && primarySummary && primarySummary.tracked.length > 0 && (
        <div className="px-3 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest font-medium select-none">
                Security summary
              </p>
              <p className="text-[11px] text-gray-400 truncate" title={primaryRequest.url}>
                {hostnameFromUrl(primaryRequest.url)} · {primaryRequestIsInferred ? 'inferred primary response' : 'latest document response'}
              </p>
            </div>
            <span className="text-[10px] text-gray-600 shrink-0">
              {primarySummary.ok.length}/{primarySummary.tracked.length} aligned with OWASP guidance
            </span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {primarySummary.ok.map(result => (
              <span key={`ok-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                {result.rule.badge}
              </span>
            ))}
            {primarySummary.warning.map(result => (
              <span key={`warning-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                Warn {result.rule.badge}
              </span>
            ))}
            {primarySummary.missing.map(result => (
              <span key={`missing-${result.rule.name}`} title={securityBadgeTitle(result)} className={`px-1.5 py-px text-[9px] font-bold border rounded ${securityBadgeClass(result)}`}>
                Missing {result.rule.badge}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center h-full text-gray-700 text-[11px]">
            Loading...
          </div>
        ) : visible.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-1.5 text-center px-8">
            <p className="text-gray-700 text-[11px]">
              {requests.length === 0
                ? 'No requests captured yet.'
                : 'No requests match the filter.'}
            </p>
            {requests.length === 0 && (
              <p className="text-gray-800 text-[10px]">
                Headers are captured as you browse. Navigate or reload the page.
              </p>
            )}
          </div>
        ) : (
          <div>
            {primaryRequest && (
              <div className="border-b border-gray-800/60">
                <div className="px-3 py-1.5 bg-gray-900/20 border-b border-gray-800/50">
                  <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium select-none">
                    Primary document response
                  </p>
                  {primaryRequestIsInferred && (
                    <p className="text-[10px] text-amber-400/80 mt-0.5">
                      No cached main document response was available, so this section is inferred from the active host.
                    </p>
                  )}
                </div>
                {renderRequestRow(primaryRequest, 'primary')}
              </div>
            )}
            {recentRequests.length > 0 && (
              <div>
                <div className="px-3 py-1.5 bg-gray-900/20 border-b border-gray-800/50">
                  <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium select-none">
                    Recent requests
                  </p>
                </div>
                {recentRequests.map(req => renderRequestRow(req, 'recent'))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
