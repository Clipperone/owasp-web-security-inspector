import React, { useCallback, useEffect, useState } from 'react';
import type { CachedRequest } from '../types';

// ÔöÇÔöÇ Security header catalogue ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ

const SECURITY_HEADERS: Record<string, { badge: string; cls: string }> = {
  'content-security-policy':     { badge: 'CSP',    cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50' },
  'strict-transport-security':   { badge: 'HSTS',   cls: 'text-emerald-400 bg-emerald-900/30 border-emerald-800/50' },
  'x-frame-options':             { badge: 'XFO',    cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' },
  'x-content-type-options':      { badge: 'XCTO',   cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' },
  'referrer-policy':             { badge: 'RP',     cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' },
  'permissions-policy':          { badge: 'PP',     cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' },
  'set-cookie':                  { badge: 'Cookie', cls: 'text-amber-400 bg-amber-900/30 border-amber-800/50' },
  'access-control-allow-origin': { badge: 'CORS',   cls: 'text-orange-400 bg-orange-900/30 border-orange-800/50' },
};

// ÔöÇÔöÇ Helpers ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ

function statusColor(code: number): string {
  if (code === 0)   return 'text-gray-600';
  if (code < 300)   return 'text-emerald-400';
  if (code < 400)   return 'text-amber-400';
  if (code < 500)   return 'text-orange-400';
  return 'text-red-400';
}

function resourceBadge(type: string): { label: string; cls: string } {
  switch (type) {
    case 'main_frame':     return { label: 'DOC', cls: 'text-blue-400 bg-blue-900/30 border-blue-800/50' };
    case 'xmlhttprequest': return { label: 'XHR', cls: 'text-purple-400 bg-purple-900/30 border-purple-800/50' };
    default:               return { label: type.toUpperCase().slice(0, 4), cls: 'text-gray-500 bg-gray-800/60 border-gray-700' };
  }
}

// ÔöÇÔöÇ Component ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ

export const CurrentHeadersTab: React.FC = () => {
  const [tabId,    setTabId]    = useState<number | null>(null);
  const [tabUrl,   setTabUrl]   = useState('');
  const [requests, setRequests] = useState<CachedRequest[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [filter,   setFilter]   = useState('');
  const [loading,  setLoading]  = useState(true);

  // ÔöÇÔöÇ Fetch cached headers for a given tab ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ
  const fetchHeaders = useCallback(async (id: number) => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_TAB_HEADERS', payload: id });
      if (res?.success) setRequests((res.data as CachedRequest[]) ?? []);
    } catch { /* silent */ }
  }, []);

  // Initial load
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

  // Auto-refresh every 3 s so the list stays live without manual interaction
  useEffect(() => {
    if (tabId === null) return;
    const interval = setInterval(() => { void fetchHeaders(tabId); }, 3000);
    return () => clearInterval(interval);
  }, [tabId, fetchHeaders]);

  // ÔöÇÔöÇ Actions ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ
  const handleClear = () => {
    if (tabId === null) return;
    void chrome.storage.session.remove(`tabHeaders:${tabId}`).then(() => {
      setRequests([]);
      setExpanded(null);
    });
  };

  // ÔöÇÔöÇ Filtered view ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ
  const visible = filter.trim()
    ? requests.filter(r => r.url.toLowerCase().includes(filter.toLowerCase()))
    : requests;

  // ÔöÇÔöÇ Render ÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇÔöÇ
  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Toolbar */}
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

      {/* Filter */}
      <div className="px-3 py-2 border-b border-gray-800 bg-gray-900/20 shrink-0">
        <div className="relative">
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by URLÔÇª"
            className="w-full pl-2 pr-6 py-1 text-[11px] bg-gray-800 border border-gray-700 rounded font-mono text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
          {filter && (
            <button
              onClick={() => setFilter('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 text-base leading-none"
            >
              ├ù
            </button>
          )}
        </div>
      </div>

      {/* Request list */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center h-full text-gray-700 text-[11px]">
            LoadingÔÇª
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
          visible.map((req, idx) => {
            const badge  = resourceBadge(req.resourceType);
            const isOpen = expanded === idx;
            return (
              <div key={idx} className="border-b border-gray-800/50">

                {/* Summary row */}
                <button
                  onClick={() => setExpanded(prev => prev === idx ? null : idx)}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-gray-900/60 transition-colors text-left group"
                  title={req.url}
                >
                  <span className={`px-1.5 py-px text-[9px] font-bold border rounded shrink-0 ${badge.cls}`}>
                    {badge.label}
                  </span>
                  <span className={`w-10 text-[11px] font-mono font-bold shrink-0 ${statusColor(req.statusCode)}`}>
                    {req.statusCode || 'ÔÇö'}
                  </span>
                  <span className="flex-1 min-w-0 text-[11px] text-gray-400 font-mono truncate">
                    {req.url}
                  </span>
                  <span className="text-[10px] text-gray-700 shrink-0">
                    {new Date(req.timestamp).toLocaleTimeString()}
                  </span>
                  <svg
                    className={`w-3 h-3 text-gray-700 shrink-0 transition-transform duration-150 ${isOpen ? 'rotate-180' : ''}`}
                    viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="m19 9-7 7-7-7" />
                  </svg>
                </button>

                {/* Expanded header list */}
                {isOpen && (
                  <div className="bg-gray-900/40 border-t border-gray-800/40 px-4 pt-2 pb-3">
                    <p className="text-[10px] text-gray-700 uppercase tracking-widest mb-2 font-medium select-none">
                      Response Headers ({req.responseHeaders.length})
                    </p>
                    {req.responseHeaders.length === 0 ? (
                      <p className="text-[10px] text-gray-800">No headers were captured for this request.</p>
                    ) : (
                      <div className="space-y-1">
                        {req.responseHeaders.map((h, i) => {
                          const sec = SECURITY_HEADERS[h.name.toLowerCase()];
                          return (
                            <div key={i} className="grid grid-cols-[180px_1fr] gap-x-3 text-[10px]">
                              <div className="flex items-center gap-1.5 min-w-0">
                                {sec && (
                                  <span className={`px-1 py-px text-[8px] font-bold border rounded shrink-0 ${sec.cls}`}>
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
          })
        )}
      </div>

    </div>
  );
};
