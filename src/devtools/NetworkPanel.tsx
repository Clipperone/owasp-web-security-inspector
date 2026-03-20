import React, { useCallback, useEffect, useRef, useState } from 'react';

// ── Types ──────────────────────────────────────────────────────────────────────

interface CapturedRequest {
  id:            number;
  method:        string;
  url:           string;
  status:        number;
  statusText:    string;
  durationMs:    number;
  authorization: string | null;
  contentType:   string | null;
  timestamp:     number;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

let _seq = 0;
const nextId = () => ++_seq;

function getRequestHeader(
  headers: chrome.devtools.network.Request['request']['headers'],
  name: string,
): string | null {
  const lc = name.toLowerCase();
  const h  = headers.find(hdr => hdr.name.toLowerCase() === lc);
  return h?.value ?? null;
}

function methodColor(method: string): string {
  switch (method.toUpperCase()) {
    case 'GET':    return 'text-emerald-400';
    case 'POST':   return 'text-blue-400';
    case 'PUT':    return 'text-amber-400';
    case 'PATCH':  return 'text-orange-400';
    case 'DELETE': return 'text-red-400';
    default:       return 'text-gray-400';
  }
}

function statusColor(status: number): string {
  if (status === 0)   return 'text-gray-600';
  if (status < 300)   return 'text-emerald-400';
  if (status < 400)   return 'text-amber-400';
  if (status < 500)   return 'text-orange-400';
  return 'text-red-400';
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + (u.search ? u.search : '');
  } catch {
    return url;
  }
}

function hostOf(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

// ── Component ──────────────────────────────────────────────────────────────────

const MAX_REQUESTS = 50;

export const NetworkPanel: React.FC = () => {
  const [requests, setRequests] = useState<CapturedRequest[]>([]);
  const [filter,   setFilter]   = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);
  const [paused,   setPaused]   = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  // ── Attach devtools network listener ─────────────────────────────────────────
  useEffect(() => {
    const handler = (req: chrome.devtools.network.Request) => {
      if (pausedRef.current) return;

      // chrome.devtools.network.Request implements the HAR entry shape
      const har = req as unknown as {
        request:  { method: string; url: string; headers: { name: string; value: string }[] };
        response: { status: number; statusText: string; headers: { name: string; value: string }[] };
        time:     number;
      };

      const captured: CapturedRequest = {
        id:            nextId(),
        method:        har.request.method,
        url:           har.request.url,
        status:        har.response.status,
        statusText:    har.response.statusText,
        durationMs:    Math.round(har.time),
        authorization: getRequestHeader(har.request.headers, 'authorization'),
        contentType:   har.response.headers.find(
          h => h.name.toLowerCase() === 'content-type',
        )?.value ?? null,
        timestamp:     Date.now(),
      };

      setRequests(prev => {
        const next = [captured, ...prev];
        return next.length > MAX_REQUESTS ? next.slice(0, MAX_REQUESTS) : next;
      });
    };

    chrome.devtools.network.onRequestFinished.addListener(handler);
    return () => chrome.devtools.network.onRequestFinished.removeListener(handler);
  }, []);

  const handleClear  = useCallback(() => { setRequests([]); setExpanded(null); }, []);
  const toggleExpand = (id: number) => setExpanded(prev => prev === id ? null : id);

  const visible = filter.trim()
    ? requests.filter(r =>
        r.url.toLowerCase().includes(filter.toLowerCase()) ||
        r.method.toLowerCase().includes(filter.toLowerCase()),
      )
    : requests;

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-300 text-[11px] font-mono select-none">

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <span className="text-[10px] uppercase tracking-widest text-gray-600 font-medium mr-1">
          Network
        </span>

        {/* Filter input */}
        <div className="relative flex-1 max-w-xs">
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by URL or method…"
            className="w-full pl-2 pr-6 py-1 text-[11px] bg-gray-800 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
          {filter && (
            <button
              onClick={() => setFilter('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-400 text-base leading-none"
            >
              ×
            </button>
          )}
        </div>

        <div className="flex items-center gap-1.5 ml-auto shrink-0">
          <button
            onClick={() => setPaused(p => !p)}
            title={paused ? 'Resume capture' : 'Pause capture'}
            className={[
              'px-2 py-1 rounded text-[11px] border transition-colors',
              paused
                ? 'bg-amber-900/30 border-amber-700/50 text-amber-400 hover:bg-amber-900/50'
                : 'bg-gray-800 border-gray-700 text-gray-500 hover:text-gray-300',
            ].join(' ')}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>

          <button
            onClick={handleClear}
            disabled={requests.length === 0}
            className="px-2 py-1 rounded text-[11px] border border-gray-700 bg-gray-800 text-gray-500 hover:text-red-400 hover:border-red-800/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Clear
          </button>
        </div>

        {requests.length > 0 && (
          <span className="text-[10px] text-gray-700 shrink-0 ml-1">
            {visible.length}/{requests.length}
          </span>
        )}
      </div>

      {/* Column headers */}
      <div className="grid grid-cols-[56px_52px_1fr_144px_60px] gap-x-2 px-3 py-1.5 border-b border-gray-800 bg-gray-900/30 text-[10px] uppercase tracking-widest text-gray-600 shrink-0">
        <span>Method</span>
        <span>Status</span>
        <span>URL</span>
        <span>Authorization</span>
        <span className="text-right">ms</span>
      </div>

      {/* Request rows */}
      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-700 text-center px-8">
            {requests.length === 0
              ? 'Waiting for requests… Navigate or reload the inspected page.'
              : 'No requests match the filter.'}
          </div>
        ) : (
          visible.map(r => (
            <div key={r.id} className="border-b border-gray-800/50">
              {/* Summary row */}
              <button
                onClick={() => toggleExpand(r.id)}
                className="w-full grid grid-cols-[56px_52px_1fr_144px_60px] gap-x-2 px-3 py-1.5 hover:bg-gray-900/60 transition-colors text-left"
                title={r.url}
              >
                <span className={`font-bold ${methodColor(r.method)}`}>
                  {r.method}
                </span>
                <span className={statusColor(r.status)}>
                  {r.status || '—'}
                </span>
                <span className="min-w-0 truncate">
                  <span className="text-gray-600">{hostOf(r.url)}</span>
                  <span className="text-gray-300">{shortUrl(r.url)}</span>
                </span>
                <span className="truncate">
                  {r.authorization ? (
                    <span className="text-blue-400">
                      {r.authorization.slice(0, 28)}{r.authorization.length > 28 ? '…' : ''}
                    </span>
                  ) : (
                    <span className="text-gray-800">—</span>
                  )}
                </span>
                <span className="text-right text-gray-600">
                  {r.durationMs > 0 ? r.durationMs : '—'}
                </span>
              </button>

              {/* Expanded detail */}
              {expanded === r.id && (
                <div className="px-4 pb-3 pt-1 bg-gray-900/40 space-y-1.5 text-[10px] border-t border-gray-800/40">
                  <p className="break-all text-gray-400">
                    <span className="text-gray-600 uppercase tracking-wider mr-2">URL</span>
                    {r.url}
                  </p>
                  {r.authorization && (
                    <p className="break-all">
                      <span className="text-gray-600 uppercase tracking-wider mr-2">Authorization</span>
                      <span className="text-blue-400">{r.authorization}</span>
                    </p>
                  )}
                  {r.contentType && (
                    <p>
                      <span className="text-gray-600 uppercase tracking-wider mr-2">Content-Type</span>
                      <span className="text-gray-500">{r.contentType}</span>
                    </p>
                  )}
                  <p className="text-gray-700">
                    <span className="uppercase tracking-wider mr-2">Captured</span>
                    {new Date(r.timestamp).toLocaleTimeString()}
                  </p>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
