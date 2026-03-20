import React, { useCallback, useEffect, useState } from 'react';
import type { StorageEntry, StorageScanResult, TokenData } from '../types';
import { decodeJwt, formatExpiry, isJwt } from '../utils/jwtUtils';

// ── Types ──────────────────────────────────────────────────────────────────────

interface DecodedView {
  source: 'scan' | 'manual';
  label:  string;
  raw:    string;
  token:  TokenData;
}

// ── Helpers / icons ────────────────────────────────────────────────────────────

const IconRefresh: React.FC<{ className?: string; spinning?: boolean }> = ({ className, spinning }) => (
  <svg className={`${className ?? ''} ${spinning ? 'animate-spin' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
  </svg>
);

const IconX: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
  </svg>
);

const IconChevron: React.FC<{ open: boolean }> = ({ open }) => (
  <svg className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path strokeLinecap="round" strokeLinejoin="round" d="m19 9-7 7-7-7" />
  </svg>
);

/** Render a JSON value as a syntax-highlighted tree (pure CSS, no lib). */
function JsonTree({ value, depth = 0 }: { value: unknown; depth?: number }): React.ReactElement {
  if (value === null)              return <span className="text-gray-500">null</span>;
  if (typeof value === 'boolean')  return <span className="text-yellow-400">{String(value)}</span>;
  if (typeof value === 'number')   return <span className="text-sky-400">{value}</span>;
  if (typeof value === 'string')   return <span className="text-emerald-400">"{value}"</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-gray-500">[]</span>;
    return (
      <span>
        <span className="text-gray-500">[</span>
        <span className="block pl-4">
          {value.map((v, i) => (
            <span key={i} className="block">
              <JsonTree value={v} depth={depth + 1} />
              {i < value.length - 1 && <span className="text-gray-600">,</span>}
            </span>
          ))}
        </span>
        <span className="text-gray-500">]</span>
      </span>
    );
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return <span className="text-gray-500">{'{}'}</span>;
    return (
      <span>
        <span className="text-gray-500">{'{'}</span>
        <span className="block pl-4">
          {entries.map(([k, v], i) => (
            <span key={k} className="block">
              <span className="text-purple-300">"{k}"</span>
              <span className="text-gray-500">: </span>
              <JsonTree value={v} depth={depth + 1} />
              {i < entries.length - 1 && <span className="text-gray-600">,</span>}
            </span>
          ))}
        </span>
        <span className="text-gray-500">{'}'}</span>
      </span>
    );
  }
  return <span className="text-gray-400">{String(value)}</span>;
}

// ── Token card ─────────────────────────────────────────────────────────────────

const TokenCard: React.FC<{
  view: DecodedView;
  onDismiss?: () => void;
}> = ({ view, onDismiss }) => {
  const [headerOpen, setHeaderOpen]   = useState(false);
  const [payloadOpen, setPayloadOpen] = useState(true);

  const { token } = view;
  const expiry = formatExpiry(token);

  return (
    <div className="border border-gray-800 rounded-lg overflow-hidden text-[11px] bg-gray-900/50">

      {/* Card header */}
      <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border-b border-gray-800">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-gray-200 truncate">{view.label}</span>
            {view.source === 'scan' && (
              <span className="text-[9px] uppercase font-bold px-1.5 py-px rounded bg-blue-900/40 text-blue-400 border border-blue-800/50 shrink-0">
                Storage
              </span>
            )}
            {view.source === 'manual' && (
              <span className="text-[9px] uppercase font-bold px-1.5 py-px rounded bg-violet-900/40 text-violet-400 border border-violet-800/50 shrink-0">
                Manual
              </span>
            )}
            {token.isExpired ? (
              <span className="text-[9px] uppercase font-bold px-1.5 py-px rounded bg-red-900/40 text-red-400 border border-red-800/50 shrink-0">
                Expired
              </span>
            ) : (
              <span className="text-[9px] uppercase font-bold px-1.5 py-px rounded bg-emerald-900/40 text-emerald-400 border border-emerald-800/50 shrink-0">
                Valid
              </span>
            )}
          </div>
          <p className="text-[10px] text-gray-600 mt-0.5">
            alg: <span className="text-gray-400">{token.header.alg}</span>
            {token.header.typ && <> · typ: <span className="text-gray-400">{token.header.typ}</span></>}
            {expiry && <> · {expiry}</>}
          </p>
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="p-1 rounded text-gray-600 hover:text-gray-300 hover:bg-gray-800 transition-colors shrink-0"
          >
            <IconX className="w-3 h-3" />
          </button>
        )}
      </div>

      {/* Raw token */}
      <div className="px-3 py-2 border-b border-gray-800/60">
        <p className="text-[10px] text-gray-600 mb-1 uppercase tracking-wider">Raw token</p>
        <div className="text-[10px] font-mono text-gray-600 break-all leading-relaxed bg-gray-950/60 rounded px-2 py-1.5">
          <span className="text-blue-400">{token.raw.split('.')[0]}</span>
          <span className="text-gray-700">.</span>
          <span className="text-emerald-400">{token.raw.split('.')[1]}</span>
          <span className="text-gray-700">.</span>
          <span className="text-gray-500">{token.raw.split('.')[2]}</span>
        </div>
      </div>

      {/* Header section */}
      <div className="border-b border-gray-800/60">
        <button
          onClick={() => setHeaderOpen(p => !p)}
          className="flex items-center gap-2 w-full px-3 py-2 hover:bg-gray-900/40 transition-colors"
        >
          <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium flex-1 text-left">Header</span>
          <IconChevron open={headerOpen} />
        </button>
        {headerOpen && (
          <div className="px-3 pb-2 font-mono text-[11px] leading-relaxed">
            <JsonTree value={token.header} />
          </div>
        )}
      </div>

      {/* Payload section */}
      <div>
        <button
          onClick={() => setPayloadOpen(p => !p)}
          className="flex items-center gap-2 w-full px-3 py-2 hover:bg-gray-900/40 transition-colors"
        >
          <span className="text-[10px] uppercase tracking-wider text-gray-500 font-medium flex-1 text-left">Payload</span>
          <IconChevron open={payloadOpen} />
        </button>
        {payloadOpen && (
          <div className="px-3 pb-3 font-mono text-[11px] leading-relaxed">
            <JsonTree value={token.payload} />
          </div>
        )}
      </div>

    </div>
  );
};

// ── TokensTab ──────────────────────────────────────────────────────────────────

export const TokensTab: React.FC = () => {
  const [scanResult, setScanResult]   = useState<StorageScanResult | null>(null);
  const [loading, setLoading]         = useState(true);
  const [manualRaw, setManualRaw]     = useState('');
  const [manualErr, setManualErr]     = useState<string | null>(null);
  const [manualViews, setManualViews] = useState<DecodedView[]>([]);

  // ── Load storage tokens from content script cache ─────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' });
      if (res?.success) {
        setScanResult(res.data as StorageScanResult | null);
      }
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // ── Decode storage entries that are JWTs ──────────────────────────────────
  const storageViews: DecodedView[] = (scanResult?.entries ?? []).reduce<DecodedView[]>((acc, entry: StorageEntry) => {
    if (!entry.isJwt) return acc;
    const result = decodeJwt(entry.value);
    if (!result.ok) return acc;
    acc.push({
      source: 'scan',
      label:  `${entry.area} → ${entry.key}`,
      raw:    entry.value,
      token:  result.token,
    });
    return acc;
  }, []);

  // ── Manual decode ─────────────────────────────────────────────────────────
  const handleManualDecode = () => {
    const raw = manualRaw.trim();
    if (!raw) { setManualErr('Paste a JWT token to decode.'); return; }
    if (!isJwt(raw)) { setManualErr('Input does not look like a JWT (expected 3 Base64Url segments).'); return; }

    const result = decodeJwt(raw);
    if (!result.ok) { setManualErr(result.error); return; }

    setManualErr(null);
    setManualViews(prev => {
      // Avoid exact duplicates
      if (prev.some(v => v.raw === raw)) return prev;
      return [{ source: 'manual', label: 'Pasted token', raw, token: result.token }, ...prev];
    });
    setManualRaw('');
  };

  const dismissManual = (raw: string) =>
    setManualViews(prev => prev.filter(v => v.raw !== raw));

  const allViews = [...manualViews, ...storageViews];

  const scannedAt = scanResult?.scannedAt
    ? new Date(scanResult.scannedAt).toLocaleTimeString()
    : null;

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* ── Manual input ───────────────────────────────────────────────────── */}
      <div className="border-b border-gray-800 bg-gray-900/30 px-3 py-3 space-y-2 shrink-0">
        <p className="text-[10px] uppercase tracking-widest text-gray-600 font-medium select-none">
          Decode a token
        </p>
        <div className="flex gap-2">
          <textarea
            value={manualRaw}
            onChange={e => { setManualRaw(e.target.value); setManualErr(null); }}
            onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) handleManualDecode(); }}
            placeholder="Paste a JWT here…"
            rows={2}
            className="flex-1 min-w-0 px-2 py-1.5 text-[11px] font-mono bg-gray-800 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors resize-none leading-relaxed"
          />
          <button
            onClick={handleManualDecode}
            className="px-3 py-1.5 self-stretch text-[11px] font-medium text-white bg-blue-600 hover:bg-blue-500 rounded transition-colors shrink-0"
          >
            Decode
          </button>
        </div>
        {manualErr && (
          <p className="text-[11px] text-red-400">{manualErr}</p>
        )}
      </div>

      {/* ── Storage scan status bar ────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-gray-900/20 border-b border-gray-800/60 shrink-0">
        <span className="text-[10px] text-gray-600 select-none">
          {loading
            ? 'Loading…'
            : scannedAt
              ? `Page scan at ${scannedAt} · ${storageViews.length} token${storageViews.length !== 1 ? 's' : ''} found`
              : 'No page scan available — navigate to a page to trigger scanning'}
        </span>
        <button
          onClick={() => { void load(); }}
          title="Refresh scan results"
          className="p-1 rounded text-gray-600 hover:text-blue-400 hover:bg-gray-800 transition-colors"
        >
          <IconRefresh className="w-3 h-3" spinning={loading} />
        </button>
      </div>

      {/* ── Token list ─────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {!loading && allViews.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full gap-2 text-center select-none">
            <svg className="w-7 h-7 text-gray-800" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 0 1 21.75 8.25Z" />
            </svg>
            <p className="text-[11px] text-gray-700 max-w-[240px] leading-relaxed">
              Paste a JWT above, or navigate to a page that stores tokens in localStorage / sessionStorage.
            </p>
          </div>
        )}
        {allViews.map(view => (
          <TokenCard
            key={view.raw}
            view={view}
            onDismiss={view.source === 'manual' ? () => dismissManual(view.raw) : undefined}
          />
        ))}
      </div>

    </div>
  );
};
