import React, { useCallback, useEffect, useState } from 'react';
import type { StorageEntry, StorageScanResult, TokenData } from '../types';
import { assessManualToken } from '../utils/assessment';
import { decodeJwt, formatExpiry, isJwt } from '../utils/jwtUtils';
import { SUPPORTED_VERIFY_ALGS, verifyJwt } from '../utils/jwtVerify';
import type { JwtAlg, VerificationKeyInput, VerifyResult } from '../utils/jwtVerify';
import { StatusBadge, severityLabel, severityTone } from './ui';

// ── Timestamp helper ───────────────────────────────────────────────────────────

function unixToLocal(unix: number): string {
  return new Date(unix * 1_000).toLocaleString();
}

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

const TIMESTAMP_CLAIMS = new Set(['exp', 'iat', 'nbf']);

/** Render a JSON value as a syntax-highlighted tree (pure CSS, no lib). */
function JsonTree({ value, depth = 0, parentKey }: { value: unknown; depth?: number; parentKey?: string }): React.ReactElement {
  if (value === null)              return <span className="text-gray-500">null</span>;
  if (typeof value === 'boolean')  return <span className="text-yellow-400">{String(value)}</span>;
  if (typeof value === 'number') {
    const isTs = parentKey !== undefined && TIMESTAMP_CLAIMS.has(parentKey);
    return (
      <span>
        <span className="text-sky-400">{value}</span>
        {isTs && (
          <span className="ml-1.5 text-[10px] text-gray-600 font-sans">
            ({unixToLocal(value)})
          </span>
        )}
      </span>
    );
  }
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
              <JsonTree value={v} depth={depth + 1} parentKey={k} />
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

// ── Signature verification (opt-in, local, Web Crypto) ──────────────────────────

const KEY_TYPE_OPTIONS: Array<{ id: VerificationKeyInput['kind']; label: string; placeholder: string }> = [
  { id: 'hmac-secret', label: 'Secret (HS*)', placeholder: 'Shared HMAC secret…' },
  { id: 'pem-spki', label: 'PEM public key', placeholder: '-----BEGIN PUBLIC KEY-----\n…' },
  { id: 'jwk', label: 'JWK', placeholder: '{ "kty": "RSA", … }' },
  { id: 'jwks', label: 'JWKS', placeholder: '{ "keys": [ … ] }' },
];

function resultTone(status: VerifyResult['status']): 'ok' | 'bad' | 'warn' {
  switch (status) {
    case 'verified': return 'ok';
    case 'unsupported-alg': return 'warn';
    default: return 'bad';
  }
}

function resultLabel(status: VerifyResult['status']): string {
  switch (status) {
    case 'verified': return 'Verified';
    case 'invalid': return 'Invalid';
    case 'unsupported-alg': return 'Unsupported';
    case 'error': return 'Error';
  }
}

function buildKeyInput(kind: VerificationKeyInput['kind'], text: string): VerificationKeyInput {
  switch (kind) {
    case 'hmac-secret': return { kind, secret: text };
    case 'pem-spki': return { kind, pem: text };
    case 'jwk': return { kind, jwk: JSON.parse(text) as JsonWebKey };
    case 'jwks': return { kind, jwks: JSON.parse(text) as { keys: JsonWebKey[] } };
  }
}

const SignatureVerifyPanel: React.FC<{ token: TokenData; onResult: (result: VerifyResult) => void }> = ({ token, onResult }) => {
  const headerAlg = typeof token.header.alg === 'string' ? token.header.alg : '';
  const initialAlg: JwtAlg = (SUPPORTED_VERIFY_ALGS as string[]).includes(headerAlg) ? (headerAlg as JwtAlg) : 'HS256';
  const [alg, setAlg] = useState<JwtAlg>(initialAlg);
  const [keyKind, setKeyKind] = useState<VerificationKeyInput['kind']>(initialAlg.startsWith('HS') ? 'hmac-secret' : 'pem-spki');
  const [keyText, setKeyText] = useState('');
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = headerAlg !== '' && headerAlg !== alg;
  const placeholder = KEY_TYPE_OPTIONS.find(o => o.id === keyKind)?.placeholder ?? '';

  const handleVerify = async () => {
    setBusy(true);
    let outcome: VerifyResult;
    try {
      outcome = await verifyJwt(token.raw, { expectedAlg: alg, key: buildKeyInput(keyKind, keyText) });
    } catch (err) {
      outcome = { status: 'error', reason: err instanceof Error ? err.message : 'Invalid key input.' };
    }
    setResult(outcome);
    onResult(outcome);
    setBusy(false);
  };

  return (
    <div className="space-y-2 rounded border border-gray-800 bg-gray-950/40 px-2.5 py-2">
      <p className="text-[10px] uppercase tracking-widest text-gray-500 font-medium select-none">Verify signature</p>
      <p className="text-[10px] text-gray-600 leading-relaxed">
        Runs locally via Web Crypto using a key you supply — nothing is sent anywhere. The algorithm you pick is used for
        verification (not the token header), which blocks algorithm-confusion attacks.
      </p>
      <div className="grid grid-cols-2 gap-1.5">
        <label className="block text-[10px] text-gray-500">
          Algorithm
          <select
            value={alg}
            onChange={e => setAlg(e.target.value as JwtAlg)}
            className="mt-0.5 w-full bg-gray-800 border border-gray-700 rounded px-1.5 py-1 text-[11px] text-gray-200 focus:outline-none focus:border-blue-600"
          >
            {SUPPORTED_VERIFY_ALGS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </label>
        <label className="block text-[10px] text-gray-500">
          Key type
          <select
            value={keyKind}
            onChange={e => setKeyKind(e.target.value as VerificationKeyInput['kind'])}
            className="mt-0.5 w-full bg-gray-800 border border-gray-700 rounded px-1.5 py-1 text-[11px] text-gray-200 focus:outline-none focus:border-blue-600"
          >
            {KEY_TYPE_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>
        </label>
      </div>
      {mismatch && (
        <p className="text-[10px] text-amber-400 leading-relaxed">
          Token header alg is <span className="font-mono">{headerAlg}</span> but you selected <span className="font-mono">{alg}</span>.
        </p>
      )}
      <textarea
        value={keyText}
        onChange={e => setKeyText(e.target.value)}
        placeholder={placeholder}
        rows={3}
        className="w-full px-2 py-1.5 text-[11px] font-mono bg-gray-800 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 resize-none leading-relaxed"
      />
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => { void handleVerify(); }}
          disabled={busy || keyText.trim().length === 0}
          className="px-2 py-1 text-[11px] rounded border border-gray-700 bg-gray-800 text-gray-300 hover:text-blue-400 hover:border-blue-800/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {busy ? 'Verifying…' : 'Verify'}
        </button>
        {result && <StatusBadge tone={resultTone(result.status)}>{resultLabel(result.status)}</StatusBadge>}
        {result?.status === 'error' && <span className="text-[10px] text-red-400 min-w-0 truncate">{result.reason}</span>}
        {result?.status === 'unsupported-alg' && <span className="text-[10px] text-amber-400">{result.alg}</span>}
      </div>
    </div>
  );
};

// ── Token card ─────────────────────────────────────────────────────────────────

const TokenCard: React.FC<{
  view: DecodedView;
  onDismiss?: () => void;
}> = ({ view, onDismiss }) => {
  const [headerOpen,  setHeaderOpen]  = useState(false);
  const [payloadOpen, setPayloadOpen] = useState(true);
  const [sigOpen,     setSigOpen]     = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);

  const { token } = view;
  const expiry = formatExpiry(token);
  const parts  = token.raw.split('.');

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

      {/* ⚠️ Expired banner */}
      {token.isExpired && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-950/60 border-b border-red-900/50">
          <span className="text-base leading-none select-none">⚠️</span>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-semibold text-red-400">Token Expired</p>
            {token.expiresAt && (
              <p className="text-[10px] text-red-600 mt-px">
                Expired on {token.expiresAt.toLocaleString()}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Raw token — three segments colour-coded */}
      <div className="px-3 py-2 border-b border-gray-800/60">
        <p className="text-[10px] text-gray-600 mb-1 uppercase tracking-wider">Raw token</p>
        <div className="text-[10px] font-mono break-all leading-relaxed bg-gray-950/60 rounded px-2 py-1.5">
          <span className="text-blue-400">{parts[0]}</span>
          <span className="text-gray-700">.</span>
          <span className="text-emerald-400">{parts[1]}</span>
          <span className="text-gray-700">.</span>
          <span className="text-gray-500">{parts[2]}</span>
        </div>
      </div>

      {/* Header section */}
      <div className="border-b border-gray-800/60">
        <button
          onClick={() => setHeaderOpen(p => !p)}
          className="flex items-center gap-2 w-full px-3 py-2 hover:bg-gray-900/40 transition-colors"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0" />
          <span className="text-[10px] uppercase tracking-wider text-blue-400 font-semibold flex-1 text-left">Header</span>
          <IconChevron open={headerOpen} />
        </button>
        {headerOpen && (
          <div className="px-3 pb-2 font-mono text-[11px] leading-relaxed border-t border-gray-800/40">
            <JsonTree value={token.header} />
          </div>
        )}
      </div>

      {/* Payload section */}
      <div className="border-b border-gray-800/60">
        <button
          onClick={() => setPayloadOpen(p => !p)}
          className="flex items-center gap-2 w-full px-3 py-2 hover:bg-gray-900/40 transition-colors"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
          <span className="text-[10px] uppercase tracking-wider text-emerald-400 font-semibold flex-1 text-left">Payload</span>
          <IconChevron open={payloadOpen} />
        </button>
        {payloadOpen && (
          <div className="px-3 pb-3 font-mono text-[11px] leading-relaxed border-t border-gray-800/40">
            <JsonTree value={token.payload} />
          </div>
        )}
      </div>

      {/* Signature section */}
      <div>
        <button
          onClick={() => setSigOpen(p => !p)}
          className="flex items-center gap-2 w-full px-3 py-2 hover:bg-gray-900/40 transition-colors"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-gray-500 shrink-0" />
          <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold flex-1 text-left">Signature</span>
          {verifyResult
            ? <span className="mr-1"><StatusBadge tone={resultTone(verifyResult.status)}>{resultLabel(verifyResult.status)}</StatusBadge></span>
            : <span className="text-[9px] text-gray-700 mr-1 select-none">not verified</span>}
          <IconChevron open={sigOpen} />
        </button>
        {sigOpen && (
          <div className="px-3 pb-3 border-t border-gray-800/40 space-y-2">
            <div className="font-mono text-[10px] text-gray-500 break-all bg-gray-950/60 rounded px-2 py-1.5">
              {token.signature || <span className="text-gray-700 italic">empty (alg: none)</span>}
            </div>
            <SignatureVerifyPanel token={token} onResult={setVerifyResult} />
          </div>
        )}
      </div>

    </div>
  );
};

// ── TokensTab ──────────────────────────────────────────────────────────────────

export const TokensTab: React.FC<{
  initialToken?: string | null;
  onConsumeToken?: () => void;
}> = ({ initialToken, onConsumeToken }) => {
  const [scanResult, setScanResult]   = useState<StorageScanResult | null>(null);
  const [loading, setLoading]         = useState(true);
  const [scanErr, setScanErr]         = useState<string | null>(null);
  const [manualRaw, setManualRaw]     = useState('');
  const [manualToken, setManualToken] = useState<TokenData | null>(null);
  const [manualErr, setManualErr]     = useState<string | null>(null);

  // Pre-populate textarea when a token is pushed from another tab
  useEffect(() => {
    if (!initialToken) return;
    handleManualInput(initialToken);
    onConsumeToken?.();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialToken]);

  // ── Load storage tokens from content script cache ─────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' });
      if (res?.success) {
        setScanResult(res.data as StorageScanResult | null);
        setScanErr(null);
      }
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, []);

  const refreshScan = useCallback(async () => {
    setLoading(true);
    setScanErr(null);

    try {
      const res = await chrome.runtime.sendMessage({ type: 'RUN_STORAGE_SCAN' });
      if (!res?.success) {
        setScanErr(res?.error ?? 'Failed to refresh scan results.');
        return;
      }

      const cached = await chrome.runtime.sendMessage({ type: 'GET_STORAGE_TOKENS' });
      if (cached?.success) {
        setScanResult(cached.data as StorageScanResult | null);
      } else {
        setScanErr(cached?.error ?? 'Failed to load refreshed scan results.');
      }
    } catch {
      setScanErr('Storage scan is not available on this tab.');
    } finally {
      setLoading(false);
    }
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

  // ── Real-time manual decode ────────────────────────────────────────────────
  const handleManualInput = (raw: string) => {
    setManualRaw(raw);
    const trimmed = raw.trim();
    if (!trimmed) { setManualToken(null); setManualErr(null); return; }
    if (!isJwt(trimmed)) {
      setManualToken(null);
      setManualErr('Not a valid JWT — expecting three Base64Url segments separated by dots.');
      return;
    }
    const result = decodeJwt(trimmed);
    if (!result.ok) { setManualToken(null); setManualErr(result.error); return; }
    setManualToken(result.token);
    setManualErr(null);
  };

  const manualView: DecodedView | null = manualToken
    ? { source: 'manual', label: 'Live preview', raw: manualToken.raw, token: manualToken }
    : null;

  const manualFindings = manualToken ? assessManualToken(manualToken.raw) : [];

  const allViews = [
    ...(manualView ? [manualView] : []),
    ...storageViews,
  ];

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
        <div className="relative">
          <textarea
            value={manualRaw}
            onChange={e => handleManualInput(e.target.value)}
            placeholder="Paste a JWT here — decoded in real time…"
            rows={3}
            className={[
              'w-full px-2 py-1.5 text-[11px] font-mono bg-gray-800 border rounded text-gray-300 placeholder-gray-600',
              'focus:outline-none transition-colors resize-none leading-relaxed',
              manualErr  ? 'border-red-700 focus:border-red-600'
              : manualToken ? 'border-emerald-700 focus:border-emerald-600'
              : 'border-gray-700 focus:border-blue-600',
            ].join(' ')}
          />
          {manualRaw && (
            <button
              onClick={() => { setManualRaw(''); setManualToken(null); setManualErr(null); }}
              className="absolute top-1.5 right-1.5 p-0.5 rounded text-gray-600 hover:text-gray-300 hover:bg-gray-700 transition-colors"
              title="Clear"
            >
              <IconX className="w-3 h-3" />
            </button>
          )}
        </div>
        {manualErr && (
          <p className="text-[11px] text-red-400">{manualErr}</p>
        )}
        {manualToken && (
          <div className="space-y-2 rounded border border-gray-800 bg-gray-950/40 px-2.5 py-2">
            <div className="flex items-center justify-between gap-2">
              <p className="text-[10px] uppercase tracking-widest text-gray-500 font-medium select-none">
                Risk preview
              </p>
              <span className="text-[10px] text-gray-600">
                {manualFindings.length} finding{manualFindings.length !== 1 ? 's' : ''}
              </span>
            </div>
            {manualFindings.length > 0 ? (
              <div className="space-y-1.5">
                {manualFindings.map(finding => (
                  <div key={finding.id} className="flex items-start gap-2">
                    <StatusBadge tone={severityTone(finding.severity)}>{severityLabel(finding.severity).toUpperCase()}</StatusBadge>
                    <div className="min-w-0">
                      <p className="text-[11px] text-gray-200 leading-relaxed">{finding.title}</p>
                      <p className="text-[10px] text-gray-500 leading-relaxed">{finding.summary}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-gray-500 leading-relaxed">
                No obvious structural JWT risk signals were detected. Signature trust and revocation state are still outside the scope of this local preview.
              </p>
            )}
          </div>
        )}
      </div>

      {/* ── Storage scan status bar ────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-gray-900/20 border-b border-gray-800/60 shrink-0">
        <span className="text-[10px] text-gray-600 select-none">
          {loading
            ? 'Loading…'
            : scanErr
              ? scanErr
            : scannedAt
              ? `Page scan at ${scannedAt} · ${storageViews.length} token${storageViews.length !== 1 ? 's' : ''} found`
              : 'No page scan available — navigate to a page to trigger scanning'}
        </span>
        <button
          onClick={() => { void refreshScan(); }}
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
          />
        ))}
      </div>

    </div>
  );
};
