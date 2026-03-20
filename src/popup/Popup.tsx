import React, { useState } from 'react';
import { CookieTab } from './CookieTab';
import { CurrentHeadersTab } from './CurrentHeadersTab';
import { HeadersTab } from './HeadersTab';
import { ScopeProvider, useScope } from './ScopeContext';
import { TokensTab } from './TokensTab';

type TabId = 'cookies' | 'headers' | 'tokens' | 'response';

const TABS: { id: TabId; label: string }[] = [
  { id: 'cookies',  label: 'Cookies'  },
  { id: 'headers',  label: 'Headers'  },
  { id: 'tokens',   label: 'Tokens'   },
  { id: 'response', label: 'Response' },
];

// ── Scope toggle (rendered inside ScopeProvider) ─────────────────────────────
const ScopeToggle: React.FC = () => {
  const { mode, setMode, activeDomain, loading } = useScope();
  const isDomain = mode === 'domain';

  return (
    <div className="flex items-center gap-2 shrink-0">
      {/* Domain label */}
      <span className="text-[10px] text-gray-500 truncate max-w-[120px] select-none" title={activeDomain || undefined}>
        {loading
          ? '…'
          : isDomain && activeDomain
            ? activeDomain
            : 'All sites'}
      </span>

      {/* Toggle */}
      <button
        onClick={() => setMode(isDomain ? 'global' : 'domain')}
        disabled={loading || !activeDomain}
        title={isDomain ? 'Switch to Global (all sites)' : `Restrict to ${activeDomain || 'current domain'}`}
        className="relative flex h-4 w-7 items-center rounded-full transition-colors duration-200 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
        style={{ background: isDomain ? '#2563eb' : '#374151' }}
      >
        <span
          className={[
            'absolute h-3 w-3 rounded-full bg-white shadow transition-transform duration-200',
            isDomain ? 'translate-x-3.5' : 'translate-x-0.5',
          ].join(' ')}
        />
      </button>

      {/* Mode label */}
      <span className={`text-[10px] font-medium select-none ${isDomain ? 'text-blue-400' : 'text-gray-600'}`}>
        {isDomain ? 'Site only' : 'Global'}
      </span>
    </div>
  );
};

// ── Inner popup (must be inside ScopeProvider) ─────────────────────────────────
const PopupInner: React.FC = () => {
  const [active, setActive]         = useState<TabId>('cookies');
  const [pendingToken, setPendingToken] = useState<string | null>(null);

  const sendToTokens = (value: string) => {
    setPendingToken(value);
    setActive('tokens');
  };

  return (
    <div className="w-[580px] h-[680px] bg-gray-950 text-gray-100 flex flex-col overflow-hidden font-mono text-xs">

      {/* ── App header ─────────────────────────────────────────────────── */}
      <header className="flex items-center gap-2.5 px-4 py-2.5 bg-gray-900 border-b border-gray-800 shrink-0">
        <svg
          className="w-4 h-4 text-blue-400 shrink-0"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
        <h1 className="text-[11px] font-semibold tracking-widest text-gray-300 uppercase select-none flex-1 min-w-0 truncate">
          Cookie · Token · Header Editor
        </h1>
        <ScopeToggle />
      </header>

      {/* ── Tab bar ────────────────────────────────────────────────────── */}
      <nav className="flex border-b border-gray-800 bg-gray-900/40 shrink-0">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={[
              'px-5 py-2.5 text-[11px] font-medium tracking-wide transition-all duration-150 border-b-2 -mb-px select-none',
              active === tab.id
                ? 'text-blue-400 border-blue-500 bg-gray-950/60'
                : 'text-gray-500 border-transparent hover:text-gray-300 hover:border-gray-700',
            ].join(' ')}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* ── Panel area ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-hidden">
        {active === 'cookies'  && <CookieTab onSendToTokens={sendToTokens} />}
        {active === 'headers'  && <HeadersTab />}
        {active === 'tokens'   && <TokensTab initialToken={pendingToken} onConsumeToken={() => setPendingToken(null)} />}
        {active === 'response' && <CurrentHeadersTab />}
      </main>

    </div>
  );
};

export const Popup: React.FC = () => (
  <ScopeProvider>
    <PopupInner />
  </ScopeProvider>
);
