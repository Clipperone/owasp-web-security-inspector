import React, { useCallback, useEffect, useState } from 'react';
import { AssessmentTab } from './AssessmentTab';
import { CookieTab } from './CookieTab';
import { CurrentHeadersTab } from './CurrentHeadersTab';
import { TokensTab } from './TokensTab';

type TabId = 'assessment' | 'cookies' | 'tokens' | 'response';

const TABS: { id: TabId; label: string }[] = [
  { id: 'assessment', label: 'Assessment'       },
  { id: 'cookies',  label: 'Cookies'          },
  { id: 'response', label: 'Response Headers' },
  { id: 'tokens',   label: 'Tokens'           },
];

const HOST_ACCESS: chrome.permissions.Permissions = { origins: ['<all_urls>'] };

export const Panel: React.FC = () => {
  const [active, setActive]         = useState<TabId>('assessment');
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  // Firefox treats host_permissions as optional at install, so the observers
  // return nothing until the user grants access. On Chromium this is always
  // granted, so the banner never appears. Undefined = not yet checked.
  const [hasHostAccess, setHasHostAccess] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const granted = await chrome.permissions.contains(HOST_ACCESS);
        if (!cancelled) setHasHostAccess(granted);
      } catch {
        // permissions API unavailable — assume access is manifest-granted.
        if (!cancelled) setHasHostAccess(true);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const requestHostAccess = useCallback(async () => {
    try {
      const granted = await chrome.permissions.request(HOST_ACCESS);
      if (granted) setHasHostAccess(true);
    } catch {
      // Ignore — the user can retry.
    }
  }, []);

  const sendToTokens = (value: string) => {
    setPendingToken(value);
    setActive('tokens');
  };

  return (
    <div className="w-full h-screen bg-gray-950 text-gray-100 flex flex-col overflow-hidden font-mono text-xs">

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
          OWASP Web Security Inspector
        </h1>
      </header>

      {/* ── Host-access prompt (Firefox) ───────────────────────────────── */}
      {hasHostAccess === false && (
        <div className="flex items-center gap-2 px-4 py-2 bg-amber-950/40 border-b border-amber-800/50 shrink-0">
          <span className="flex-1 text-[11px] text-amber-300">
            Grant access to page data so the inspector can read headers, cookies, and storage.
          </span>
          <button
            onClick={() => { void requestHostAccess(); }}
            className="px-2 py-1 text-[11px] font-medium text-white bg-amber-700 hover:bg-amber-600 rounded transition-colors shrink-0"
          >
            Grant site access
          </button>
        </div>
      )}

      {/* ── Tab bar ────────────────────────────────────────────────────── */}
      <nav className="flex border-b border-gray-800 bg-gray-900/40 shrink-0 overflow-x-auto">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={[
              'px-5 py-2.5 text-[11px] font-medium tracking-wide transition-all duration-150 border-b-2 -mb-px select-none whitespace-nowrap',
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
        {active === 'assessment' && <AssessmentTab />}
        {active === 'cookies'  && <CookieTab onSendToTokens={sendToTokens} />}
        {active === 'tokens'   && <TokensTab initialToken={pendingToken} onConsumeToken={() => setPendingToken(null)} />}
        {active === 'response' && <CurrentHeadersTab />}
      </main>

    </div>
  );
};
