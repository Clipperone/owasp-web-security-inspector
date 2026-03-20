import React, { createContext, useContext, useEffect, useState } from 'react';

// ── Types ──────────────────────────────────────────────────────────────────────

export type ScopeMode = 'global' | 'domain';

export interface ScopeContextValue {
  /** Current scope mode — "global" applies rules to all URLs, "domain" restricts to activeDomain. */
  mode: ScopeMode;
  setMode: (mode: ScopeMode) => void;
  /** Hostname of the currently active tab (e.g. "github.com"). Empty string if unavailable. */
  activeDomain: string;
  /** True while the tab hostname is being resolved. */
  loading: boolean;
}

// ── Context ────────────────────────────────────────────────────────────────────

const ScopeContext = createContext<ScopeContextValue>({
  mode:         'global',
  setMode:      () => undefined,
  activeDomain: '',
  loading:      true,
});

// ── Provider ───────────────────────────────────────────────────────────────────

export const ScopeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setMode]               = useState<ScopeMode>('global');
  const [activeDomain, setActiveDomain] = useState('');
  const [loading, setLoading]         = useState(true);

  useEffect(() => {
    chrome.tabs
      .query({ active: true, currentWindow: true })
      .then(([tab]) => {
        try {
          if (tab?.url) {
            setActiveDomain(new URL(tab.url).hostname);
          }
        } catch {
          // non-URL tabs (e.g. chrome://) — leave activeDomain as ''
        }
      })
      .catch(() => { /* silent */ })
      .finally(() => setLoading(false));
  }, []);

  return (
    <ScopeContext.Provider value={{ mode, setMode, activeDomain, loading }}>
      {children}
    </ScopeContext.Provider>
  );
};

// ── Hook ───────────────────────────────────────────────────────────────────────

export function useScope(): ScopeContextValue {
  return useContext(ScopeContext);
}
