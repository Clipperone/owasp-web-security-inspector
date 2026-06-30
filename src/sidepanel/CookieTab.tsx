import React, { useCallback, useEffect, useRef, useState } from 'react';
import { cookieUrl, cookieId } from '../utils/cookieUtils';
import { exportToCurl, exportToNetscape } from '../utils/exporter';
import { isJwt } from '../utils/jwtUtils';
import { CookieEditorForm, type CookieDraft } from './CookieEditorForm';
import { useDismissOnOutsideClick } from './useDismissOnOutsideClick';

// ── Types ──────────────────────────────────────────────────────────────────────

// ── Helpers ────────────────────────────────────────────────────────────────────

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function toDraft(c: chrome.cookies.Cookie): CookieDraft {
  return {
    name:           c.name,
    value:          c.value,
    domain:         c.domain,
    path:           c.path,
    secure:         c.secure,
    httpOnly:       c.httpOnly,
    sameSite:       c.sameSite,
    expirationDate: c.expirationDate,
  };
}

function newDraft(domain: string): CookieDraft {
  return {
    name:           '',
    value:          '',
    domain,
    path:           '/',
    secure:         false,
    httpOnly:       false,
    sameSite:       'unspecified',
    expirationDate: undefined,
  };
}

function isPartitionedCookie(cookie: chrome.cookies.Cookie | null): boolean {
  const candidate = cookie as (chrome.cookies.Cookie & { partitionKey?: unknown }) | null;
  return Boolean(candidate && candidate.partitionKey != null);
}

function getCookieValidationError(
  draft: CookieDraft,
  original: chrome.cookies.Cookie | null,
  tabDomain: string,
): string | null {
  const name = draft.name.trim();
  const domain = draft.domain.trim();
  const path = draft.path.trim() || '/';
  const preservesHostOnlyDomain = Boolean(original?.hostOnly && domain === original.domain);
  const omitDomainAttribute = !domain || preservesHostOnlyDomain;
  const effectiveDomain = domain || tabDomain;

  if (!name) return 'Cookie name is required.';
  if (!effectiveDomain) return 'Cookie domain is required.';
  if (draft.sameSite === 'no_restriction' && !draft.secure) {
    return 'SameSite=None requires the Secure flag to be enabled.';
  }
  if (name.startsWith('__Secure-') && !draft.secure) {
    return '__Secure- cookies must keep the Secure flag enabled.';
  }
  if (name.startsWith('__Host-')) {
    if (!draft.secure) return '__Host- cookies must keep the Secure flag enabled.';
    if (path !== '/') return '__Host- cookies must use the root path /.';
    if (!omitDomainAttribute) {
      return '__Host- cookies cannot include a Domain attribute. Clear the domain field to keep them host-only.';
    }
  }
  if (isPartitionedCookie(original) && !draft.secure) {
    return 'Partitioned cookies must keep the Secure flag enabled.';
  }

  return null;
}

// ── SVG icons ──────────────────────────────────────────────────────────────────
const IconRefresh: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
  </svg>
);

const IconPlus: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
  </svg>
);

const IconPencil: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10" />
  </svg>
);

const IconTrash: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
  </svg>
);

const IconSearch: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
  </svg>
);

const IconX: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
  </svg>
);

// ── CookieTab ──────────────────────────────────────────────────────────────────
export const CookieTab: React.FC<{
  onSendToTokens?: (value: string) => void;
}> = ({ onSendToTokens }) => {
  const [cookies, setCookies]     = useState<chrome.cookies.Cookie[]>([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [tabUrl, setTabUrl]       = useState('');
  const [tabDomain, setTabDomain] = useState('');
  const [filter, setFilter]       = useState('');
  const [sortAsc, setSortAsc]     = useState(true);

  const [draft, setDraft]                   = useState<CookieDraft | null>(null);
  const [original, setOriginal]             = useState<chrome.cookies.Cookie | null>(null);
  const [saveErr, setSaveErr]               = useState<string | null>(null);
  const [saving, setSaving]                 = useState(false);
  const [confirmDelete, setConfirmDelete]   = useState<chrome.cookies.Cookie | null>(null);
  const [editingId, setEditingId]           = useState<string | null>(null);
  const [exportOpen, setExportOpen]         = useState(false);
  const [clipToast, setClipToast]           = useState<string | null>(null);
  const [confirmClearAll, setConfirmClearAll] = useState(false);
  const exportRef                            = useRef<HTMLDivElement>(null);
  const clipTimerRef                         = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Load ─────────────────────────────────────────────────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab?.url ?? '';
      setTabUrl(url);
      if (url) {
        try { setTabDomain(new URL(url).hostname); } catch { setTabDomain(''); }
      } else {
        setTabDomain('');
      }
      const all = url ? await chrome.cookies.getAll({ url }) : [];
      setCookies([...all].sort((a, b) => a.name.localeCompare(b.name)));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load cookies.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const closeExportMenu = useCallback(() => setExportOpen(false), []);
  useDismissOnOutsideClick(exportRef, closeExportMenu, exportOpen);

  // ── Derived list ──────────────────────────────────────────────────────────────
  const visible = [...cookies]
    .filter(c => {
      if (!filter) return true;
      const q = filter.toLowerCase();
      return (
        c.name.toLowerCase().includes(q) ||
        c.value.toLowerCase().includes(q) ||
        c.domain.toLowerCase().includes(q)
      );
    })
    .sort((a, b) => {
      const cmp = a.name.localeCompare(b.name);
      return sortAsc ? cmp : -cmp;
    });

  // ── Delete ────────────────────────────────────────────────────────────────────
  const handleDelete = async (c: chrome.cookies.Cookie) => {
    try {
      await chrome.cookies.remove({ url: cookieUrl(c.domain, c.path, c.secure, tabUrl), name: c.name });
    } catch {
      // silent
    } finally {
      setConfirmDelete(null);
      void load();
    }
  };

  // ── Edit / Save ───────────────────────────────────────────────────────────────
  const openEdit = (c: chrome.cookies.Cookie | null) => {
    setOriginal(c);
    setDraft(c ? toDraft(c) : newDraft(tabDomain));
    setEditingId(c ? cookieId(c) : '__new__');
    setSaveErr(null);
  };

  const closeEdit = () => {
    setDraft(null);
    setOriginal(null);
    setEditingId(null);
    setSaveErr(null);
  };

  const patch = <K extends keyof CookieDraft>(key: K, value: CookieDraft[K]) => {
    setDraft(prev => (prev ? { ...prev, [key]: value } : null));
  };

  const validationErr = draft ? getCookieValidationError(draft, original, tabDomain) : null;
  const formError = validationErr ?? saveErr;
  const saveDisabled = saving || Boolean(validationErr);

  const handleSave = async () => {
    if (!draft) return;
    const validationError = getCookieValidationError(draft, original, tabDomain);
    const name = draft.name.trim();
    const domain = draft.domain.trim();
    const path = draft.path.trim() || '/';
    const preservesHostOnlyDomain = Boolean(original?.hostOnly && domain === original.domain);
    const omitDomainAttribute = !domain || preservesHostOnlyDomain;
    const effectiveDomain = domain || tabDomain;

    if (validationError) { setSaveErr(validationError); return; }
    setSaving(true);
    setSaveErr(null);
    try {
      // If identity fields changed on an existing cookie, remove the old one first
      if (
        original &&
        (original.name !== draft.name || original.domain !== draft.domain || original.path !== draft.path)
      ) {
        await chrome.cookies.remove({
          url:  cookieUrl(original.domain, original.path, original.secure, tabUrl),
          name: original.name,
        });
      }

      await chrome.cookies.set({
        url:      cookieUrl(effectiveDomain, path, draft.secure, tabUrl),
        name,
        value:    draft.value,
        domain:   omitDomainAttribute ? undefined : domain,
        path,
        secure:   draft.secure,
        httpOnly: draft.httpOnly,
        sameSite: draft.sameSite,
        ...(draft.expirationDate != null ? { expirationDate: draft.expirationDate } : {}),
      });

      closeEdit();
      await load();
    } catch (e) {
      setSaveErr(e instanceof Error ? e.message : 'Failed to save cookie.');
    } finally {
      setSaving(false);
    }
  };

  // ── Clear all ─────────────────────────────────────────────────────────────────
  const handleClearAll = async () => {
    setConfirmClearAll(false);
    await Promise.allSettled(
      cookies.map(c =>
        chrome.cookies.remove({ url: cookieUrl(c.domain, c.path, c.secure, tabUrl), name: c.name }),
      ),
    );
    void load();
  };

  // ── Export ────────────────────────────────────────────────────────────────────
  const copyAndToast = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      if (clipTimerRef.current) clearTimeout(clipTimerRef.current);
      setClipToast(label);
      clipTimerRef.current = setTimeout(() => setClipToast(null), 2500);
    } catch { /* silent */ }
    setExportOpen(false);
  };

  const handleExportCurl     = () => void copyAndToast(exportToCurl(tabUrl, visible, []), 'Copied as cURL!');
  const handleExportNetscape = () => void copyAndToast(exportToNetscape(visible), 'Copied as cookies.txt!');

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full relative overflow-hidden">

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 bg-gray-900/30 shrink-0">
        <div className="relative flex-1 min-w-0">
          <IconSearch className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-600 pointer-events-none" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by name, value, or domain…"
            className={`w-full pl-6 py-1.5 text-[11px] bg-gray-900 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors ${filter ? 'pr-6' : 'pr-2'}`}
          />
          {filter && (
            <button
              onClick={() => setFilter('')}
              title="Clear filter"
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300 transition-colors"
            >
              <IconX className="w-3 h-3" />
            </button>
          )}
        </div>
        <span className="text-[10px] text-gray-600 tabular-nums shrink-0 select-none">
          {visible.length}/{cookies.length}
        </span>
        <button
          onClick={() => openEdit(null)}
          title="Add new cookie"
          className="p-1.5 rounded text-gray-500 hover:text-emerald-400 hover:bg-gray-800 transition-colors"
        >
          <IconPlus className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => setConfirmClearAll(true)}
          disabled={cookies.length === 0}
          title="Clear all cookies for this site"
          className="p-1.5 rounded text-gray-500 hover:text-red-400 hover:bg-gray-800 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <IconTrash className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => { void load(); }}
          title="Refresh"
          className="p-1.5 rounded text-gray-500 hover:text-blue-400 hover:bg-gray-800 transition-colors"
        >
          <IconRefresh className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
        </button>

        {/* Export dropdown */}
        <div ref={exportRef} className="relative shrink-0">
          <button
            onClick={() => setExportOpen(p => !p)}
            disabled={visible.length === 0}
            title="Export cookies"
            className="px-2 py-1 text-[11px] text-gray-500 hover:text-blue-400 hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed rounded transition-colors"
          >
            Export
          </button>
          {exportOpen && (
            <div className="absolute right-0 top-full mt-1 w-48 bg-gray-900 border border-gray-700 rounded shadow-xl z-50 overflow-hidden">
              <button
                onClick={handleExportCurl}
                className="w-full text-left px-3 py-2 text-[11px] text-gray-400 hover:text-gray-200 hover:bg-gray-800/60 transition-colors"
              >
                Copy as cURL
              </button>
              <button
                onClick={handleExportNetscape}
                className="w-full text-left px-3 py-2 text-[11px] text-gray-400 hover:text-gray-200 hover:bg-gray-800/60 transition-colors"
              >
                Copy as Netscape cookies.txt
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Clear-all confirmation banner */}
      {confirmClearAll && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-950/40 border-b border-red-800/50 shrink-0">
          <span className="flex-1 text-[11px] text-red-300">
            Delete all <span className="font-semibold">{cookies.length}</span> cookie{cookies.length !== 1 ? 's' : ''} for <span className="font-semibold">{tabDomain}</span>?
          </span>
          <button
            onClick={() => setConfirmClearAll(false)}
            className="px-2 py-1 text-[11px] text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded transition-colors"
          >Cancel</button>
          <button
            onClick={() => { void handleClearAll(); }}
            className="px-2 py-1 text-[11px] font-medium text-white bg-red-700 hover:bg-red-600 rounded transition-colors"
          >Delete all</button>
        </div>
      )}

      {/* Clipboard toast */}
      {clipToast && (
        <div className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-900/30 border-b border-emerald-800/40 shrink-0">
          <span className="text-[11px] text-emerald-400">✓ {clipToast}</span>
        </div>
      )}

      {/* Content area */}
      <div className="flex-1 overflow-y-auto">
        {!loading && error && (
          <div className="flex items-center justify-center h-20 text-red-400 text-[11px] px-4 text-center">
            {error}
          </div>
        )}

        {!loading && !error && !tabUrl && (
          <div className="flex items-center justify-center h-20 text-gray-600 text-[11px] text-center px-6">
            Navigate to a webpage to inspect its cookies.
          </div>
        )}

        {!loading && !error && tabUrl && visible.length === 0 && editingId !== '__new__' && (
          <div className="flex items-center justify-center h-20 text-gray-600 text-[11px] text-center px-6">
            {filter ? 'No cookies match the filter.' : 'No cookies found for this page.'}
          </div>
        )}

        {!error && tabUrl && (visible.length > 0 || editingId === '__new__') && (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 z-10 bg-gray-900 border-b border-gray-800">
              <tr className="text-gray-600 text-[10px] uppercase tracking-wider">
                <th
                  className="text-left px-3 py-2 font-medium cursor-pointer select-none hover:text-gray-400 transition-colors w-[30%]"
                  onClick={() => setSortAsc(p => !p)}
                >
                  Name&nbsp;{sortAsc ? '↑' : '↓'}
                </th>
                <th className="text-left px-3 py-2 font-medium w-[32%]">Value</th>
                <th className="text-left px-3 py-2 font-medium w-[22%]">Domain</th>
                <th className="text-center px-3 py-2 font-medium w-[9%]">Flags</th>
                <th className="text-right px-2 py-2 font-medium w-[7%]"></th>
              </tr>
            </thead>
            <tbody>
              {/* ── Inline form for new cookie (inserted at top) ── */}
              {editingId === '__new__' && draft && (
                <tr>
                  <td colSpan={5} className="p-0 border-b border-blue-900/50">
                    <div className="border-l-2 border-blue-600/60 bg-gray-950/60 px-4 py-3">
                      <CookieEditorForm
                        title="New Cookie"
                        draft={draft}
                        onPatch={patch}
                        formError={formError}
                        saveDisabled={saveDisabled}
                        saving={saving}
                        submitLabel="Create"
                        onCancel={closeEdit}
                        onSave={() => { void handleSave(); }}
                      />
                    </div>
                  </td>
                </tr>
              )}

              {visible.map(c => {
                const id = cookieId(c);
                const isEditing = editingId === id;
                const isConfirm = confirmDelete && cookieId(confirmDelete) === id;

                return (
                  <React.Fragment key={id}>
                    <tr className={['border-b border-gray-800/50 group text-[11px]', isEditing ? 'bg-blue-950/20' : 'hover:bg-gray-900/50'].join(' ')}>
                      {/* Name */}
                      <td className="px-3 py-1.5 font-mono text-gray-200 max-w-0">
                        <div className="truncate" title={c.name}>
                          {c.name || <span className="text-gray-700 italic text-[10px]">(empty)</span>}
                        </div>
                      </td>

                      {/* Value */}
                      <td className="px-3 py-1.5 font-mono text-gray-500 max-w-0">
                        <div className="truncate" title={c.value}>
                          {c.value ? truncate(c.value, 38) : <span className="text-gray-700 text-[10px]">(empty)</span>}
                        </div>
                      </td>

                      {/* Domain */}
                      <td className="px-3 py-1.5 text-gray-500 max-w-0">
                        <div className="truncate" title={c.domain}>{c.domain}</div>
                      </td>

                      {/* Flags */}
                      <td className="px-3 py-1.5 text-center">
                        <div className="flex items-center justify-center gap-0.5 flex-nowrap">
                          {c.secure && (
                            <span title="Secure (HTTPS only)" className="inline-block text-[9px] font-bold px-1 py-px rounded bg-emerald-900/40 text-emerald-400 border border-emerald-800/50 leading-tight">S</span>
                          )}
                          {c.httpOnly && (
                            <span title="HttpOnly (not accessible via JavaScript)" className="inline-block text-[9px] font-bold px-1 py-px rounded bg-amber-900/40 text-amber-400 border border-amber-800/50 leading-tight">H</span>
                          )}
                          {!c.expirationDate && (
                            <span title="Session cookie (expires when browser closes)" className="inline-block text-[9px] font-bold px-1 py-px rounded bg-purple-900/40 text-purple-400 border border-purple-800/50 leading-tight">Ss</span>
                          )}
                          {isJwt(c.value) && (
                            <button
                              title="Open in Tokens tab"
                              onClick={e => { e.stopPropagation(); onSendToTokens?.(c.value); }}
                              className="inline-block text-[9px] font-bold px-1 py-px rounded bg-sky-900/40 text-sky-400 border border-sky-800/50 leading-tight hover:bg-sky-800/60 hover:text-sky-300 transition-colors cursor-pointer"
                            >
                              JWT
                            </button>
                          )}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="px-2 py-1.5 text-right">
                        {isConfirm ? (
                          <div className="flex items-center justify-end gap-1.5">
                            <button onClick={() => void handleDelete(c)} title="Confirm delete" className="text-[10px] text-red-400 hover:text-red-300 font-semibold transition-colors">✓</button>
                            <button onClick={() => setConfirmDelete(null)} title="Cancel" className="text-[10px] text-gray-600 hover:text-gray-400 transition-colors">✕</button>
                          </div>
                        ) : (
                          <div className={['flex items-center justify-end gap-0.5 transition-opacity', isEditing ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'].join(' ')}>
                            <button
                              onClick={() => isEditing ? closeEdit() : openEdit(c)}
                              title={isEditing ? 'Close editor' : 'Edit cookie'}
                              className={['p-1 rounded hover:bg-gray-800 transition-colors', isEditing ? 'text-blue-400' : 'text-gray-600 hover:text-blue-400'].join(' ')}
                            >
                              <IconPencil className="w-3 h-3" />
                            </button>
                            <button onClick={() => setConfirmDelete(c)} title="Delete cookie" className="p-1 rounded text-gray-600 hover:text-red-400 hover:bg-gray-800 transition-colors">
                              <IconTrash className="w-3 h-3" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>

                    {/* ── Inline edit accordion ── */}
                    {isEditing && draft && (
                      <tr>
                        <td colSpan={5} className="p-0 border-b border-blue-900/50">
                          <div className="border-l-2 border-blue-600/60 bg-gray-950/60 px-4 py-3">
                            <CookieEditorForm
                              draft={draft}
                              onPatch={patch}
                              formError={formError}
                              saveDisabled={saveDisabled}
                              saving={saving}
                              submitLabel="Update"
                              onCancel={closeEdit}
                              onSave={() => { void handleSave(); }}
                            />
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
};
