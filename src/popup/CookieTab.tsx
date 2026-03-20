import React, { useCallback, useEffect, useState } from 'react';

// ── Types ──────────────────────────────────────────────────────────────────────
type SameSite = chrome.cookies.SameSiteStatus;

interface Draft {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSite;
  expirationDate: number | undefined;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Builds a URL for chrome.cookies APIs from cookie attributes. */
function cookieUrl(domain: string, path: string, secure: boolean): string {
  const host = domain.replace(/^\.+/, '');
  return `${secure ? 'https' : 'http'}://${host}${path || '/'}`;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function cookieId(c: chrome.cookies.Cookie): string {
  return `${c.name}|${c.domain}|${c.path}`;
}

function toDraft(c: chrome.cookies.Cookie): Draft {
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

function newDraft(domain: string): Draft {
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

function unixToLocalInput(unix: number | undefined): string {
  if (!unix) return '';
  return new Date(unix * 1000).toISOString().slice(0, 16);
}

function localInputToUnix(s: string): number | undefined {
  if (!s) return undefined;
  const t = new Date(s).getTime();
  return isNaN(t) ? undefined : Math.floor(t / 1000);
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

// ── Form primitives ────────────────────────────────────────────────────────────
const Field: React.FC<{
  label: string;
  required?: boolean;
  children: React.ReactNode;
}> = ({ label, required, children }) => (
  <div className="flex flex-col gap-1">
    <label className="text-[10px] text-gray-500 uppercase tracking-wider font-medium select-none">
      {label}
      {required && <span className="text-red-500 ml-0.5">*</span>}
    </label>
    {children}
  </div>
);

const TextInput: React.FC<{
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
}> = ({ value, onChange, placeholder, mono }) => (
  <input
    type="text"
    value={value}
    onChange={e => onChange(e.target.value)}
    placeholder={placeholder}
    className={[
      'w-full px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded',
      'text-gray-300 placeholder-gray-600',
      'focus:outline-none focus:border-blue-600 transition-colors',
      mono ? 'font-mono' : '',
    ].join(' ')}
  />
);

const Toggle: React.FC<{
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  hint?: string;
}> = ({ label, checked, onChange, hint }) => (
  <label className="flex items-center gap-2 cursor-pointer group" title={hint}>
    <input
      type="checkbox"
      checked={checked}
      onChange={e => onChange(e.target.checked)}
      className="sr-only"
    />
    <div
      className={[
        'relative flex h-4 w-7 items-center rounded-full transition-colors duration-200 shrink-0',
        checked ? 'bg-blue-600' : 'bg-gray-700',
      ].join(' ')}
    >
      <span
        className={[
          'absolute h-3 w-3 rounded-full bg-white shadow transition-transform duration-200',
          checked ? 'translate-x-3.5' : 'translate-x-0.5',
        ].join(' ')}
      />
    </div>
    <span className="text-[11px] text-gray-400 group-hover:text-gray-300 transition-colors select-none">
      {label}
    </span>
  </label>
);

// ── CookieTab ──────────────────────────────────────────────────────────────────
export const CookieTab: React.FC = () => {
  const [cookies, setCookies]     = useState<chrome.cookies.Cookie[]>([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [tabUrl, setTabUrl]       = useState('');
  const [tabDomain, setTabDomain] = useState('');
  const [filter, setFilter]       = useState('');
  const [sortAsc, setSortAsc]     = useState(true);

  const [draft, setDraft]                   = useState<Draft | null>(null);
  const [original, setOriginal]             = useState<chrome.cookies.Cookie | null>(null);
  const [saveErr, setSaveErr]               = useState<string | null>(null);
  const [saving, setSaving]                 = useState(false);
  const [confirmDelete, setConfirmDelete]   = useState<chrome.cookies.Cookie | null>(null);

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
      await chrome.cookies.remove({ url: cookieUrl(c.domain, c.path, c.secure), name: c.name });
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
    setSaveErr(null);
  };

  const closeEdit = () => {
    setDraft(null);
    setOriginal(null);
    setSaveErr(null);
  };

  const patch = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    setDraft(prev => (prev ? { ...prev, [key]: value } : null));
  };

  const handleSave = async () => {
    if (!draft) return;
    if (!draft.name.trim()) { setSaveErr('Cookie name is required.'); return; }
    if (draft.sameSite === 'no_restriction' && !draft.secure) {
      setSaveErr('SameSite=None requires the Secure flag to be enabled.');
      return;
    }
    setSaving(true);
    setSaveErr(null);
    try {
      // If identity fields changed on an existing cookie, remove the old one first
      if (
        original &&
        (original.name !== draft.name || original.domain !== draft.domain || original.path !== draft.path)
      ) {
        await chrome.cookies.remove({
          url:  cookieUrl(original.domain, original.path, original.secure),
          name: original.name,
        });
      }

      const effectiveDomain = draft.domain || tabDomain;
      await chrome.cookies.set({
        url:      cookieUrl(effectiveDomain, draft.path, draft.secure),
        name:     draft.name,
        value:    draft.value,
        domain:   draft.domain || undefined,
        path:     draft.path || '/',
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
            className="w-full pl-6 pr-2 py-1.5 text-[11px] bg-gray-900 border border-gray-700 rounded text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
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
          onClick={() => { void load(); }}
          title="Refresh"
          className="p-1.5 rounded text-gray-500 hover:text-blue-400 hover:bg-gray-800 transition-colors"
        >
          <IconRefresh className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-blue-400' : ''}`} />
        </button>
      </div>

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

        {!loading && !error && tabUrl && visible.length === 0 && (
          <div className="flex items-center justify-center h-20 text-gray-600 text-[11px] text-center px-6">
            {filter ? 'No cookies match the filter.' : 'No cookies found for this page.'}
          </div>
        )}

        {!error && tabUrl && visible.length > 0 && (
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
              {visible.map(c => {
                const id = cookieId(c);
                const isConfirm = confirmDelete && cookieId(confirmDelete) === id;

                return (
                  <tr
                    key={id}
                    className="border-b border-gray-800/50 hover:bg-gray-900/50 group text-[11px]"
                  >
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
                      <div className="flex items-center justify-center gap-0.5 flex-wrap">
                        {c.secure && (
                          <span
                            title="Secure (HTTPS only)"
                            className="inline-block text-[9px] font-bold px-1 py-px rounded bg-emerald-900/40 text-emerald-400 border border-emerald-800/50 leading-tight"
                          >
                            S
                          </span>
                        )}
                        {c.httpOnly && (
                          <span
                            title="HttpOnly (not accessible via JavaScript)"
                            className="inline-block text-[9px] font-bold px-1 py-px rounded bg-amber-900/40 text-amber-400 border border-amber-800/50 leading-tight"
                          >
                            H
                          </span>
                        )}
                        {!c.expirationDate && (
                          <span
                            title="Session cookie (expires when browser closes)"
                            className="inline-block text-[9px] font-bold px-1 py-px rounded bg-purple-900/40 text-purple-400 border border-purple-800/50 leading-tight"
                          >
                            Ss
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="px-2 py-1.5 text-right">
                      {isConfirm ? (
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => void handleDelete(c)}
                            title="Confirm delete"
                            className="text-[10px] text-red-400 hover:text-red-300 font-semibold transition-colors"
                          >
                            ✓
                          </button>
                          <button
                            onClick={() => setConfirmDelete(null)}
                            title="Cancel"
                            className="text-[10px] text-gray-600 hover:text-gray-400 transition-colors"
                          >
                            ✕
                          </button>
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => openEdit(c)}
                            title="Edit cookie"
                            className="p-1 rounded text-gray-600 hover:text-blue-400 hover:bg-gray-800 transition-colors"
                          >
                            <IconPencil className="w-3 h-3" />
                          </button>
                          <button
                            onClick={() => setConfirmDelete(c)}
                            title="Delete cookie"
                            className="p-1 rounded text-gray-600 hover:text-red-400 hover:bg-gray-800 transition-colors"
                          >
                            <IconTrash className="w-3 h-3" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Edit / Add sheet ─────────────────────────────────────────────────── */}
      {draft && (
        <div className="absolute inset-0 z-50 flex flex-col justify-end">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/70"
            onClick={closeEdit}
          />

          {/* Bottom sheet */}
          <div className="relative bg-gray-900 border-t border-gray-700 rounded-t-xl shadow-2xl overflow-y-auto max-h-[92%]">

            {/* Sheet header */}
            <div className="flex items-center justify-between px-4 pt-4 pb-3 border-b border-gray-800 shrink-0">
              <h2 className="text-xs font-semibold text-gray-200">
                {original ? `Edit — ${truncate(original.name, 40)}` : 'New Cookie'}
              </h2>
              <button
                onClick={closeEdit}
                className="p-1 rounded text-gray-500 hover:text-gray-300 hover:bg-gray-800 transition-colors"
              >
                <IconX className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="px-4 py-3 space-y-3">

              {/* Name + Value */}
              <div className="grid grid-cols-2 gap-3">
                <Field label="Name" required>
                  <TextInput
                    value={draft.name}
                    onChange={v => patch('name', v)}
                    placeholder="cookie_name"
                    mono
                  />
                </Field>
                <Field label="Value">
                  <TextInput
                    value={draft.value}
                    onChange={v => patch('value', v)}
                    placeholder="cookie_value"
                    mono
                  />
                </Field>
              </div>

              {/* Domain + Path */}
              <div className="grid grid-cols-2 gap-3">
                <Field label="Domain">
                  <TextInput
                    value={draft.domain}
                    onChange={v => patch('domain', v)}
                    placeholder=".example.com"
                    mono
                  />
                </Field>
                <Field label="Path">
                  <TextInput
                    value={draft.path}
                    onChange={v => patch('path', v || '/')}
                    placeholder="/"
                    mono
                  />
                </Field>
              </div>

              {/* SameSite + Expires */}
              <div className="grid grid-cols-2 gap-3">
                <Field label="SameSite">
                  <select
                    value={draft.sameSite}
                    onChange={e => patch('sameSite', e.target.value as SameSite)}
                    className="w-full px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded text-gray-300 focus:outline-none focus:border-blue-600 transition-colors"
                  >
                    <option value="unspecified">Unspecified</option>
                    <option value="lax">Lax</option>
                    <option value="strict">Strict</option>
                    <option value="no_restriction">None (no restriction)</option>
                  </select>
                </Field>
                <Field label="Expires (session if empty)">
                  <input
                    type="datetime-local"
                    value={unixToLocalInput(draft.expirationDate)}
                    onChange={e => patch('expirationDate', localInputToUnix(e.target.value))}
                    className="w-full px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded text-gray-300 focus:outline-none focus:border-blue-600 transition-colors"
                  />
                </Field>
              </div>

              {/* Flags */}
              <div className="flex items-center gap-6 pt-1">
                <Toggle
                  label="Secure"
                  checked={draft.secure}
                  onChange={v => patch('secure', v)}
                  hint="Transmit over HTTPS only"
                />
                <Toggle
                  label="HttpOnly"
                  checked={draft.httpOnly}
                  onChange={v => patch('httpOnly', v)}
                  hint="Not accessible via document.cookie"
                />
              </div>

              {/* Save error */}
              {saveErr && (
                <p className="text-[11px] text-red-400 bg-red-900/20 border border-red-800/40 rounded px-3 py-2">
                  {saveErr}
                </p>
              )}

              {/* Actions */}
              <div className="flex items-center justify-end gap-2 pt-1 pb-1">
                <button
                  onClick={closeEdit}
                  className="px-3 py-1.5 text-[11px] text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => { void handleSave(); }}
                  disabled={saving}
                  className="px-4 py-1.5 text-[11px] font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors"
                >
                  {saving ? 'Saving…' : (original ? 'Update' : 'Create')}
                </button>
              </div>

            </div>
          </div>
        </div>
      )}

    </div>
  );
};
