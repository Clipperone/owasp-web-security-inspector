import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { HeaderModification, HeaderOperation, HeaderRule, HeaderRuleDraft } from '../types';
import { validateHeaderModification, defaultRuleName } from '../utils/headerUtils';
import { exportToCurl } from '../utils/exporter';
import { HeaderRuleRow } from './HeaderRuleRow';
import { useDismissOnOutsideClick } from './useDismissOnOutsideClick';

// Types

interface FormState {
  name:      string;
  urlFilter: string;
  header:    string;
  value:     string;
  operation: HeaderOperation;
  target:    'request' | 'response';
  scopeMode: 'global' | 'domain';
  scopeDomain: string;
}

const EMPTY_FORM: FormState = {
  name:      '',
  urlFilter: '*://*/*',
  header:    '',
  value:     '',
  operation: 'set',
  target:    'request',
  scopeMode: 'global',
  scopeDomain: '',
};

function createFormState(activeDomain: string): FormState {
  return {
    ...EMPTY_FORM,
    scopeDomain: activeDomain,
  };
}

function toFormState(rule: HeaderRule): FormState {
  const requestMod = rule.requestHeaders?.[0];
  const responseMod = rule.responseHeaders?.[0];
  const mod = requestMod ?? responseMod;

  return {
    name: rule.name,
    urlFilter: rule.urlFilter,
    header: mod?.header ?? '',
    value: mod?.value ?? '',
    operation: mod?.operation ?? 'set',
    target: requestMod ? 'request' : 'response',
    scopeMode: rule.domainScope ? 'domain' : 'global',
    scopeDomain: rule.domainScope ?? '',
  };
}

// Quick templates

interface Template {
  label:     string;
  urlFilter?: string;
  header:    string;
  value:     string;
  operation: HeaderOperation;
  target:    'request' | 'response';
}

const TEMPLATES: Template[] = [
  {
    label:     'Bearer Token',
    header:    'Authorization',
    value:     'Bearer YOUR_TOKEN_HERE',
    operation: 'set',
    target:    'request',
  },
  {
    label:     'CORS Bypass',
    urlFilter: '*://*/*',
    header:    'Access-Control-Allow-Origin',
    value:     '*',
    operation: 'set',
    target:    'response',
  },
  {
    label:     'Debug Header',
    header:    'X-Debug',
    value:     'true',
    operation: 'set',
    target:    'request',
  },
];

// Helpers and icons

const IconPlus: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
  </svg>
);

// Inline select with consistent dark styling
const Select: React.FC<{
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}> = ({ value, onChange, options, className }) => (
  <select
    value={value}
    onChange={e => onChange(e.target.value)}
    className={[
      'px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded',
      'text-gray-300 focus:outline-none focus:border-blue-600 transition-colors',
      className ?? '',
    ].join(' ')}
  >
    {options.map(o => (
      <option key={o.value} value={o.value}>{o.label}</option>
    ))}
  </select>
);

const TextInput: React.FC<{
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}> = ({ value, onChange, placeholder, className }) => (
  <input
    type="text"
    value={value}
    onChange={e => onChange(e.target.value)}
    placeholder={placeholder}
    className={[
      'px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded font-mono',
      'text-gray-300 placeholder-gray-600',
      'focus:outline-none focus:border-blue-600 transition-colors',
      className ?? '',
    ].join(' ')}
  />
);

// HeadersTab

export const HeadersTab: React.FC = () => {
  const [rules, setRules]   = useState<HeaderRule[]>([]);
  const [form, setForm]     = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [toast, setToast]   = useState<{ ok: boolean; msg: string } | null>(null);
  const toastTimer           = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [editingRuleId, setEditingRuleId] = useState<number | null>(null);

  // Export dropdown
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef                    = useRef<HTMLDivElement>(null);

  // Template dropdown
  const [tplOpen, setTplOpen]  = useState(false);
  const tplRef                  = useRef<HTMLDivElement>(null);
  const closeExportMenu = useCallback(() => setExportOpen(false), []);
  const closeTemplateMenu = useCallback(() => setTplOpen(false), []);

  // Active tab info
  const [tabUrl, setTabUrl] = useState('');
  const [activeDomain, setActiveDomain] = useState('');

  // Drag state
  const dragIndex = useRef<number | null>(null);
  const [dragging, setDragging] = useState<number | null>(null);

  // Load
  const load = useCallback(async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_HEADER_RULES' });
      if (res?.success) setRules(res.data as HeaderRule[]);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // Fetch active tab URL and domain for the live-preview badge and scoped-rule helper.
  useEffect(() => {
    void (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const url = tab?.url ?? '';
        setTabUrl(url);

        try {
          setActiveDomain(url ? new URL(url).hostname : '');
        } catch {
          setActiveDomain('');
        }
      } catch { /* silent */ }
    })();
  }, []);

  useEffect(() => {
    if (editingRuleId !== null || !activeDomain) return;

    setForm(prev => {
      if (prev.scopeDomain.trim()) return prev;
      return { ...prev, scopeDomain: activeDomain };
    });
  }, [activeDomain, editingRuleId]);

  useDismissOnOutsideClick(exportRef, closeExportMenu, exportOpen);
  useDismissOnOutsideClick(tplRef, closeTemplateMenu, tplOpen);

  // Live preview badge
  const matchingCount = (() => {
    if (!tabUrl) return 0;
    let hostname = '';
    try { hostname = new URL(tabUrl).hostname; } catch { return 0; }
    return rules.filter(r => {
      if (!r.enabled) return false;
      if (r.domainScope && r.domainScope !== hostname) return false;
      // Simple wildcard check: does the URL pattern plausibly match?
      const pattern = r.urlFilter.replace(/\*/g, '.*').replace(/\?/g, '.');
      try { return new RegExp(pattern).test(tabUrl); } catch { return true; }
    }).length;
  })();

  // Toast helper
  const showToast = (ok: boolean, msg: string) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ ok, msg });
    toastTimer.current = setTimeout(() => setToast(null), 2800);
  };

  // Form helpers
  const patchForm = <K extends keyof FormState>(key: K, val: FormState[K]) =>
    setForm(prev => ({ ...prev, [key]: val }));

  const isValueRequired = form.operation !== 'remove';

  const applyTemplate = (tpl: Template) => {
    setForm(prev => ({
      ...prev,
      urlFilter: tpl.urlFilter ?? prev.urlFilter,
      header:    tpl.header,
      value:     tpl.value,
      operation: tpl.operation,
      target:    tpl.target,
    }));
    setTplOpen(false);
  };

  // Save
  const handleSave = async () => {
    const validationErr = validateHeaderModification(form.header, form.operation, form.value);
    if (validationErr) { showToast(false, validationErr); return; }

    const effectiveScopeDomain = form.scopeDomain.trim() || activeDomain;
    if (form.scopeMode === 'domain' && !effectiveScopeDomain) {
      showToast(false, 'A scoped rule requires a domain.');
      return;
    }

    setSaving(true);
    try {
      const currentRule = editingRuleId
        ? rules.find(r => r.id === editingRuleId) ?? null
        : null;
      const now      = new Date().toISOString();
      const mod: HeaderModification = form.operation === 'remove'
        ? { header: form.header.trim(), operation: 'remove' }
        : { header: form.header.trim(), operation: form.operation, value: form.value.trim() };

      const rulePayload: HeaderRuleDraft = {
        name:            form.name.trim() || defaultRuleName(form.operation, form.header),
        urlFilter:       form.urlFilter.trim() || '*://*/*',
        requestHeaders:  form.target === 'request'  ? [mod] : undefined,
        responseHeaders: form.target === 'response' ? [mod] : undefined,
        domainScope:     form.scopeMode === 'domain' ? effectiveScopeDomain : undefined,
      };

      const res = editingRuleId
        ? await chrome.runtime.sendMessage({
          type: 'UPDATE_HEADER_RULE',
          payload: {
            id: editingRuleId,
            priority: currentRule?.priority ?? 1,
            enabled: currentRule?.enabled ?? true,
            createdAt: currentRule?.createdAt ?? now,
            updatedAt: now,
            ...rulePayload,
          } satisfies HeaderRule,
        })
        : await chrome.runtime.sendMessage({ type: 'ADD_HEADER_RULE', payload: rulePayload });

      if (res?.success) {
        // Background returns the full updated list — set it directly, no extra GET round-trip
        setRules(res.data as HeaderRule[]);
        setEditingRuleId(null);
        setForm(createFormState(activeDomain));
        showToast(true, editingRuleId ? 'Rule updated successfully.' : 'Rule saved successfully.');
      } else {
        showToast(false, res?.error ?? 'Failed to save rule.');
      }
    } catch (e) {
      showToast(false, e instanceof Error ? e.message : 'Unexpected error.');
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (rule: HeaderRule) => {
    setEditingRuleId(rule.id);
    setForm(toFormState(rule));
    setToast(null);
  };

  const handleCancelEdit = () => {
    setEditingRuleId(null);
    setForm(createFormState(activeDomain));
    setToast(null);
  };

  // Toggle
  const handleToggle = async (id: number) => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'TOGGLE_HEADER_RULE', payload: id });
      if (res?.success) setRules(res.data as HeaderRule[]);
    } catch { /* silent */ }
  };

  // ── Delete ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  const handleDelete = async (id: number) => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'DELETE_HEADER_RULE', payload: id });
      if (res?.success) setRules(res.data as HeaderRule[]);
    } catch { /* silent */ }
  };

  // Drag-and-drop reordering
  const handleDragStart = (index: number) => {
    dragIndex.current = index;
    setDragging(index);
  };

  const handleDragOver = (index: number) => {
    if (dragIndex.current === null || dragIndex.current === index) return;
    const next = [...rules];
    const [moved] = next.splice(dragIndex.current, 1);
    next.splice(index, 0, moved);
    dragIndex.current = index;
    setRules(next);
  };

  const handleDrop = () => {
    setDragging(null);
    dragIndex.current = null;
    const orderedIds = rules.map(r => r.id);

    void (async () => {
      try {
        const res = await chrome.runtime.sendMessage({ type: 'REORDER_HEADER_RULES', payload: orderedIds });
        if (res?.success) {
          setRules(res.data as HeaderRule[]);
        }
      } catch {
        // silent
      }
    })();
  };

  // Export
  const handleExportCurl = async () => {
    setExportOpen(false);
    try {
      const url = tabUrl || 'https://example.com';
      await navigator.clipboard.writeText(exportToCurl(url, [], rules));
      showToast(true, 'Copied to clipboard!');
    } catch {
      showToast(false, 'Failed to copy to clipboard.');
    }
  };

  return (
    <div className="flex flex-col h-full overflow-hidden max-w-[600px] mx-auto w-full">

      {/* Add rule form */}
      <div className="border-b border-gray-800 bg-gray-900/30 px-3 py-3 space-y-2 shrink-0">
        {/* Form header with template picker */}
        <div className="flex items-center justify-between mb-1">
          <p className="text-[10px] uppercase tracking-widest text-gray-600 font-medium select-none">
            {editingRuleId ? `Edit rule #${editingRuleId}` : 'New rule'}
          </p>
          <div className="flex items-center gap-2">
            {editingRuleId && (
              <button
                onClick={handleCancelEdit}
                className="px-2 py-1 text-[11px] text-gray-500 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors"
              >
                Cancel
              </button>
            )}
            <div ref={tplRef} className="relative">
              <button
                onClick={() => setTplOpen(p => !p)}
                className="px-2 py-1 text-[11px] text-gray-500 hover:text-blue-400 hover:bg-gray-800 rounded transition-colors"
              >
                Templates ▾
              </button>
              {tplOpen && (
                <div className="absolute right-0 top-full mt-1 w-44 bg-gray-900 border border-gray-700 rounded shadow-xl z-50 overflow-hidden">
                  {TEMPLATES.map(tpl => (
                    <button
                      key={tpl.label}
                      onClick={() => applyTemplate(tpl)}
                      className="w-full text-left px-3 py-2 text-[11px] text-gray-400 hover:text-gray-200 hover:bg-gray-800/60 transition-colors"
                    >
                      {tpl.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Row 1: Name */}
        <TextInput
          value={form.name}
          onChange={v => patchForm('name', v)}
          placeholder="Rule name (optional)"
          className="w-full"
        />

        {/* Row 2: URL filter */}
        <TextInput
          value={form.urlFilter}
          onChange={v => patchForm('urlFilter', v)}
            placeholder="URL filter e.g. *://*.example.com/*"
          className="w-full"
        />

        {/* Row 3: target + operation + header name */}
        <div className="flex gap-2">
          <Select
            value={form.target}
            onChange={v => patchForm('target', v as FormState['target'])}
            options={[
              { value: 'request',  label: 'Request' },
              { value: 'response', label: 'Response' },
            ]}
          />
          <Select
            value={form.operation}
            onChange={v => patchForm('operation', v as HeaderOperation)}
            options={[
              { value: 'set',    label: 'Set' },
              { value: 'append', label: 'Append' },
              { value: 'remove', label: 'Remove' },
            ]}
          />
          <TextInput
            value={form.header}
            onChange={v => patchForm('header', v)}
            placeholder="Header name"
            className="flex-1 min-w-0"
          />
        </div>

        {/* Row 4: value (hidden when operation=remove) */}
        {isValueRequired && (
          <TextInput
            value={form.value}
            onChange={v => patchForm('value', v)}
            placeholder="Header value"
            className="w-full"
          />
        )}

        {/* Row 5: scope */}
        <div className="flex gap-2">
          <Select
            value={form.scopeMode}
            onChange={v => {
              const nextMode = v as FormState['scopeMode'];
              setForm(prev => ({
                ...prev,
                scopeMode: nextMode,
                scopeDomain: nextMode === 'domain' && !prev.scopeDomain.trim()
                  ? activeDomain
                  : prev.scopeDomain,
              }));
            }}
            options={[
              { value: 'global', label: 'Global scope' },
              { value: 'domain', label: 'Scoped domain' },
            ]}
          />
          {form.scopeMode === 'domain' && (
            <TextInput
              value={form.scopeDomain}
              onChange={v => patchForm('scopeDomain', v)}
              placeholder={activeDomain || 'example.com'}
              className="flex-1 min-w-0"
            />
          )}
        </div>

        {/* Row 6: live badge + toast + save button */}
        <div className="flex items-center justify-between gap-2 pt-0.5">
          <div className="flex items-center gap-2 min-w-0">
            {toast ? (
              <p className={`text-[11px] font-medium truncate ${toast.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                {toast.ok ? '✔ ' : '✖ '}{toast.msg}
              </p>
            ) : tabUrl ? (
              <span className={[
                'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border select-none',
                matchingCount > 0
                  ? 'bg-blue-900/30 text-blue-400 border-blue-800/50'
                  : 'bg-gray-800/60 text-gray-600 border-gray-700/50',
              ].join(' ')}>
                <span className={`w-1.5 h-1.5 rounded-full ${matchingCount > 0 ? 'bg-blue-400' : 'bg-gray-600'}`} />
                {matchingCount} rule{matchingCount !== 1 ? 's' : ''} active on this tab
              </span>
            ) : (
              <span />
            )}
          </div>
          <button
            onClick={() => { void handleSave(); }}
            disabled={saving}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors shrink-0"
          >
            <IconPlus className="w-3 h-3" />
            {saving ? 'Saving…' : editingRuleId ? 'Update rule' : 'Add rule'}
          </button>
        </div>
      </div>

      {/* Rule list header */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-gray-800 bg-gray-900/20 shrink-0">
        <span className="text-[10px] text-gray-600 uppercase tracking-widest font-medium select-none">
          {rules.length > 0 ? `Rules (${rules.length})` : 'Rules'}
        </span>
        <div ref={exportRef} className="relative">
          <button
            onClick={() => setExportOpen(p => !p)}
            disabled={rules.length === 0}
            className="px-2 py-1 text-[11px] text-gray-500 hover:text-blue-400 hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed rounded transition-colors"
          >
            Export
          </button>
          {exportOpen && (
            <div className="absolute right-0 top-full mt-1 w-40 bg-gray-900 border border-gray-700 rounded shadow-xl z-50 overflow-hidden">
              <button
                onClick={() => { void handleExportCurl(); }}
                className="w-full text-left px-3 py-2 text-[11px] text-gray-400 hover:text-gray-200 hover:bg-gray-800/60 transition-colors"
              >
                Copy as cURL
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Rule list (drag-sortable) */}
      <div
        className="flex-1 overflow-y-auto"
        onDragEnd={() => { setDragging(null); dragIndex.current = null; }}
      >
        {rules.length === 0 ? (
          <div className="flex items-center justify-center h-20 text-gray-700 text-[11px] text-center px-6 select-none">
            No rules yet. Add one above.
          </div>
        ) : (
          rules.map((r, i) => (
            <HeaderRuleRow
              key={r.id}
              rule={r}
              index={i}
              dragging={dragging}
              editing={editingRuleId === r.id}
              onEdit={handleEdit}
              onToggle={id => { void handleToggle(id); }}
              onDelete={id => { void handleDelete(id); }}
              onDragStart={handleDragStart}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
            />
          ))
        )}
      </div>

    </div>
  );
};


