import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { HeaderModification, HeaderOperation, HeaderRule } from '../types';
import { nextRuleId, saveRule, deleteRule, toggleRule } from '../utils/storageUtils';

// ── Types ──────────────────────────────────────────────────────────────────────

interface FormState {
  name:      string;
  urlFilter: string;
  header:    string;
  value:     string;
  operation: HeaderOperation;
  target:    'request' | 'response';
}

const EMPTY_FORM: FormState = {
  name:      '',
  urlFilter: '*://*/*',
  header:    '',
  value:     '',
  operation: 'set',
  target:    'request',
};

// ── Helpers / icons ────────────────────────────────────────────────────────────

const IconPlus: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
  </svg>
);

const IconTrash: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
  </svg>
);

const IconChevron: React.FC<{ open: boolean }> = ({ open }) => (
  <svg
    className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
    viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
  >
    <path strokeLinecap="round" strokeLinejoin="round" d="m19 9-7 7-7-7" />
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

// ── Rule row ───────────────────────────────────────────────────────────────────

const RuleRow: React.FC<{
  rule: HeaderRule;
  onToggle: (id: number) => void;
  onDelete: (id: number) => void;
}> = ({ rule, onToggle, onDelete }) => {
  const [open, setOpen] = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);

  const mods: HeaderModification[] = [
    ...(rule.requestHeaders  ?? []).map(m => ({ ...m, _target: 'request'  as const })),
    ...(rule.responseHeaders ?? []).map(m => ({ ...m, _target: 'response' as const })),
  ];

  return (
    <div className={`border-b border-gray-800/60 text-[11px] ${rule.enabled ? '' : 'opacity-50'}`}>
      {/* Summary row */}
      <div className="flex items-center gap-2 px-3 py-2 group hover:bg-gray-900/40 transition-colors">
        {/* Toggle */}
        <button
          onClick={() => onToggle(rule.id)}
          title={rule.enabled ? 'Disable rule' : 'Enable rule'}
          className={[
            'relative flex h-4 w-7 items-center rounded-full transition-colors duration-200 shrink-0',
            rule.enabled ? 'bg-blue-600' : 'bg-gray-700',
          ].join(' ')}
        >
          <span className={[
            'absolute h-3 w-3 rounded-full bg-white shadow transition-transform duration-200',
            rule.enabled ? 'translate-x-3.5' : 'translate-x-0.5',
          ].join(' ')} />
        </button>

        {/* Name + filter */}
        <button
          onClick={() => setOpen(p => !p)}
          className="flex-1 min-w-0 flex items-center gap-1.5 text-left"
        >
          <span className="truncate text-gray-300 font-medium">
            {rule.name || <span className="text-gray-600 italic">(unnamed)</span>}
          </span>
          <span className="truncate text-gray-600 text-[10px]">— {rule.urlFilter}</span>
          <IconChevron open={open} />
        </button>

        {/* Delete */}
        {confirmDel ? (
          <div className="flex items-center gap-1.5 shrink-0">
            <button onClick={() => onDelete(rule.id)} className="text-[10px] text-red-400 hover:text-red-300 font-semibold">✓</button>
            <button onClick={() => setConfirmDel(false)} className="text-[10px] text-gray-600 hover:text-gray-400">✕</button>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDel(true)}
            title="Delete rule"
            className="p-1 rounded text-gray-700 hover:text-red-400 hover:bg-gray-800 transition-colors opacity-0 group-hover:opacity-100"
          >
            <IconTrash className="w-3 h-3" />
          </button>
        )}
      </div>

      {/* Expanded modifications */}
      {open && mods.length > 0 && (
        <div className="px-3 pb-2 pt-0 space-y-1">
          {mods.map((m, i) => (
            <div key={i} className="flex items-center gap-1.5 text-[10px]">
              <span className={`px-1.5 py-px rounded font-bold uppercase tracking-wide shrink-0 ${
                (m as HeaderModification & { _target: string })._target === 'request'
                  ? 'bg-blue-900/40 text-blue-400 border border-blue-800/50'
                  : 'bg-purple-900/40 text-purple-400 border border-purple-800/50'
              }`}>
                {(m as HeaderModification & { _target: string })._target === 'request' ? 'REQ' : 'RES'}
              </span>
              <span className={`px-1.5 py-px rounded text-[9px] uppercase tracking-wide shrink-0 ${
                m.operation === 'set'    ? 'bg-emerald-900/30 text-emerald-400' :
                m.operation === 'append' ? 'bg-amber-900/30 text-amber-400' :
                                           'bg-red-900/30 text-red-400'
              }`}>{m.operation}</span>
              <code className="text-gray-400 truncate">{m.header}</code>
              {m.value !== undefined && (
                <>
                  <span className="text-gray-700">→</span>
                  <code className="text-gray-500 truncate">{m.value}</code>
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ── HeadersTab ─────────────────────────────────────────────────────────────────

export const HeadersTab: React.FC = () => {
  const [rules, setRules]   = useState<HeaderRule[]>([]);
  const [form, setForm]     = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [toast, setToast]   = useState<{ ok: boolean; msg: string } | null>(null);
  const toastTimer           = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Load ─────────────────────────────────────────────────────────────────────
  const load = useCallback(async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_HEADER_RULES' });
      if (res?.success) setRules(res.data as HeaderRule[]);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // ── Toast helper ──────────────────────────────────────────────────────────────
  const showToast = (ok: boolean, msg: string) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ ok, msg });
    toastTimer.current = setTimeout(() => setToast(null), 2800);
  };

  // ── Form helpers ──────────────────────────────────────────────────────────────
  const patchForm = <K extends keyof FormState>(key: K, val: FormState[K]) =>
    setForm(prev => ({ ...prev, [key]: val }));

  const isValueRequired = form.operation !== 'remove';

  // ── Save ──────────────────────────────────────────────────────────────────────
  const handleSave = async () => {
    if (!form.header.trim()) { showToast(false, 'Header name is required.'); return; }
    if (isValueRequired && !form.value.trim()) { showToast(false, 'Header value is required.'); return; }

    setSaving(true);
    try {
      const id       = await nextRuleId();
      const now      = new Date().toISOString();
      const mod: HeaderModification = form.operation === 'remove'
        ? { header: form.header.trim(), operation: 'remove' }
        : { header: form.header.trim(), operation: form.operation, value: form.value.trim() };

      const rule: HeaderRule = {
        id,
        priority:        1,
        name:            form.name.trim() || `${form.operation} ${form.header.trim()}`,
        enabled:         true,
        urlFilter:       form.urlFilter.trim() || '*://*/*',
        requestHeaders:  form.target === 'request'  ? [mod] : undefined,
        responseHeaders: form.target === 'response' ? [mod] : undefined,
        createdAt:       now,
        updatedAt:       now,
      };

      await saveRule(rule);
      const res = await chrome.runtime.sendMessage({ type: 'ADD_HEADER_RULE', payload: rule });

      if (res?.success) {
        setRules(res.data as HeaderRule[] ?? (await (async () => { const r = await chrome.runtime.sendMessage({ type: 'GET_HEADER_RULES' }); return r.data as HeaderRule[]; })()));
        setForm(EMPTY_FORM);
        showToast(true, 'Rule saved successfully.');
        await load();
      } else {
        showToast(false, res?.error ?? 'Failed to save rule.');
      }
    } catch (e) {
      showToast(false, e instanceof Error ? e.message : 'Unexpected error.');
    } finally {
      setSaving(false);
    }
  };

  // ── Toggle ────────────────────────────────────────────────────────────────────
  const handleToggle = async (id: number) => {
    try {
      await toggleRule(id);
      const res = await chrome.runtime.sendMessage({ type: 'TOGGLE_HEADER_RULE', payload: id });
      if (res?.success) await load();
    } catch { /* silent */ }
  };

  // ── Delete ────────────────────────────────────────────────────────────────────
  const handleDelete = async (id: number) => {
    try {
      await deleteRule(id);
      const res = await chrome.runtime.sendMessage({ type: 'DELETE_HEADER_RULE', payload: id });
      if (res?.success) await load();
    } catch { /* silent */ }
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* ── Add rule form ──────────────────────────────────────────────────── */}
      <div className="border-b border-gray-800 bg-gray-900/30 px-3 py-3 space-y-2 shrink-0">
        <p className="text-[10px] uppercase tracking-widest text-gray-600 font-medium select-none mb-1">
          New rule
        </p>

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
          placeholder="URL filter — e.g. *://*.example.com/*"
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

        {/* Row 5: save button */}
        <div className="flex items-center justify-between gap-2 pt-0.5">
          {toast ? (
            <p className={`text-[11px] font-medium truncate ${toast.ok ? 'text-emerald-400' : 'text-red-400'}`}>
              {toast.ok ? '✓ ' : '✕ '}{toast.msg}
            </p>
          ) : (
            <span />
          )}
          <button
            onClick={() => { void handleSave(); }}
            disabled={saving}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors shrink-0"
          >
            <IconPlus className="w-3 h-3" />
            {saving ? 'Saving…' : 'Add rule'}
          </button>
        </div>
      </div>

      {/* ── Rule list ─────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {rules.length === 0 ? (
          <div className="flex items-center justify-center h-20 text-gray-700 text-[11px] text-center px-6 select-none">
            No rules yet. Add one above.
          </div>
        ) : (
          rules.map(r => (
            <RuleRow
              key={r.id}
              rule={r}
              onToggle={id => { void handleToggle(id); }}
              onDelete={id => { void handleDelete(id); }}
            />
          ))
        )}
      </div>

    </div>
  );
};
