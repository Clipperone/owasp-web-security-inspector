import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { HeaderModification, HeaderOperation, HeaderRule } from '../types';
import { nextRuleId, saveRule, deleteRule, toggleRule } from '../utils/storageUtils';
import { validateHeaderModification, defaultRuleName } from '../utils/headerUtils';
import { useScope } from './ScopeContext';
import { exportToCurl } from '../utils/exporter';

// â”€â”€ Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Quick templates â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

interface Template {
  label:     string;
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

// â”€â”€ Helpers / icons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

const IconGrip: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="currentColor">
    <path d="M8.5 6a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0ZM8.5 12a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0ZM8.5 18a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0ZM15.5 6a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0ZM15.5 12a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0ZM15.5 18a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0Z" />
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

// â”€â”€ Rule row (drag-and-drop aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const RuleRow: React.FC<{
  rule:        HeaderRule;
  index:       number;
  dragging:    number | null;
  onToggle:    (id: number) => void;
  onDelete:    (id: number) => void;
  onDragStart: (index: number) => void;
  onDragOver:  (index: number) => void;
  onDrop:      () => void;
}> = ({ rule, index, dragging, onToggle, onDelete, onDragStart, onDragOver, onDrop }) => {
  const [open, setOpen]         = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);

  const mods: HeaderModification[] = [
    ...(rule.requestHeaders  ?? []).map(m => ({ ...m, _target: 'request'  as const })),
    ...(rule.responseHeaders ?? []).map(m => ({ ...m, _target: 'response' as const })),
  ];

  const isDragging = dragging === index;

  return (
    <div
      draggable
      onDragStart={() => onDragStart(index)}
      onDragOver={e => { e.preventDefault(); onDragOver(index); }}
      onDrop={onDrop}
      className={[
        'border-b border-gray-800/60 text-[11px] transition-opacity duration-150',
        rule.enabled ? '' : 'opacity-50',
        isDragging ? 'opacity-40 bg-blue-900/10' : '',
      ].join(' ')}
    >
      {/* Summary row */}
      <div className="flex items-center gap-2 px-3 py-2 group hover:bg-gray-900/40 transition-colors">
        {/* Drag handle */}
        <span
          className="text-gray-700 hover:text-gray-500 cursor-grab active:cursor-grabbing shrink-0"
          title="Drag to reorder"
        >
          <IconGrip className="w-3 h-3" />
        </span>

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
          <span className="truncate text-gray-600 text-[10px]">â€” {rule.urlFilter}</span>
          <IconChevron open={open} />
        </button>

        {/* Delete */}
        {confirmDel ? (
          <div className="flex items-center gap-1.5 shrink-0">
            <button onClick={() => onDelete(rule.id)} className="text-[10px] text-red-400 hover:text-red-300 font-semibold">âœ“</button>
            <button onClick={() => setConfirmDel(false)} className="text-[10px] text-gray-600 hover:text-gray-400">âœ•</button>
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
                  <span className="text-gray-700">â†’</span>
                  <code className="text-gray-500 truncate">{m.value}</code>
                </>
              )}
            </div>
          ))}
          {rule.domainScope && (
            <div className="text-[10px] text-gray-600 font-mono">
              scope: {rule.domainScope}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// â”€â”€ HeadersTab â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export const HeadersTab: React.FC = () => {
  const [rules, setRules]   = useState<HeaderRule[]>([]);
  const [form, setForm]     = useState<FormState>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [toast, setToast]   = useState<{ ok: boolean; msg: string } | null>(null);
  const toastTimer           = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { mode, activeDomain } = useScope();

  // Export dropdown
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef                    = useRef<HTMLDivElement>(null);

  // Template dropdown
  const [tplOpen, setTplOpen]  = useState(false);
  const tplRef                  = useRef<HTMLDivElement>(null);

  // Active tab info
  const [tabUrl, setTabUrl] = useState('');

  // Drag state
  const dragIndex = useRef<number | null>(null);
  const [dragging, setDragging] = useState<number | null>(null);

  // â”€â”€ Load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const load = useCallback(async () => {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_HEADER_RULES' });
      if (res?.success) setRules(res.data as HeaderRule[]);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // Fetch active tab URL for the live-preview badge
  useEffect(() => {
    void (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        setTabUrl(tab?.url ?? '');
      } catch { /* silent */ }
    })();
  }, []);

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false);
      if (tplRef.current   && !tplRef.current.contains(e.target as Node))   setTplOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // â”€â”€ Live preview badge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ Toast helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const showToast = (ok: boolean, msg: string) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ ok, msg });
    toastTimer.current = setTimeout(() => setToast(null), 2800);
  };

  // â”€â”€ Form helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const patchForm = <K extends keyof FormState>(key: K, val: FormState[K]) =>
    setForm(prev => ({ ...prev, [key]: val }));

  const isValueRequired = form.operation !== 'remove';

  const applyTemplate = (tpl: Template) => {
    setForm(prev => ({
      ...prev,
      header:    tpl.header,
      value:     tpl.value,
      operation: tpl.operation,
      target:    tpl.target,
    }));
    setTplOpen(false);
  };

  // â”€â”€ Save â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const handleSave = async () => {
    const validationErr = validateHeaderModification(form.header, form.operation, form.value);
    if (validationErr) { showToast(false, validationErr); return; }

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
        name:            form.name.trim() || defaultRuleName(form.operation, form.header),
        enabled:         true,
        urlFilter:       form.urlFilter.trim() || '*://*/*',
        requestHeaders:  form.target === 'request'  ? [mod] : undefined,
        responseHeaders: form.target === 'response' ? [mod] : undefined,
        domainScope:     mode === 'domain' && activeDomain ? activeDomain : undefined,
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

  // â”€â”€ Toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const handleToggle = async (id: number) => {
    try {
      await toggleRule(id);
      const res = await chrome.runtime.sendMessage({ type: 'TOGGLE_HEADER_RULE', payload: id });
      if (res?.success) await load();
    } catch { /* silent */ }
  };

  // â”€â”€ Delete â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const handleDelete = async (id: number) => {
    try {
      await deleteRule(id);
      const res = await chrome.runtime.sendMessage({ type: 'DELETE_HEADER_RULE', payload: id });
      if (res?.success) await load();
    } catch { /* silent */ }
  };

  // â”€â”€ Drag & drop reordering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    void chrome.runtime.sendMessage({ type: 'REORDER_HEADER_RULES', payload: orderedIds });
  };

  // â”€â”€ Export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

      {/* â”€â”€ Add rule form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <div className="border-b border-gray-800 bg-gray-900/30 px-3 py-3 space-y-2 shrink-0">
        {/* Form header with template picker */}
        <div className="flex items-center justify-between mb-1">
          <p className="text-[10px] uppercase tracking-widest text-gray-600 font-medium select-none">
            New rule
          </p>
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
          placeholder="URL filter â€” e.g. *://*.example.com/*"
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

        {/* Row 5: live badge + toast + save button */}
        <div className="flex items-center justify-between gap-2 pt-0.5">
          <div className="flex items-center gap-2 min-w-0">
            {toast ? (
              <p className={`text-[11px] font-medium truncate ${toast.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                {toast.ok ? 'âœ“ ' : 'âœ• '}{toast.msg}
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
            {saving ? 'Savingâ€¦' : 'Add rule'}
          </button>
        </div>
      </div>

      {/* â”€â”€ Rule list header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
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

      {/* â”€â”€ Rule list (drag-sortable) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
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
            <RuleRow
              key={r.id}
              rule={r}
              index={i}
              dragging={dragging}
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


