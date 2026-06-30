import React from 'react';
import { localInputToUnix, unixToLocalInput } from '../utils/cookieUtils';

export type CookieSameSite = `${chrome.cookies.SameSiteStatus}`;

export interface CookieDraft {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: CookieSameSite;
  expirationDate: number | undefined;
}

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

export const CookieEditorForm: React.FC<{
  draft: CookieDraft;
  onPatch: <K extends keyof CookieDraft>(key: K, value: CookieDraft[K]) => void;
  formError: string | null;
  saveDisabled: boolean;
  saving: boolean;
  submitLabel: string;
  onCancel: () => void;
  onSave: () => void;
  title?: string;
}> = ({ draft, onPatch, formError, saveDisabled, saving, submitLabel, onCancel, onSave, title }) => (
  <div className="space-y-2.5">
    {title && <p className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider">{title}</p>}
    <div className="grid grid-cols-2 gap-3">
      <Field label="Name" required>
        <TextInput value={draft.name} onChange={v => onPatch('name', v)} placeholder="cookie_name" mono />
      </Field>
      <Field label="Value">
        <TextInput value={draft.value} onChange={v => onPatch('value', v)} placeholder="cookie_value" mono />
      </Field>
    </div>
    <div className="grid grid-cols-3 gap-3">
      <Field label="Domain">
        <TextInput value={draft.domain} onChange={v => onPatch('domain', v)} placeholder=".example.com" mono />
      </Field>
      <Field label="Path">
        <TextInput value={draft.path} onChange={v => onPatch('path', v || '/')} placeholder="/" mono />
      </Field>
      <Field label="SameSite">
        <select
          value={draft.sameSite}
          onChange={e => onPatch('sameSite', e.target.value as CookieSameSite)}
          className="w-full px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded text-gray-300 focus:outline-none focus:border-blue-600 transition-colors"
        >
          <option value="unspecified">Unspecified</option>
          <option value="lax">Lax</option>
          <option value="strict">Strict</option>
          <option value="no_restriction">None</option>
        </select>
      </Field>
    </div>
    <div className="flex items-end gap-4">
      <div className="flex-1">
        <Field label="Expires (session if empty)">
          <input
            type="datetime-local"
            value={unixToLocalInput(draft.expirationDate)}
            onChange={e => onPatch('expirationDate', localInputToUnix(e.target.value))}
            className="w-full px-2 py-1.5 text-[11px] bg-gray-800 border border-gray-700 rounded text-gray-300 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </Field>
      </div>
      <div className="flex items-center gap-4 pb-0.5">
        <Toggle label="Secure" checked={draft.secure} onChange={v => onPatch('secure', v)} hint="HTTPS only" />
        <Toggle label="HttpOnly" checked={draft.httpOnly} onChange={v => onPatch('httpOnly', v)} hint="No JS access" />
      </div>
    </div>
    {formError && <p className="text-[11px] text-red-400 bg-red-900/20 border border-red-800/40 rounded px-3 py-2">{formError}</p>}
    <div className="flex items-center justify-end gap-2">
      <button onClick={onCancel} className="px-3 py-1.5 text-[11px] text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded transition-colors">Cancel</button>
      <button onClick={onSave} disabled={saveDisabled} className="px-4 py-1.5 text-[11px] font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors">{saving ? 'Saving…' : submitLabel}</button>
    </div>
  </div>
);