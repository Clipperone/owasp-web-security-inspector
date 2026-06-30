import React, { useState } from 'react';
import type { HeaderModification, HeaderRule } from '../types';

const IconTrash: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
  </svg>
);

const IconPencil: React.FC<{ className?: string }> = ({ className }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
    <path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125" />
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

export const HeaderRuleRow: React.FC<{
  rule: HeaderRule;
  index: number;
  dragging: number | null;
  editing: boolean;
  onEdit: (rule: HeaderRule) => void;
  onToggle: (id: number) => void;
  onDelete: (id: number) => void;
  onDragStart: (index: number) => void;
  onDragOver: (index: number) => void;
  onDrop: () => void;
}> = ({ rule, index, dragging, editing, onEdit, onToggle, onDelete, onDragStart, onDragOver, onDrop }) => {
  const [open, setOpen] = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);

  const mods: HeaderModification[] = [
    ...(rule.requestHeaders ?? []).map(m => ({ ...m, _target: 'request' as const })),
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
        editing ? 'bg-blue-950/20' : '',
        isDragging ? 'opacity-40 bg-blue-900/10' : '',
      ].join(' ')}
    >
      <div className="flex items-center gap-2 px-3 py-2 group hover:bg-gray-900/40 transition-colors">
        <span
          className="text-gray-700 hover:text-gray-500 cursor-grab active:cursor-grabbing shrink-0"
          title="Drag to reorder"
        >
          <IconGrip className="w-3 h-3" />
        </span>

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

        <button
          onClick={() => setOpen(p => !p)}
          className="flex-1 min-w-0 flex items-center gap-1.5 text-left"
        >
          <span className="truncate text-gray-300 font-medium">
            {rule.name || <span className="text-gray-600 italic">(unnamed)</span>}
          </span>
          <span className="truncate text-gray-600 text-[10px]">– {rule.urlFilter}</span>
          <IconChevron open={open} />
        </button>

        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onEdit(rule)}
            title="Edit rule"
            className={[
              'p-1 rounded transition-colors',
              editing
                ? 'text-blue-300 bg-blue-900/30'
                : 'text-gray-700 hover:text-blue-400 hover:bg-gray-800 opacity-0 group-hover:opacity-100',
            ].join(' ')}
          >
            <IconPencil className="w-3 h-3" />
          </button>

          {confirmDel ? (
            <div className="flex items-center gap-1.5 shrink-0">
              <button onClick={() => onDelete(rule.id)} className="text-[10px] text-red-400 hover:text-red-300 font-semibold">✔</button>
              <button onClick={() => setConfirmDel(false)} className="text-[10px] text-gray-600 hover:text-gray-400">✖</button>
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
      </div>

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
                m.operation === 'set' ? 'bg-emerald-900/30 text-emerald-400' :
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