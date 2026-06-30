import React from 'react';

/**
 * The single expand/collapse affordance used across the whole UI.
 * Replaces the inconsistent `+`/`−` and ad-hoc chevrons that were scattered
 * across the assessment, transport, headers, and token views.
 */
export function Chevron({ open }: { open: boolean }): React.JSX.Element {
  return (
    <svg
      className={`w-3 h-3 text-gray-500 shrink-0 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      aria-hidden="true"
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
    </svg>
  );
}
