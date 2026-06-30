import React, { useState } from 'react';
import { Chevron } from './Chevron';

/**
 * A collapsible, titled group with an optional right-aligned meta slot
 * (typically status counters). One consistent header style and one expand
 * affordance for every grouped list in the app.
 */
export function Section({
  title,
  meta,
  defaultOpen = false,
  children,
}: {
  title: React.ReactNode;
  meta?: React.ReactNode;
  defaultOpen?: boolean;
  children: React.ReactNode;
}): React.JSX.Element {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="border border-gray-800 rounded overflow-hidden bg-gray-950/20">
      <button
        type="button"
        onClick={() => setOpen(current => !current)}
        className="w-full px-3 py-2 text-left bg-gray-950/40 hover:bg-gray-900/30 transition-colors"
      >
        <div className="flex items-center justify-between gap-3">
          <p className="text-[12px] text-gray-100 font-semibold min-w-0 truncate">{title}</p>
          <div className="flex items-center gap-3 shrink-0 text-[10px]">
            {meta}
            <Chevron open={open} />
          </div>
        </div>
      </button>
      {open && <div className="border-t border-gray-800">{children}</div>}
    </section>
  );
}
