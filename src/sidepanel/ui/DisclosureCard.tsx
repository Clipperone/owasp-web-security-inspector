import React, { useState } from 'react';
import { Chevron } from './Chevron';

/**
 * A single expandable finding/check row: a badge + title (+ optional meta) on
 * the trigger line, and a details body revealed on expand. Shared by the
 * header, transport, cookie, token, and storage assessment views so they all
 * disclose detail the same way.
 */
export function DisclosureCard({
  badge,
  title,
  meta,
  defaultOpen = false,
  children,
}: {
  badge?: React.ReactNode;
  title: React.ReactNode;
  meta?: React.ReactNode;
  defaultOpen?: boolean;
  children: React.ReactNode;
}): React.JSX.Element {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border-b border-gray-800/60 last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen(current => !current)}
        className="w-full px-3 py-2 text-left hover:bg-gray-900/20 transition-colors"
      >
        <div className="flex items-center gap-2">
          {badge}
          <h3 className="text-[12px] text-gray-100 font-semibold flex-1 min-w-0">{title}</h3>
          {meta}
          <Chevron open={open} />
        </div>
      </button>
      {open && <div className="px-3 pb-2.5 space-y-2">{children}</div>}
    </div>
  );
}
