import React from 'react';
import { toneBadgeClasses, type Tone } from './status';

/**
 * Small uppercase status pill. Used for severity and pass/fail/warn states.
 * The colour comes exclusively from the shared tone vocabulary in status.ts.
 */
export function StatusBadge({ tone, children }: { tone: Tone; children: React.ReactNode }): React.JSX.Element {
  return (
    <span className={`px-1.5 py-px text-[9px] font-bold border rounded shrink-0 ${toneBadgeClasses(tone)}`}>
      {children}
    </span>
  );
}
