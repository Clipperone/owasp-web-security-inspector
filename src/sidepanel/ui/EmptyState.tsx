import React from 'react';
import { toneTextClasses, type Tone } from './status';

/**
 * A consistent message block for empty / not-yet-captured / informational
 * states, replacing the several bespoke "no data" panels in the views.
 */
export function EmptyState({
  tone = 'neutral',
  title,
  children,
}: {
  tone?: Tone;
  title: string;
  children?: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="p-4 space-y-2 text-[11px]">
      <p className={`font-semibold ${toneTextClasses(tone)}`}>{title}</p>
      {children && <p className="text-gray-500 leading-relaxed">{children}</p>}
    </div>
  );
}
