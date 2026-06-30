import React from 'react';

/**
 * A labelled block inside a disclosure body: a small uppercase caption above
 * its content. Used for Summary / Expected / Observed / Evidence / Remediation
 * and the equivalent transport fields, so every detail pane reads the same.
 */
export function Field({
  label,
  mono = false,
  children,
}: {
  label: string;
  mono?: boolean;
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div>
      <p className="text-[10px] text-gray-600 uppercase tracking-widest font-medium mb-1">{label}</p>
      <div className={mono ? 'text-[11px] text-gray-300 font-mono break-words' : 'text-[11px] text-gray-300 leading-relaxed'}>
        {children}
      </div>
    </div>
  );
}
