import { useEffect } from 'react';

export function useDismissOnOutsideClick<T extends HTMLElement>(
  ref: React.RefObject<T | null>,
  onDismiss: () => void,
  enabled: boolean,
): void {
  useEffect(() => {
    if (!enabled) return;

    const handleMouseDown = (event: MouseEvent) => {
      const target = event.target as Node | null;
      if (ref.current && target && ref.current.contains(target)) return;
      onDismiss();
    };

    document.addEventListener('mousedown', handleMouseDown);
    return () => document.removeEventListener('mousedown', handleMouseDown);
  }, [enabled, onDismiss, ref]);
}