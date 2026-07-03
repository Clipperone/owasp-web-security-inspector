/**
 * @file site.ts
 * @description Best-effort "same-site" comparison without a Public Suffix List.
 *
 * The browser-side-only constraint rules out bundling a full PSL, so we use a
 * last-two-labels heuristic plus a tiny set of common two-level suffixes. This
 * is intentionally approximate: it can misgroup multi-part suffixes (e.g. two
 * different `*.co.uk` sites), which is why callers only use it for INFO-level
 * third-party inventory, never for high-severity findings.
 */

/** A small set of common two-level public suffixes to reduce false negatives. */
const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'com.au', 'net.au', 'org.au',
  'co.jp', 'com.br', 'com.cn', 'co.in', 'co.nz', 'co.za',
  'github.io',
]);

/** Approximate registrable domain (eTLD+1) for a hostname. */
export function registrableDomain(hostname: string): string {
  const host = hostname.replace(/\.$/, '').toLowerCase();
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');

  const lastTwo = labels.slice(-2).join('.');
  if (TWO_LEVEL_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

/** True when two hostnames share the same approximate registrable domain. */
export function isSameSite(a: string, b: string): boolean {
  if (a === '' || b === '') return false;
  return registrableDomain(a) === registrableDomain(b);
}
