/**
 * Deterministic redaction helpers.
 *
 * Determinism is a hard constraint: the same input must always produce the same
 * masked output (no randomness, no timestamps), so a future Snapshot Diff never
 * reports spurious changes for an unchanged secret.
 */

const ELLIPSIS = '…';

/** Keep the first `keepStart` and last `keepEnd` characters, mask the middle. */
export function partialMask(value: string, keepStart: number, keepEnd: number): string {
  const v = value.trim();
  if (v.length <= keepStart + keepEnd) {
    // Too short to reveal both ends without exposing everything — mask fully.
    return `${ELLIPSIS} (${v.length} chars)`;
  }
  return `${v.slice(0, keepStart)}${ELLIPSIS}${v.slice(v.length - keepEnd)}`;
}

/** Replace the whole match with a length-annotated redaction marker. */
export function fullMask(value: string, label = 'redacted'): string {
  return `[${label}, ${value.trim().length} chars]`;
}

/** Mask an email as `a…@domain` (first character + domain preserved). */
export function maskEmail(value: string): string {
  const at = value.indexOf('@');
  if (at <= 0) return partialMask(value, 1, 0);
  const local = value.slice(0, at);
  const domain = value.slice(at); // includes '@'
  return `${local[0]}${ELLIPSIS}${domain}`;
}

/** Mask a payment card as groups of four, revealing only the last four digits. */
export function maskCard(value: string): string {
  const digits = value.replace(/\D/g, '');
  const last4 = digits.slice(-4);
  return `•••• •••• •••• ${last4}`;
}

/** Mask an IBAN as `CC00…1234` (country + check digits + last four). */
export function maskIban(value: string): string {
  const iban = value.replace(/\s+/g, '').toUpperCase();
  if (iban.length <= 8) return partialMask(iban, 4, 0);
  return `${iban.slice(0, 4)}${ELLIPSIS}${iban.slice(-4)}`;
}

/**
 * Mask the password segment of a `scheme://user:pass@host…` credential URL,
 * keeping the scheme, username, and host as useful evidence.
 */
export function maskUrlCredentials(value: string): string {
  // scheme://user:pass@rest → scheme://user:•••@rest
  return value.replace(/^([a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:)[^\s/@]+(@)/i, `$1•••$2`);
}
