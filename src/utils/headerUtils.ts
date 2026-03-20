/**
 * Header rule utilities — validation and display helpers shared between the
 * popup form and any future tooling.
 */

import type { HeaderOperation } from '../types';

/**
 * Validates the three core fields of a header modification entry.
 * Returns a human-readable error string on failure, or `null` when valid.
 *
 * Rules:
 *   - `header` is always required.
 *   - `value` is required for `append` and `set`; omitted for `remove`.
 */
export function validateHeaderModification(
  header: string,
  operation: HeaderOperation,
  value: string,
): string | null {
  if (!header.trim()) return 'Header name is required.';
  if (operation !== 'remove' && !value.trim()) return 'Header value is required.';
  return null;
}

/**
 * Generates a readable default rule name when the user leaves the name
 * field blank, e.g. `"set Authorization"`.
 */
export function defaultRuleName(operation: string, header: string): string {
  return `${operation} ${header.trim()}`;
}
