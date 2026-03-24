/**
 * @file jwtUtils.ts
 * @description Pure TypeScript utilities for JWT validation and decoding.
 *
 * All operations run locally in the browser using the built-in `atob()`
 * function. No external libraries are used — intentional per the project's
 * "Local Only" architecture rule.
 *
 * Signature verification is intentionally NOT performed: this extension is an
 * inspector tool, not an authentication library. Verifying signatures would
 * require possession of the secret / public key, which is not available here.
 */

import type { JWTHeader, JWTPayload, TokenData } from '../types';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** A compact-serialized JWT contains exactly 3 dot-separated segments. */
const JWT_SEGMENT_COUNT = 3;

/**
 * A valid Base64Url segment uses only A-Z, a-z, 0-9, `-`, and `_`.
 * Padding characters (`=`) are absent in the compact JWT serialization.
 */
const BASE64URL_SEGMENT_RE = /^[A-Za-z0-9\-_]+$/;

// ─────────────────────────────────────────────────────────────────────────────
// Public result type
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Discriminated union returned by `decodeJwt`.
 * Always narrow on `ok` before accessing `token` or `error`.
 *
 * @example
 * const result = decodeJwt(raw);
 * if (result.ok) { ... result.token ... }
 * else           { ... result.error ... }
 */
export type JwtDecodeResult =
  | { ok: true;  token: TokenData }
  | { ok: false; error: string };

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns `true` when `value` matches the compact JWT serialization format
 * and both header and payload decode to JSON objects with a valid JOSE `alg`
 * header. This avoids false positives from arbitrary dot-separated strings
 * that happen to look Base64Url-ish.
 *
 * @example
 * isJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig') // → true
 * isJwt('hello.world')                                    // → false
 * isJwt('')                                               // → false
 */
export function isJwt(value: string): boolean {
  return parseJwtEnvelope(value).ok;
}

/**
 * Decodes a compact JWT string into its header, payload, and signature parts.
 *
 * Returns a discriminated union — all exceptions are caught internally so it
 * is safe to call with any arbitrary string.
 *
 * Validation performed:
 * - Structural check (3 Base64Url segments)
 * - Header and payload must decode to JSON objects
 * - JOSE header must contain a string `alg` claim (RFC 7515 §4.1.1)
 * - Time claims `exp`, `nbf`, `iat` must be numbers when present (RFC 7519 §4.1)
 *
 * @param raw - The raw JWT string to decode.
 *
 * @example
 * const result = decodeJwt(rawToken);
 * if (result.ok) {
 *   console.log(result.token.payload.sub);
 *   console.log(result.token.isExpired);
 * } else {
 *   console.error(result.error);
 * }
 */
export function decodeJwt(raw: string): JwtDecodeResult {
  const envelope = parseJwtEnvelope(raw);
  if (!envelope.ok) {
    return { ok: false, error: envelope.error };
  }

  const { header, payload, signature } = envelope;

  // Validate numeric time claims — protects against type-confusion attacks
  // where a crafted token sets `exp` to a non-number (e.g. "exp": "never")
  // to defeat client-side expiry checks.
  for (const claim of ['exp', 'nbf', 'iat'] as const) {
    if (claim in payload && typeof payload[claim] !== 'number') {
      return {
        ok: false,
        error: `Invalid JWT payload: claim "${claim}" must be a number (Unix timestamp).`,
      };
    }
  }

  // ── Build expiry metadata ─────────────────────────────────────────────────
  const expClaim  = payload.exp;
  const expiresAt = typeof expClaim === 'number' ? new Date(expClaim * 1_000) : undefined;
  const isExpired = expiresAt !== undefined ? expiresAt < new Date() : false;

  return {
    ok: true,
    token: {
      raw,
      header,
      payload,
      signature,
      isExpired,
      expiresAt,
    },
  };
}

/**
 * Returns a human-readable string describing when a token expires or expired.
 * Designed for compact display in the extension popup.
 *
 * @example
 * formatExpiry(token) // → "Expires in 2 hours"
 * formatExpiry(token) // → "Expired 3 days ago"
 * formatExpiry(token) // → "No expiry claim"
 */
export function formatExpiry(token: TokenData): string {
  if (token.expiresAt === undefined) return 'No expiry claim';

  const diffMs   = token.expiresAt.getTime() - Date.now();
  const diffSecs = Math.round(diffMs / 1_000);
  const absSecs  = Math.abs(diffSecs);
  const past     = diffSecs < 0;

  /**
   * Builds a phrase like "Expires in 2 hours" or "Expired 2 hours ago".
   */
  const fmt = (n: number, unit: string): string =>
    past
      ? `Expired ${n} ${unit}${n !== 1 ? 's' : ''} ago`
      : `Expires in ${n} ${unit}${n !== 1 ? 's' : ''}`;

  if (absSecs < 60)                        return fmt(absSecs,                     'second');
  const absMins  = Math.round(absSecs  / 60);
  if (absMins  < 60)                       return fmt(absMins,                     'minute');
  const absHours = Math.round(absMins  / 60);
  if (absHours < 24)                       return fmt(absHours,                    'hour');
  return                                          fmt(Math.round(absHours / 24),   'day');
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Internal discriminated union for segment-level decode results. */
type SegmentResult<T> =
  | { ok: true;  value: T }
  | { ok: false; error: string };

type JwtEnvelopeResult =
  | {
      ok: true;
      header: JWTHeader;
      payload: JWTPayload;
      signature: string;
    }
  | { ok: false; error: string };

function parseJwtEnvelope(value: string): JwtEnvelopeResult {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, error: 'Value does not match the JWT compact serialization format.' };
  }

  const parts = value.split('.');
  if (parts.length !== JWT_SEGMENT_COUNT) {
    return { ok: false, error: 'Value does not match the JWT compact serialization format.' };
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts;
  if (
    headerSegment.length === 0 ||
    payloadSegment.length === 0 ||
    !BASE64URL_SEGMENT_RE.test(headerSegment) ||
    !BASE64URL_SEGMENT_RE.test(payloadSegment)
  ) {
    return { ok: false, error: 'Value does not match the JWT compact serialization format.' };
  }

  const headerResult = decodeSegment<JWTHeader>(headerSegment);
  if (!headerResult.ok) {
    return { ok: false, error: `Invalid JWT header: ${headerResult.error}` };
  }

  if (typeof headerResult.value.alg !== 'string') {
    return { ok: false, error: 'Invalid JWT header: missing or non-string "alg" field.' };
  }

  const payloadResult = decodeSegment<JWTPayload>(payloadSegment);
  if (!payloadResult.ok) {
    return { ok: false, error: `Invalid JWT payload: ${payloadResult.error}` };
  }

  return {
    ok: true,
    header: headerResult.value,
    payload: payloadResult.value,
    signature: signatureSegment ?? '',
  };
}

/**
 * Converts a single Base64Url-encoded JWT segment into a typed JSON object.
 *
 * Base64Url → Base64 conversion steps:
 *   1. Replace URL-safe chars:  `-` → `+`  and  `_` → `/`
 *   2. Restore `=` padding (Base64 strings must be a multiple of 4 characters)
 *   3. `atob()` → binary string
 *   4. `decodeURIComponent(escape(...))` → correct UTF-8 string
 *      (plain `atob()` alone mangles multi-byte characters)
 *   5. `JSON.parse` → typed value
 *
 * All steps are wrapped in try/catch so failures produce a descriptive message
 * instead of an uncaught exception.
 */
function decodeSegment<T>(segment: string): SegmentResult<T> {
  try {
    // Step 1 & 2: Base64Url → padded Base64
    const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      '=',
    );

    // Step 3 & 4: binary → UTF-8 string
    const jsonString = decodeURIComponent(escape(atob(padded)));

    // Step 5: parse JSON
    const parsed = JSON.parse(jsonString) as T;

    // A JWT segment must be a JSON object, never a primitive or array
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { ok: false, error: 'Segment decoded to a non-object JSON value.' };
    }

    return { ok: true, value: parsed };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
