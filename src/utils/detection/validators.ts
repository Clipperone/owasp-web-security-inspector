/**
 * Pure validation and hashing helpers used by the detection engine.
 *
 * These run in plain code AFTER a cheap bounded regex prefilter so that
 * expensive/ambiguous matching is never expressed as a regex (ReDoS-safe) and
 * false positives are cut with real checksums (Luhn / mod-97 / Codice Fiscale).
 */

/** Luhn checksum — used for payment cards and Italian VAT (Partita IVA). */
export function luhn(digits: string): boolean {
  const clean = digits.replace(/\D/g, '');
  if (clean.length === 0) return false;
  let sum = 0;
  let double = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = clean.charCodeAt(i) - 48; // '0' = 48
    if (d < 0 || d > 9) return false;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** IBAN country → total length. Conservative subset of common EU countries. */
const IBAN_LENGTHS: Record<string, number> = {
  AT: 20, BE: 16, CH: 21, CZ: 24, DE: 22, DK: 18, ES: 24, FI: 18, FR: 27,
  GB: 22, IE: 22, IT: 27, LU: 20, NL: 18, NO: 15, PL: 28, PT: 25, SE: 24,
};

/**
 * Validates an IBAN by country-specific length and the ISO 7064 mod-97 check.
 * The modulo is computed incrementally so no BigInt is required.
 */
export function ibanMod97(raw: string): boolean {
  const iban = raw.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(iban)) return false;
  const expected = IBAN_LENGTHS[iban.slice(0, 2)];
  if (expected === undefined || iban.length !== expected) return false;

  // Move the first four chars to the end, then map letters to 10..35.
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    let chunk: string;
    if (code >= 65 && code <= 90) chunk = String(code - 55);       // A-Z → 10..35
    else if (code >= 48 && code <= 57) chunk = rearranged[i];       // 0-9
    else return false;
    for (let j = 0; j < chunk.length; j++) {
      remainder = (remainder * 10 + (chunk.charCodeAt(j) - 48)) % 97;
    }
  }
  return remainder === 1;
}

// Codice Fiscale checksum tables (odd/even character positions → value).
const CF_ODD: Record<string, number> = {
  '0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
  A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18,
  N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
};
const CF_EVEN: Record<string, number> = {
  '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
  A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10, L: 11, M: 12,
  N: 13, O: 14, P: 15, Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22, X: 23, Y: 24, Z: 25,
};
const CF_REMAINDER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Validates the check character of a 16-char Italian Codice Fiscale.
 * The first 15 characters feed the odd/even tables; the 16th is the expected
 * remainder letter. Omocodia (letter-substituted digits) is handled because the
 * tables key on both digits and their substitute letters.
 */
export function codiceFiscaleChecksum(cf: string): boolean {
  const value = cf.trim().toUpperCase();
  if (!/^[A-Z0-9]{16}$/.test(value)) return false;
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    const ch = value[i];
    // Positions are 1-based in the spec: odd positions (1,3,...) use CF_ODD.
    const table = (i % 2 === 0) ? CF_ODD : CF_EVEN;
    const add = table[ch];
    if (add === undefined) return false;
    sum += add;
  }
  return CF_REMAINDER[sum % 26] === value[15];
}

/** Shannon entropy (bits per character) of a string. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** True for the canonical 8-4-4-4-12 hex UUID shape (any version). */
export function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.trim());
}

/** FNV-1a 32-bit hash as an 8-char hex string. Deterministic; no crypto needed. */
export function fnv1a32(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i) & 0xff;
    // hash *= 16777619, kept in 32-bit range via Math.imul
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Decodes a Basic-auth credential (the part after `Basic `). Returns the decoded
 * `user:pass` when it is well-formed base64 containing a colon, else null.
 */
export function decodeBasicAuth(base64: string): string | null {
  try {
    // atob exists in the content-script (browser) and in the vitest (node ≥16) runtime.
    const decoded = atob(base64);
    const colon = decoded.indexOf(':');
    return colon >= 1 ? decoded : null;
  } catch {
    return null;
  }
}
