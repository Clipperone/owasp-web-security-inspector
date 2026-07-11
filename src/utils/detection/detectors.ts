/**
 * Detector catalog.
 *
 * Every `pattern` is bounded and linear-time (literal prefixes plus fixed or
 * `{m,n}`-bounded character classes — no nested or ambiguous quantifiers), so it
 * is ReDoS-safe on the ≤4096-char inputs the engine feeds it. Anything that
 * needs real disambiguation (Luhn, mod-97, Codice Fiscale, entropy, base64
 * decoding) runs in `validate()` as plain code after a cheap regex prefilter.
 */
import type { DetectionCategory, AssessmentSeverity } from '../../types';
import {
  luhn,
  ibanMod97,
  codiceFiscaleChecksum,
  shannonEntropy,
  isUuid,
  decodeBasicAuth,
} from './validators';
import {
  partialMask,
  fullMask,
  maskEmail,
  maskCard,
  maskIban,
  maskUrlCredentials,
} from './redact';

export interface DetectorSpec {
  id: string;
  category: DetectionCategory;
  severity: AssessmentSeverity;
  /** Cheap lowercase-substring gate run before the regex (skips most values). */
  prefilter?: (lowerValue: string) => boolean;
  /** Bounded, linear-time, global regex. */
  pattern: RegExp;
  /** Max matches recorded per value (default 5). */
  maxMatches?: number;
  /** Checksum/structure validation in plain code; match kept only when true. */
  validate?: (match: string) => boolean;
  /** Deterministic mask used both for value splicing and the display sample. */
  redact: (match: string) => string;
}

// ── Payment-card helpers ──────────────────────────────────────────────────────

/** Known issuer identification number (IIN) prefixes for the major networks. */
function hasKnownCardIin(digits: string): boolean {
  if (/^4/.test(digits)) return true;                              // Visa
  if (/^(5[1-5]|2[2-7])/.test(digits)) return true;                // Mastercard
  if (/^3[47]/.test(digits)) return true;                          // Amex
  if (/^(6011|65|64[4-9])/.test(digits)) return true;              // Discover
  if (/^35/.test(digits)) return true;                             // JCB
  return false;
}

function validateCard(match: string): boolean {
  // Reject mixed separators (e.g. "4111 1111-1111 1111") — real cards use one.
  if (match.includes(' ') && match.includes('-')) return false;
  const digits = match.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  if (!hasKnownCardIin(digits)) return false;
  return luhn(digits);
}

// ── High-entropy secret ───────────────────────────────────────────────────────

function validateHighEntropy(match: string): boolean {
  if (match.startsWith('ey')) return false;   // JWT segment — owned by the JWT path
  if (isUuid(match)) return false;            // random-looking but not a secret
  const isHex = /^[0-9a-fA-F]+$/.test(match);
  const entropy = shannonEntropy(match);
  if (isHex) return match.length >= 32 && entropy >= 3.2;
  return match.length >= 40 && entropy >= 4.0;
}

// ── Credential-field redaction ────────────────────────────────────────────────

const JSON_CRED_RE = /("(?:password|passwd|passphrase|pwd|secret|client_secret|api_secret)"\s*:\s*")([^"\\]{1,256})(")/i;
const PLACEHOLDER_SECRETS = new Set(['', 'null', 'true', 'false', '***', 'xxx', 'changeme', 'password']);

function validateJsonCredential(match: string): boolean {
  const m = JSON_CRED_RE.exec(match);
  if (!m) return false;
  return !PLACEHOLDER_SECRETS.has(m[2].toLowerCase());
}

function redactJsonCredential(match: string): string {
  return match.replace(JSON_CRED_RE, '$1•••$3');
}

const FORM_CRED_RE = /((?:^|[?&#;])(?:password|passwd|pwd)=)([^&\s]{1,128})/i;

function validateFormCredential(match: string): boolean {
  const m = FORM_CRED_RE.exec(match);
  if (!m) return false;
  return !PLACEHOLDER_SECRETS.has(m[2].toLowerCase());
}

function redactFormCredential(match: string): string {
  return match.replace(FORM_CRED_RE, '$1•••');
}

// ── URL-credential / connection-string validation ─────────────────────────────

function validateUrlCredentials(match: string): boolean {
  try {
    const url = new URL(match);
    return url.password.length > 0;
  } catch {
    return false;
  }
}

// ── The catalog ───────────────────────────────────────────────────────────────

export const DETECTORS: DetectorSpec[] = [
  // Private keys — the pattern matches the PEM header; the engine redacts the
  // whole value on any private-key hit so a truncated key body cannot leak.
  {
    id: 'pem-private-key',
    category: 'private-key',
    severity: 'high',
    prefilter: v => v.includes('private key'),
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    redact: m => fullMask(m, 'redacted private key'),
  },

  // Cloud / SaaS API keys (distinctive fixed-shape prefixes).
  {
    id: 'aws-access-key-id',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('akia') || v.includes('asia'),
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    redact: m => partialMask(m, 4, 4),
  },
  {
    id: 'github-token',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('gh'),
    pattern: /\bgh[oprsu]_[A-Za-z0-9]{36}\b/g,
    redact: m => partialMask(m, 4, 4),
  },
  {
    id: 'github-pat',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('github_pat_'),
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
    redact: m => partialMask(m, 11, 4),
  },
  {
    id: 'stripe-live-key',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('_live_'),
    pattern: /\b[rs]k_live_[A-Za-z0-9]{16,247}\b/g,
    redact: m => partialMask(m, 8, 4),
  },
  {
    id: 'stripe-test-key',
    category: 'api-key',
    severity: 'low',
    prefilter: v => v.includes('_test_'),
    pattern: /\b[rs]k_test_[A-Za-z0-9]{16,247}\b/g,
    redact: m => partialMask(m, 8, 4),
  },
  {
    id: 'google-api-key',
    category: 'api-key',
    severity: 'medium',
    prefilter: v => v.includes('aiza'),
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    redact: m => partialMask(m, 4, 4),
  },
  {
    id: 'slack-token',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('xox'),
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,250}\b/g,
    redact: m => partialMask(m, 5, 4),
  },
  // Anthropic keys share the `sk-` prefix with OpenAI, so this detector is
  // listed first: on the overlapping span both are api-key + validated, and the
  // engine's tie-break falls back to catalog order, keeping the Anthropic hit.
  {
    id: 'anthropic-key',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('sk-ant-'),
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,250}\b/g,
    validate: m => shannonEntropy(m) >= 3.5,
    redact: m => partialMask(m, 7, 4),
  },
  {
    id: 'openai-key',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('sk-'),
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,250}\b/g,
    validate: m => shannonEntropy(m) >= 3.5,
    redact: m => partialMask(m, 3, 4),
  },
  {
    id: 'huggingface-token',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('hf_'),
    pattern: /\bhf_[A-Za-z0-9]{34,40}\b/g,
    redact: m => partialMask(m, 3, 4),
  },
  {
    id: 'replicate-token',
    category: 'api-key',
    severity: 'high',
    prefilter: v => v.includes('r8_'),
    pattern: /\br8_[A-Za-z0-9]{37,40}\b/g,
    redact: m => partialMask(m, 3, 4),
  },

  // Structured credentials.
  {
    id: 'basic-auth',
    category: 'credential',
    severity: 'high',
    prefilter: v => v.includes('basic '),
    pattern: /\bBasic [A-Za-z0-9+/]{8,340}={0,2}/g,
    validate: m => decodeBasicAuth(m.slice('Basic '.length)) !== null,
    redact: () => 'Basic [redacted]',
  },
  {
    id: 'url-credentials',
    category: 'credential',
    severity: 'high',
    prefilter: v => v.includes('://') && v.includes('@'),
    pattern: /\b(?:https?|ftp):\/\/[^\s/:@]{1,64}:[^\s/@]{1,128}@[^\s/@]{1,256}/gi,
    validate: validateUrlCredentials,
    redact: maskUrlCredentials,
  },
  {
    id: 'connection-string',
    category: 'connection-string',
    severity: 'high',
    prefilter: v => v.includes('://') && v.includes('@'),
    pattern: /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|mariadb|rediss?|amqps?|mssql):\/\/[^\s/:@]{1,64}:[^\s/@]{1,128}@[^\s/@]{1,256}/gi,
    validate: validateUrlCredentials,
    redact: maskUrlCredentials,
  },
  {
    id: 'json-credential-field',
    category: 'credential',
    severity: 'high',
    prefilter: v => v.includes('passw') || v.includes('pwd') || v.includes('secret'),
    pattern: /"(?:password|passwd|passphrase|pwd|secret|client_secret|api_secret)"\s*:\s*"[^"\\]{1,256}"/gi,
    validate: validateJsonCredential,
    redact: redactJsonCredential,
  },
  {
    id: 'form-credential-pair',
    category: 'credential',
    severity: 'high',
    prefilter: v => v.includes('password=') || v.includes('passwd=') || v.includes('pwd='),
    pattern: /(?:^|[?&#;])(?:password|passwd|pwd)=[^&\s]{1,128}/gi,
    validate: validateFormCredential,
    redact: redactFormCredential,
  },

  // Generic high-entropy secret (last resort; overlaps are dropped in favour of
  // the specific detectors above by the engine).
  {
    id: 'high-entropy-secret',
    category: 'high-entropy-secret',
    severity: 'medium',
    pattern: /\b[A-Za-z0-9+/=_-]{32,512}\b/g,
    validate: validateHighEntropy,
    redact: m => partialMask(m, 4, 4),
  },

  // PII.
  {
    id: 'pii-email',
    category: 'pii-email',
    severity: 'low',
    prefilter: v => v.includes('@'),
    pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,251}\.[A-Za-z]{2,24}\b/g,
    redact: maskEmail,
  },
  {
    id: 'pii-card',
    category: 'pii-card',
    severity: 'high',
    pattern: /\b\d[\d -]{11,21}\d\b/g,
    validate: validateCard,
    redact: maskCard,
  },
  {
    id: 'pii-phone-e164',
    category: 'pii-phone',
    severity: 'low',
    prefilter: v => v.includes('+'),
    pattern: /\+[1-9][\d ().-]{6,18}\d/g,
    validate: m => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 8 && digits.length <= 15;
    },
    redact: m => partialMask(m, 3, 3),
  },
  {
    id: 'pii-iban',
    category: 'pii-iban',
    severity: 'medium',
    pattern: /\b[A-Z]{2}\d{2}[A-Za-z0-9]{11,30}\b/g,
    validate: ibanMod97,
    redact: maskIban,
  },
  {
    id: 'pii-codice-fiscale',
    category: 'pii-codice-fiscale',
    severity: 'medium',
    pattern: /\b[A-Za-z]{6}[0-9LMNPQRSTUVlmnpqrstuv]{2}[A-Za-z][0-9LMNPQRSTUVlmnpqrstuv]{2}[A-Za-z][0-9LMNPQRSTUVlmnpqrstuv]{3}[A-Za-z]\b/g,
    validate: codiceFiscaleChecksum,
    redact: m => partialMask(m, 3, 1),
  },
  {
    id: 'eu-vat',
    category: 'eu-vat',
    severity: 'info',
    pattern: /\b(?:IT\d{11}|DE\d{9}|NL\d{9}B\d{2}|ES[A-Z0-9]\d{7}[A-Z0-9])\b/g,
    validate: m => (m.startsWith('IT') ? luhn(m.slice(2)) : true),
    redact: m => m, // public business identifier — not redacted
  },
];

/**
 * Priority for overlap resolution — a lower number wins when two detectors match
 * the same span. Specific/structured secrets beat the generic entropy detector.
 */
export const CATEGORY_PRIORITY: Record<DetectionCategory, number> = {
  'private-key': 0,
  'api-key': 1,
  'credential': 2,
  'connection-string': 2,
  'pii-card': 3,
  'pii-iban': 3,
  'pii-codice-fiscale': 3,
  'high-entropy-secret': 4,
  'pii-email': 5,
  'pii-phone': 5,
  'eu-vat': 6,
};
