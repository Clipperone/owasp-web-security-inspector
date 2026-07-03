/**
 * @file jwtVerify.ts
 * @description Local JWT signature verification via the Web Crypto API
 * (`crypto.subtle`). Milestone M4.
 *
 * This is intentionally separate from `jwtUtils.ts` (which only *decodes*).
 * Verification proves the token was signed with the provided key — a different,
 * stronger claim than "decoded successfully".
 *
 * Design constraints (browser-side only):
 *   - No external libraries and no network calls. The caller supplies the key
 *     material (HMAC secret, SPKI PEM public key, JWK, or a pasted JWKS set).
 *   - The verification algorithm is taken from the caller's `expectedAlg`, never
 *     from the token header, to prevent algorithm-confusion attacks (e.g. an
 *     RS256 public key being abused as an HS256 shared secret).
 *   - `alg: none` is always rejected.
 */

/** JOSE algorithms this module understands. `none`/`EdDSA` are recognized but not verifiable here. */
export type JwtAlg =
  | 'HS256' | 'HS384' | 'HS512'
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384'
  | 'EdDSA'
  | 'none';

/** Algorithms offered in the UI (those we can actually verify with Web Crypto). */
export const SUPPORTED_VERIFY_ALGS: JwtAlg[] = [
  'HS256', 'HS384', 'HS512',
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384',
];

export type VerificationKeyInput =
  | { kind: 'hmac-secret'; secret: string }
  | { kind: 'pem-spki'; pem: string }
  | { kind: 'jwk'; jwk: JsonWebKey }
  | { kind: 'jwks'; jwks: { keys: JsonWebKey[] } };

export type VerifyResult =
  | { status: 'verified' }
  | { status: 'invalid' }
  | { status: 'unsupported-alg'; alg: string }
  | { status: 'error'; reason: string };

export interface VerifyOptions {
  expectedAlg: JwtAlg;
  key: VerificationKeyInput;
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm table
// ─────────────────────────────────────────────────────────────────────────────

interface AlgDescriptor {
  family: 'HMAC' | 'RSASSA' | 'PSS' | 'ECDSA';
  hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  namedCurve?: 'P-256' | 'P-384';
  /** Salt length (bytes) for RSA-PSS verification. */
  saltLength?: number;
  /** Expected raw signature length (bytes) for ECDSA r‖s. */
  ecdsaSignatureLength?: number;
}

const ALG_TABLE: Partial<Record<JwtAlg, AlgDescriptor>> = {
  HS256: { family: 'HMAC', hash: 'SHA-256' },
  HS384: { family: 'HMAC', hash: 'SHA-384' },
  HS512: { family: 'HMAC', hash: 'SHA-512' },
  RS256: { family: 'RSASSA', hash: 'SHA-256' },
  RS384: { family: 'RSASSA', hash: 'SHA-384' },
  RS512: { family: 'RSASSA', hash: 'SHA-512' },
  PS256: { family: 'PSS', hash: 'SHA-256', saltLength: 32 },
  PS384: { family: 'PSS', hash: 'SHA-384', saltLength: 48 },
  PS512: { family: 'PSS', hash: 'SHA-512', saltLength: 64 },
  ES256: { family: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256', ecdsaSignatureLength: 64 },
  ES384: { family: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384', ecdsaSignatureLength: 96 },
};

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Encode a string to UTF-8 bytes backed by a plain ArrayBuffer (Web Crypto BufferSource). */
function utf8(value: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(value);
  const view = new Uint8Array(new ArrayBuffer(encoded.byteLength));
  view.set(encoded);
  return view;
}

/** Decode a Base64Url string (JWT segment / signature) into raw bytes. */
export function base64UrlToUint8Array(segment: string): Uint8Array<ArrayBuffer> {
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Convert a PEM-encoded SPKI public key into DER bytes for `importKey('spki', …)`. */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const trimmed = pem.trim();
  if (/BEGIN RSA (PUBLIC|PRIVATE) KEY/.test(trimmed)) {
    throw new Error('PKCS#1 keys are not supported — provide an SPKI public key (-----BEGIN PUBLIC KEY-----).');
  }
  if (/BEGIN CERTIFICATE/.test(trimmed)) {
    throw new Error('Certificates are not supported — extract the SPKI public key (-----BEGIN PUBLIC KEY-----).');
  }
  const body = trimmed
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (body.length === 0) {
    throw new Error('No PEM body found — expected a base64 SPKI public key.');
  }
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key selection / import
// ─────────────────────────────────────────────────────────────────────────────

function ktyForFamily(family: AlgDescriptor['family']): string {
  switch (family) {
    case 'HMAC': return 'oct';
    case 'ECDSA': return 'EC';
    default: return 'RSA';
  }
}

/** Pick the JWK to use from a JWKS set, preferring `kid`, then `alg`, then `kty`. */
export function selectJwkFromSet(
  jwks: { keys: JsonWebKey[] },
  expectedAlg: JwtAlg,
  family: AlgDescriptor['family'],
  kid?: string,
): JsonWebKey {
  const keys = jwks.keys ?? [];
  if (keys.length === 0) {
    throw new Error('JWKS contains no keys.');
  }

  if (kid) {
    const byKid = keys.filter(k => (k as { kid?: string }).kid === kid);
    if (byKid.length === 1) return byKid[0];
    if (byKid.length > 1) throw new Error('Ambiguous JWKS: multiple keys share the requested kid.');
  }

  const byAlg = keys.filter(k => k.alg === expectedAlg);
  if (byAlg.length === 1) return byAlg[0];
  if (byAlg.length > 1) throw new Error('Ambiguous JWKS: specify a kid to disambiguate.');

  const expectedKty = ktyForFamily(family);
  const byKty = keys.filter(k => k.kty === expectedKty);
  if (byKty.length === 1) return byKty[0];

  throw new Error('Ambiguous JWKS: specify a kid to select the verification key.');
}

function importAlgorithm(descriptor: AlgDescriptor): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams {
  switch (descriptor.family) {
    case 'HMAC': return { name: 'HMAC', hash: descriptor.hash };
    case 'RSASSA': return { name: 'RSASSA-PKCS1-v1_5', hash: descriptor.hash };
    case 'PSS': return { name: 'RSA-PSS', hash: descriptor.hash };
    case 'ECDSA': return { name: 'ECDSA', namedCurve: descriptor.namedCurve! };
  }
}

function verifyAlgorithm(descriptor: AlgDescriptor): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  switch (descriptor.family) {
    case 'HMAC': return { name: 'HMAC' };
    case 'RSASSA': return { name: 'RSASSA-PKCS1-v1_5' };
    case 'PSS': return { name: 'RSA-PSS', saltLength: descriptor.saltLength! };
    case 'ECDSA': return { name: 'ECDSA', hash: descriptor.hash };
  }
}

async function importVerificationKey(
  descriptor: AlgDescriptor,
  expectedAlg: JwtAlg,
  key: VerificationKeyInput,
  kid?: string,
): Promise<CryptoKey> {
  const algorithm = importAlgorithm(descriptor);

  switch (key.kind) {
    case 'hmac-secret':
      if (descriptor.family !== 'HMAC') {
        throw new Error(`${expectedAlg} requires an asymmetric key, not a shared secret.`);
      }
      return crypto.subtle.importKey('raw', utf8(key.secret), algorithm, false, ['verify']);
    case 'pem-spki':
      if (descriptor.family === 'HMAC') {
        throw new Error('HS* algorithms use a shared secret, not a PEM public key.');
      }
      return crypto.subtle.importKey('spki', pemToArrayBuffer(key.pem), algorithm, false, ['verify']);
    case 'jwk':
      return crypto.subtle.importKey('jwk', key.jwk, algorithm, false, ['verify']);
    case 'jwks': {
      const jwk = selectJwkFromSet(key.jwks, expectedAlg, descriptor.family, kid);
      return crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify']);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

interface DecodedHeader {
  alg?: string;
  kid?: string;
}

function readHeader(segment: string): DecodedHeader {
  const json = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(segment))) as Record<string, unknown>;
  return {
    alg: typeof json.alg === 'string' ? json.alg : undefined,
    kid: typeof json.kid === 'string' ? json.kid : undefined,
  };
}

/**
 * Verify a compact JWS signature locally.
 *
 * The algorithm is chosen from `opts.expectedAlg` (never the token header) to
 * defeat algorithm-confusion attacks. `alg: none` is always rejected.
 */
export async function verifyJwt(raw: string, opts: VerifyOptions): Promise<VerifyResult> {
  const { expectedAlg, key } = opts;

  try {
    if (expectedAlg === 'none') {
      return { status: 'invalid' };
    }

    const descriptor = ALG_TABLE[expectedAlg];
    if (!descriptor) {
      return { status: 'unsupported-alg', alg: expectedAlg };
    }

    const parts = raw.trim().split('.');
    if (parts.length !== 3) {
      return { status: 'error', reason: 'Not a compact JWS — expected three dot-separated segments.' };
    }
    const [headerSegment, payloadSegment, signatureSegment] = parts;

    let header: DecodedHeader;
    try {
      header = readHeader(headerSegment);
    } catch {
      return { status: 'error', reason: 'Malformed JWT header.' };
    }
    // A token that declares alg:none is never trusted, regardless of expectedAlg.
    if (header.alg === 'none') {
      return { status: 'invalid' };
    }

    const signature = base64UrlToUint8Array(signatureSegment);
    // ECDSA JOSE signatures are raw fixed-width r‖s (not ASN.1 DER). A wrong
    // length usually means a DER blob was pasted — reject instead of throwing.
    if (descriptor.family === 'ECDSA'
      && descriptor.ecdsaSignatureLength !== undefined
      && signature.length !== descriptor.ecdsaSignatureLength) {
      return { status: 'invalid' };
    }

    const cryptoKey = await importVerificationKey(descriptor, expectedAlg, key, header.kid);
    const signingInput = utf8(`${headerSegment}.${payloadSegment}`);
    const ok = await crypto.subtle.verify(verifyAlgorithm(descriptor), cryptoKey, signature, signingInput);

    return ok ? { status: 'verified' } : { status: 'invalid' };
  } catch (err) {
    return { status: 'error', reason: err instanceof Error ? err.message : String(err) };
  }
}
