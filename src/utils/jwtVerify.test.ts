import { describe, expect, test } from 'vitest';
import { verifyJwt, type JwtAlg } from './jwtVerify';

// Web Crypto is a global in Node 19+ and in the browser. Guard defensively for
// older runtimes so the suite is portable.
const subtle: SubtleCrypto = globalThis.crypto?.subtle;

// ── Encoding helpers ─────────────────────────────────────────────────────────

function bytesToB64Url(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function jsonToB64Url(obj: unknown): string {
  return bytesToB64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

function enc(value: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(value);
  const view = new Uint8Array(new ArrayBuffer(encoded.byteLength));
  view.set(encoded);
  return view;
}

const HASH: Record<string, string> = { '256': 'SHA-256', '384': 'SHA-384', '512': 'SHA-512' };

// ── Token minters ────────────────────────────────────────────────────────────

async function signHs(secret: string, alg: JwtAlg = 'HS256', payload: Record<string, unknown> = { sub: 'user' }): Promise<string> {
  const key = await subtle.importKey('raw', enc(secret), { name: 'HMAC', hash: HASH[alg.slice(2)] }, false, ['sign']);
  const signingInput = `${jsonToB64Url({ alg, typ: 'JWT' })}.${jsonToB64Url(payload)}`;
  const sig = await subtle.sign({ name: 'HMAC' }, key, enc(signingInput));
  return `${signingInput}.${bytesToB64Url(new Uint8Array(sig))}`;
}

async function toPem(publicKey: CryptoKey): Promise<string> {
  const spki = await subtle.exportKey('spki', publicKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

async function signRs(payload: Record<string, unknown> = { sub: 'user' }): Promise<{ token: string; pem: string; jwk: JsonWebKey }> {
  const pair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  const signingInput = `${jsonToB64Url({ alg: 'RS256', typ: 'JWT' })}.${jsonToB64Url(payload)}`;
  const sig = await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, pair.privateKey, enc(signingInput));
  return {
    token: `${signingInput}.${bytesToB64Url(new Uint8Array(sig))}`,
    pem: await toPem(pair.publicKey),
    jwk: await subtle.exportKey('jwk', pair.publicKey),
  };
}

async function signPs(): Promise<{ token: string; pem: string }> {
  const pair = await subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;
  const signingInput = `${jsonToB64Url({ alg: 'PS256', typ: 'JWT' })}.${jsonToB64Url({ sub: 'user' })}`;
  const sig = await subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, pair.privateKey, enc(signingInput));
  return { token: `${signingInput}.${bytesToB64Url(new Uint8Array(sig))}`, pem: await toPem(pair.publicKey) };
}

async function signEs(): Promise<{ token: string; pem: string }> {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const signingInput = `${jsonToB64Url({ alg: 'ES256', typ: 'JWT' })}.${jsonToB64Url({ sub: 'user' })}`;
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, enc(signingInput));
  return { token: `${signingInput}.${bytesToB64Url(new Uint8Array(sig))}`, pem: await toPem(pair.publicKey) };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('verifyJwt', () => {
  test('verifies a valid HS256 token', async () => {
    const token = await signHs('top-secret');
    expect(await verifyJwt(token, { expectedAlg: 'HS256', key: { kind: 'hmac-secret', secret: 'top-secret' } }))
      .toEqual({ status: 'verified' });
  });

  test('rejects HS256 with the wrong secret', async () => {
    const token = await signHs('top-secret');
    expect(await verifyJwt(token, { expectedAlg: 'HS256', key: { kind: 'hmac-secret', secret: 'wrong' } }))
      .toEqual({ status: 'invalid' });
  });

  test('verifies HS384 and HS512', async () => {
    const t384 = await signHs('s', 'HS384');
    const t512 = await signHs('s', 'HS512');
    expect(await verifyJwt(t384, { expectedAlg: 'HS384', key: { kind: 'hmac-secret', secret: 's' } })).toEqual({ status: 'verified' });
    expect(await verifyJwt(t512, { expectedAlg: 'HS512', key: { kind: 'hmac-secret', secret: 's' } })).toEqual({ status: 'verified' });
  });

  test('verifies RS256 via PEM and via JWK', async () => {
    const { token, pem, jwk } = await signRs();
    expect(await verifyJwt(token, { expectedAlg: 'RS256', key: { kind: 'pem-spki', pem } })).toEqual({ status: 'verified' });
    expect(await verifyJwt(token, { expectedAlg: 'RS256', key: { kind: 'jwk', jwk } })).toEqual({ status: 'verified' });
  });

  test('rejects RS256 when the payload is tampered', async () => {
    const { token, pem } = await signRs();
    const [h, , s] = token.split('.');
    const tampered = `${h}.${jsonToB64Url({ sub: 'admin' })}.${s}`;
    expect(await verifyJwt(tampered, { expectedAlg: 'RS256', key: { kind: 'pem-spki', pem } })).toEqual({ status: 'invalid' });
  });

  test('verifies a valid PS256 token', async () => {
    const { token, pem } = await signPs();
    expect(await verifyJwt(token, { expectedAlg: 'PS256', key: { kind: 'pem-spki', pem } })).toEqual({ status: 'verified' });
  });

  test('verifies ES256 and rejects a wrong-length signature', async () => {
    const { token, pem } = await signEs();
    expect(await verifyJwt(token, { expectedAlg: 'ES256', key: { kind: 'pem-spki', pem } })).toEqual({ status: 'verified' });

    const [h, p] = token.split('.');
    const badSig = bytesToB64Url(new Uint8Array(70)); // ES256 must be exactly 64 bytes
    expect(await verifyJwt(`${h}.${p}.${badSig}`, { expectedAlg: 'ES256', key: { kind: 'pem-spki', pem } }))
      .toEqual({ status: 'invalid' });
  });

  test('always rejects alg:none', async () => {
    const token = `${jsonToB64Url({ alg: 'none', typ: 'JWT' })}.${jsonToB64Url({ sub: 'user' })}.`;
    expect(await verifyJwt(token, { expectedAlg: 'HS256', key: { kind: 'hmac-secret', secret: 's' } })).toEqual({ status: 'invalid' });
    const hs = await signHs('s');
    expect(await verifyJwt(hs, { expectedAlg: 'none', key: { kind: 'hmac-secret', secret: 's' } })).toEqual({ status: 'invalid' });
  });

  test('defeats the RS256→HS256 algorithm-confusion attack', async () => {
    const { pem } = await signRs();
    // Attacker forges an HS256 token using the public key text as the HMAC secret.
    const forged = await signHs(pem, 'HS256', { sub: 'admin' });
    // The reviewer selected RS256 + the public key, so verification must fail.
    expect(await verifyJwt(forged, { expectedAlg: 'RS256', key: { kind: 'pem-spki', pem } })).toEqual({ status: 'invalid' });
  });

  test('reports unsupported algorithms', async () => {
    const token = await signHs('s');
    expect(await verifyJwt(token, { expectedAlg: 'EdDSA', key: { kind: 'hmac-secret', secret: 's' } }))
      .toEqual({ status: 'unsupported-alg', alg: 'EdDSA' });
  });

  test('returns an error for malformed key material', async () => {
    const { token } = await signRs();
    const result = await verifyJwt(token, { expectedAlg: 'RS256', key: { kind: 'pem-spki', pem: 'not a real key' } });
    expect(result.status).toBe('error');
  });

  test('selects the sole JWKS key, and errors on an ambiguous set', async () => {
    const { token, jwk } = await signRs();
    const other = (await signRs()).jwk;
    expect(await verifyJwt(token, { expectedAlg: 'RS256', key: { kind: 'jwks', jwks: { keys: [jwk] } } })).toEqual({ status: 'verified' });

    const ambiguous = await verifyJwt(token, { expectedAlg: 'RS256', key: { kind: 'jwks', jwks: { keys: [jwk, other] } } });
    expect(ambiguous.status).toBe('error');
  });

  test('errors on a malformed token', async () => {
    const result = await verifyJwt('only.two', { expectedAlg: 'HS256', key: { kind: 'hmac-secret', secret: 's' } });
    expect(result.status).toBe('error');
  });
});
