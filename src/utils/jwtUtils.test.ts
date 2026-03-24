import { afterEach, describe, expect, test, vi } from 'vitest';
import { decodeJwt, formatExpiry, isJwt } from './jwtUtils';

function base64UrlEncode(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = '';
  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createJwt(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  return `${base64UrlEncode(header)}.${base64UrlEncode(payload)}.signature`;
}

describe('jwtUtils', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('detects and decodes a structurally valid JWT', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-24T12:00:00Z'));

    const token = createJwt({ sub: 'user-123', exp: 1_774_818_000, iat: 1_774_814_400 });

    expect(isJwt(token)).toBe(true);

    const decoded = decodeJwt(token);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    expect(decoded.token.payload.sub).toBe('user-123');
    expect(decoded.token.isExpired).toBe(false);
    expect(formatExpiry(decoded.token)).toContain('Expires in');
  });

  test('rejects JWTs with invalid numeric time claims', () => {
    const token = createJwt({ sub: 'user-123', exp: 'never' });
    const decoded = decodeJwt(token);

    expect(decoded.ok).toBe(false);
    if (decoded.ok) return;

    expect(decoded.error).toContain('claim "exp" must be a number');
  });

  test('does not treat arbitrary dot-separated strings as JWTs', () => {
    expect(isJwt('hello.world.signature')).toBe(false);
    expect(decodeJwt('hello.world.signature').ok).toBe(false);
  });
});