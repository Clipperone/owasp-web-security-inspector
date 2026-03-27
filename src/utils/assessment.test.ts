import { afterEach, describe, expect, test, vi } from 'vitest';
import type { CachedRequest, StorageEntry } from '../types';
import {
  assessBrowserTokens,
  assessCookiesForUrl,
  assessHeaders,
  buildAssessmentFindings,
  getFindingCounts,
  getOwaspHeaderAssessment,
  getTokenAssessmentSummary,
} from './assessment';

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

function createCookie(overrides: Partial<chrome.cookies.Cookie> = {}): chrome.cookies.Cookie {
  return {
    domain: 'app.example.com',
    expirationDate: undefined,
    hostOnly: true,
    httpOnly: false,
    name: 'session',
    path: '/',
    sameSite: 'unspecified',
    secure: false,
    session: true,
    storeId: '0',
    value: 'opaque-session-id',
    ...overrides,
  };
}

function createRequest(overrides: Partial<CachedRequest> = {}): CachedRequest {
  return {
    method: 'GET',
    resourceType: 'main_frame',
    responseHeaders: [],
    statusCode: 200,
    timestamp: Date.now(),
    url: 'https://app.example.com/account',
    ...overrides,
  };
}

describe('assessment utilities', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('classifies sensitive and csrf cookies through findings', () => {
    const cookies = [
      createCookie({ name: 'session', secure: false, httpOnly: false, sameSite: 'unspecified' }),
      createCookie({ name: 'xsrf', secure: true, httpOnly: false, sameSite: 'unspecified', value: 'csrf-value' }),
    ];

    const findings = assessCookiesForUrl(cookies, 'https://app.example.com/account/profile');
    const titles = findings.map(finding => finding.title);

    expect(titles).toContain('Sensitive cookie without Secure');
    expect(titles).toContain('Sensitive cookie without HttpOnly');
    expect(titles).toContain('Sensitive cookie without explicit SameSite');
    expect(titles).toContain('CSRF-related cookie without explicit SameSite');
  });

  test('parses Set-Cookie headers with equals signs and evaluates response-side security attributes', () => {
    const requests = [
      createRequest({
        method: 'POST',
        resourceType: 'xmlhttprequest',
        url: 'https://app.example.com/auth/callback',
        responseHeaders: [
          { name: 'Set-Cookie', value: 'auth_token=abc=def; Path=/; SameSite=None' },
          { name: 'Cache-Control', value: 'no-store' },
        ],
      }),
    ];

    const findings = assessHeaders('https://app.example.com/account', requests);
    const titles = findings.map(finding => finding.title);
    const evidence = findings.map(finding => finding.evidence).join('\n');

    expect(titles).toContain('Set-Cookie for a sensitive cookie is missing Secure');
    expect(titles).toContain('Set-Cookie for a sensitive cookie is missing HttpOnly');
    expect(titles).toContain('Set-Cookie uses SameSite=None without Secure');
    expect(evidence).toContain('auth_token');
    expect(evidence).toContain('/auth/callback');
  });

  test('sorts aggregate findings by severity before title and reports counts', () => {
    const cookies = [
      createCookie({ name: 'session', secure: false, httpOnly: false, sameSite: 'unspecified' }),
      createCookie({ name: 'auth', secure: true, httpOnly: true, sameSite: 'lax', path: '/account' }),
    ];

    const findings = buildAssessmentFindings({
      activeUrl: 'https://app.example.com/account',
      cookies,
      storageEntries: [],
      requests: [createRequest()],
    });

    const counts = getFindingCounts(findings);
    const lastFinding = findings[findings.length - 1];

    expect(findings[0]?.severity).toBe('high');
    expect(lastFinding?.severity === 'low' || lastFinding?.severity === 'info').toBe(true);
    expect(counts.high).toBeGreaterThan(0);
    expect(counts.medium).toBeGreaterThanOrEqual(0);
  });

  test('detects JWT risk and sensitive claims across token origins', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-24T12:00:00Z'));

    const jwt = createJwt({
      sub: 'user-123',
      email: 'user@example.com',
      role: 'admin',
      iat: 1_774_814_400,
      exp: 1_774_900_800,
      scope: 'read:all',
    });

    const entries: StorageEntry[] = [
      {
        area: 'localStorage',
        key: 'access_token',
        value: jwt,
        hints: ['jwt-value'],
        isJwt: true,
      },
      {
        area: 'sessionStorage',
        key: 'refresh_token',
        value: 'Bearer abcdefghijklmnopqrstuvwxyz0123456789',
        hints: ['key-name'],
        isJwt: false,
      },
    ];

    const findings = assessBrowserTokens([], entries);
    const titles = findings.map(finding => finding.title);
    const tokenSummary = getTokenAssessmentSummary([], entries, jwt);

    expect(titles).toContain('JWT stored in localStorage');
    expect(titles).toContain('JWT payload exposes potentially sensitive claims');
    expect(titles).toContain('JWT has a long validity window');
    expect(titles).toContain('Opaque token-like value stored in sessionStorage');
    expect(tokenSummary.counts.localStorage).toBe(1);
    expect(tokenSummary.counts.sessionStorage).toBe(1);
    expect(tokenSummary.counts.manual).toBe(1);
    expect(tokenSummary.jwtCount).toBe(2);
  });

  test('builds a passing OWASP Secure Headers report for validator-aligned responses', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        { name: 'X-Frame-Options', value: 'DENY' },
        { name: 'X-Content-Type-Options', value: 'nosniff' },
        { name: 'Content-Security-Policy', value: "default-src 'self'; object-src 'none'; frame-ancestors 'none'" },
        { name: 'X-Permitted-Cross-Domain-Policies', value: 'none' },
        { name: 'Referrer-Policy', value: 'no-referrer' },
        { name: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },
        { name: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
        { name: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
        {
          name: 'Permissions-Policy',
          value: 'accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(self), unload=(), usb=(), web-share=(), xr-spatial-tracking=()',
        },
        { name: 'Cache-Control', value: 'no-store, max-age=0' },
        { name: 'X-DNS-Prefetch-Control', value: 'off' },
      ],
    });
    const logoutRequest = createRequest({
      method: 'POST',
      resourceType: 'xmlhttprequest',
      url: 'https://app.example.com/logout',
      responseHeaders: [
        { name: 'Clear-Site-Data', value: '"cache","cookies","storage"' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest, logoutRequest]);
    const hstsCheck = report.checks.find(check => check.headerName === 'Strict-Transport-Security');
    const clearSiteDataCheck = report.checks.find(check => check.headerName === 'Clear-Site-Data');
    const deprecatedChecks = report.checks.filter(check => check.kind === 'deprecated');

    expect(report.summary.fail).toBe(0);
    expect(report.summary.warn).toBe(0);
    expect(hstsCheck?.status).toBe('pass');
    expect(clearSiteDataCheck?.status).toBe('pass');
    expect(deprecatedChecks.every(check => check.status === 'pass')).toBe(true);
  });

  test('flags failing OWASP Secure Headers checks and project advisories', () => {
    const primaryRequest = createRequest({
      responseHeaders: [
        { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
        { name: 'X-Frame-Options', value: 'SAMEORIGIN' },
        { name: 'X-Content-Type-Options', value: 'sniff' },
        { name: 'Content-Security-Policy', value: "default-src 'self' 'unsafe-inline'" },
        { name: 'X-Permitted-Cross-Domain-Policies', value: 'master-only' },
        { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { name: 'Cross-Origin-Embedder-Policy', value: 'unsafe-none' },
        { name: 'Cross-Origin-Opener-Policy', value: 'same-origin-allow-popups' },
        { name: 'Cross-Origin-Resource-Policy', value: 'same-site' },
        { name: 'Permissions-Policy', value: 'geolocation=()' },
        { name: 'Cache-Control', value: 'private, max-age=60' },
        { name: 'X-DNS-Prefetch-Control', value: 'on' },
        { name: 'Expect-CT', value: 'max-age=86400' },
        { name: 'Server', value: 'nginx/1.27.0' },
        { name: 'X-Powered-By', value: 'Express' },
      ],
    });

    const report = getOwaspHeaderAssessment('https://app.example.com/account', [primaryRequest]);
    const cspCheck = report.checks.find(check => check.headerName === 'Content-Security-Policy');
    const clearSiteDataCheck = report.checks.find(check => check.headerName === 'Clear-Site-Data');
    const expectCtCheck = report.checks.find(check => check.headerName === 'Expect-CT');
    const serverCheck = report.checks.find(check => check.headerName === 'Server');

    expect(report.summary.fail).toBeGreaterThan(0);
    expect(report.summary.warn).toBeGreaterThan(0);
    expect(cspCheck?.status).toBe('fail');
    expect(clearSiteDataCheck?.status).toBe('not-applicable');
    expect(expectCtCheck?.status).toBe('fail');
    expect(serverCheck?.status).toBe('warn');
  });
});