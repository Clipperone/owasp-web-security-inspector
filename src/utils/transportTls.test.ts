import { describe, expect, test } from 'vitest';
import type { CachedRequest, TransportDomObservation } from '../types';
import { buildTransportTlsSection } from './transportTls';

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

function createDomObservation(overrides: Partial<TransportDomObservation> = {}): TransportDomObservation {
  return {
    pageUrl: 'https://app.example.com/account',
    scannedAt: new Date().toISOString(),
    absoluteHttpLinks: [],
    forms: [],
    passwordFieldCount: 0,
    ...overrides,
  };
}

describe('transportTls assessment', () => {
  test('reports good practice when the observed session is fully HTTPS', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'https://app.example.com/account',
      requests: [
        createRequest({
          url: 'https://app.example.com/account',
          responseHeaders: [
            { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          ],
        }),
        createRequest({
          resourceType: 'xmlhttprequest',
          url: 'https://app.example.com/api/profile',
        }),
      ],
      domObservation: createDomObservation(),
      storageScan: null,
    });

    expect(report.overallStatus).toBe('pass');
    expect(report.checks.find(check => check.theme === 'https-adoption')?.status).toBe('pass');
    expect(report.checks.find(check => check.theme === 'hsts')?.status).toBe('pass');
    expect(report.checks.find(check => check.theme === 'downgrade-signals')?.status).toBe('pass');
  });

  test('flags a login form over HTTP as a sensitive unencrypted flow', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'http://app.example.com/login',
      requests: [
        createRequest({
          url: 'http://app.example.com/login',
        }),
      ],
      domObservation: createDomObservation({
        pageUrl: 'http://app.example.com/login',
        forms: [
          {
            action: 'http://app.example.com/login',
            method: 'POST',
            hasPasswordField: true,
            passwordFieldCount: 1,
            sensitiveFieldNames: ['username', 'password'],
          },
        ],
        passwordFieldCount: 1,
      }),
      storageScan: null,
    });

    expect(report.checks.find(check => check.theme === 'sensitive-flows')?.status).toBe('fail');
    expect(report.checks.find(check => check.theme === 'https-adoption')?.status).toBe('fail');
  });

  test('masks token values observed in HTTP query strings', () => {
    const rawToken = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const report = buildTransportTlsSection({
      activeUrl: 'http://app.example.com/callback',
      requests: [
        createRequest({
          url: `http://app.example.com/callback?access_token=${rawToken}`,
          resourceType: 'xmlhttprequest',
        }),
      ],
      domObservation: createDomObservation({ pageUrl: 'http://app.example.com/callback' }),
      storageScan: null,
    });

    const sensitiveCheck = report.checks.find(check => check.theme === 'sensitive-flows');

    expect(sensitiveCheck?.status).toBe('fail');
    expect(sensitiveCheck?.evidenceRefs[0]?.detail).not.toContain(rawToken);
    expect(sensitiveCheck?.evidenceRefs[0]?.detail).toContain('abcd***89');
  });

  test('marks HSTS as warn when present but incomplete', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'https://app.example.com/home',
      requests: [
        createRequest({
          url: 'https://app.example.com/home',
          responseHeaders: [
            { name: 'Strict-Transport-Security', value: 'max-age=86400' },
          ],
        }),
      ],
      domObservation: createDomObservation(),
      storageScan: null,
    });

    expect(report.checks.find(check => check.theme === 'hsts')?.status).toBe('warn');
  });

  test('marks HSTS as fail when HTTPS responses omit it', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'https://app.example.com/home',
      requests: [
        createRequest({
          url: 'https://app.example.com/home',
        }),
      ],
      domObservation: createDomObservation(),
      storageScan: null,
    });

    expect(report.checks.find(check => check.theme === 'hsts')?.status).toBe('fail');
  });

  test('returns inconclusive when only partial evidence is available', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'https://app.example.com/home',
      requests: [],
      domObservation: null,
      storageScan: null,
    });

    expect(report.overallStatus).toBe('inconclusive');
    expect(report.checks).toHaveLength(4);
    expect(report.summary.inconclusive).toBe(4);
  });

  test('detects downgrade signals from HTTPS pages with HTTP references', () => {
    const report = buildTransportTlsSection({
      activeUrl: 'https://app.example.com/home',
      requests: [
        createRequest({
          url: 'https://app.example.com/home',
          responseHeaders: [
            { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          ],
        }),
        createRequest({
          resourceType: 'xmlhttprequest',
          url: 'http://app.example.com/api/legacy',
        }),
      ],
      domObservation: createDomObservation({
        absoluteHttpLinks: ['http://app.example.com/help'],
        forms: [
          {
            action: 'http://app.example.com/search',
            method: 'GET',
            hasPasswordField: false,
            passwordFieldCount: 0,
            sensitiveFieldNames: ['query'],
          },
        ],
      }),
      storageScan: null,
    });

    expect(report.checks.find(check => check.theme === 'downgrade-signals')?.status).toBe('fail');
  });
});