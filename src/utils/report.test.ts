import { describe, expect, test } from 'vitest';
import type { CachedRequest } from '../types';
import { buildAssessmentFindings, getOwaspHeaderAssessment } from './assessment';
import { buildTransportTlsSection } from './transportTls';
import { buildFullAssessmentReport, renderReportJson, renderReportMarkdown } from './report';

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

function createCookie(overrides: Partial<chrome.cookies.Cookie> = {}): chrome.cookies.Cookie {
  return {
    domain: 'app.example.com',
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

describe('unified assessment report', () => {
  const activeUrl = 'https://app.example.com/account';
  const requests = [createRequest()];
  const cookies = [createCookie()];

  function buildReport() {
    const headers = getOwaspHeaderAssessment(activeUrl, requests);
    const transport = buildTransportTlsSection({ activeUrl, requests, domObservation: null, storageScan: null });
    const findings = buildAssessmentFindings({ activeUrl, cookies, storageEntries: [], requests });
    return buildFullAssessmentReport({
      generatedAt: '2026-01-01T00:00:00.000Z',
      activeUrl,
      headers,
      transport,
      findings,
    });
  }

  test('markdown covers every category section and the limitations note', () => {
    const markdown = renderReportMarkdown(buildReport());

    expect(markdown).toContain('# OWASP Web Security Assessment');
    expect(markdown).toContain('## Summary');
    expect(markdown).toContain('## OWASP Secure Headers');
    expect(markdown).toContain('## Transport & TLS');
    expect(markdown).toContain('## Findings');
    expect(markdown).toContain('## Limitations');
    // An insecure session cookie should surface a finding in the report body.
    expect(markdown).toContain('Sensitive cookie without Secure');
  });

  test('severity counts are derived from the findings', () => {
    const report = buildReport();
    const total = report.severityCounts.high + report.severityCounts.medium + report.severityCounts.low + report.severityCounts.info;

    expect(total).toBe(report.findings.length);
    expect(report.severityCounts.high).toBeGreaterThan(0);
  });

  test('json export round-trips and preserves context', () => {
    const parsed = JSON.parse(renderReportJson(buildReport())) as { activeUrl: string; generatedAt: string; findings: unknown[] };

    expect(parsed.activeUrl).toBe(activeUrl);
    expect(parsed.generatedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(Array.isArray(parsed.findings)).toBe(true);
  });
});
