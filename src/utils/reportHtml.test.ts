import { describe, expect, test } from 'vitest';
import type {
  AssessmentFinding,
  CachedRequest,
  HeaderAssessmentCheck,
  HeaderAssessmentReport,
  TransportTlsCheck,
  TransportTlsReport,
} from '../types';
import { buildAssessmentFindings, getOwaspHeaderAssessment } from './assessment';
import { buildTransportTlsSection } from './transportTls';
import { buildFullAssessmentReport, type FullAssessmentReport } from './report';
import { escapeHtml, renderReportHtml } from './reportHtml';

// ── Factories ────────────────────────────────────────────────────────────────

function primaryRequest(): CachedRequest {
  return {
    method: 'GET',
    resourceType: 'main_frame',
    responseHeaders: [],
    statusCode: 200,
    timestamp: 0,
    url: 'https://app.example.com/account',
  };
}

function makeHeaderReport(overrides: Partial<HeaderAssessmentReport> = {}): HeaderAssessmentReport {
  return {
    activeUrl: 'https://app.example.com/account',
    primaryRequest: primaryRequest(),
    capturedRequestCount: 1,
    logoutRequestCount: 0,
    observedHeaderNames: [],
    checks: [],
    summary: { pass: 0, fail: 0, warn: 0, 'not-applicable': 0 },
    ...overrides,
  };
}

function makeHeaderCheck(overrides: Partial<HeaderAssessmentCheck> = {}): HeaderAssessmentCheck {
  return {
    id: 'h1',
    headerName: 'Content-Security-Policy',
    kind: 'required',
    status: 'fail',
    summary: 'Missing CSP.',
    expected: "default-src 'self'",
    observedValues: [],
    evidence: 'Not observed.',
    remediation: 'Add a CSP header.',
    source: 'project',
    ...overrides,
  };
}

function makeTransportReport(overrides: Partial<TransportTlsReport> = {}): TransportTlsReport {
  return {
    activeUrl: 'https://app.example.com/account',
    primaryHost: 'app.example.com',
    capturedRequestCount: 1,
    observedHttpRequestCount: 0,
    observedHttpsRequestCount: 1,
    domObservation: null,
    checks: [],
    summary: { pass: 1, fail: 0, warn: 0, inconclusive: 0 },
    overallStatus: 'pass',
    overview: 'Transport looks healthy.',
    coverage: 'partial',
    confidence: 'medium',
    ...overrides,
  };
}

function makeTransportCheck(overrides: Partial<TransportTlsCheck> = {}): TransportTlsCheck {
  return {
    id: 't1',
    theme: 'https-adoption',
    title: 'HTTPS adoption',
    status: 'pass',
    confidence: 'high',
    coverage: 'broad',
    summary: 'All requests used HTTPS.',
    observedFacts: [],
    assessment: 'Good.',
    guidance: [],
    evidenceRefs: [],
    ...overrides,
  };
}

function makeFinding(overrides: Partial<AssessmentFinding> = {}): AssessmentFinding {
  return {
    id: 'f1',
    category: 'headers',
    severity: 'high',
    title: 'A finding',
    summary: 'Something happened.',
    evidence: 'Some evidence.',
    remediation: 'Fix it.',
    ...overrides,
  };
}

function makeReport(overrides: Partial<FullAssessmentReport> = {}): FullAssessmentReport {
  const base = buildFullAssessmentReport({
    generatedAt: '2026-01-01T00:00:00.000Z',
    activeUrl: 'https://app.example.com/account',
    headers: makeHeaderReport(),
    transport: makeTransportReport(),
    findings: [],
  });
  return { ...base, ...overrides };
}

/** Count non-overlapping occurrences of `needle` in `haystack`. */
function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// ── escapeHtml unit table ─────────────────────────────────────────────────────

describe('escapeHtml', () => {
  test('escapes the five HTML-significant characters', () => {
    expect(escapeHtml('&')).toBe('&amp;');
    expect(escapeHtml('<')).toBe('&lt;');
    expect(escapeHtml('>')).toBe('&gt;');
    expect(escapeHtml('"')).toBe('&quot;');
    expect(escapeHtml("'")).toBe('&#39;');
  });

  test('ampersand is escaped once, not double-encoded', () => {
    expect(escapeHtml('a & b < c')).toBe('a &amp; b &lt; c');
    expect(escapeHtml('<b>')).toBe('&lt;b&gt;');
  });

  test('is a no-op on plain text and the empty string', () => {
    expect(escapeHtml('')).toBe('');
    expect(escapeHtml('plain ASCII text 123')).toBe('plain ASCII text 123');
  });
});

// ── Structure & self-containment ──────────────────────────────────────────────

describe('renderReportHtml — structure', () => {
  const activeUrl = 'https://app.example.com/account';
  const requests = [primaryRequest()];
  const cookies: chrome.cookies.Cookie[] = [{
    domain: 'app.example.com', hostOnly: true, httpOnly: false, name: 'session', path: '/',
    sameSite: 'unspecified', secure: false, session: true, storeId: '0', value: 'opaque-session-id',
  }];

  const realReport = buildFullAssessmentReport({
    generatedAt: '2026-01-01T00:00:00.000Z',
    activeUrl,
    headers: getOwaspHeaderAssessment(activeUrl, requests),
    transport: buildTransportTlsSection({ activeUrl, requests, domObservation: null, storageScan: null }),
    findings: buildAssessmentFindings({ activeUrl, cookies, storageEntries: [], requests }),
  });

  test('is a complete HTML document with charset and CSP meta', () => {
    const out = renderReportHtml(realReport);
    expect(out.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(out).toContain('<meta charset="utf-8">');
    expect(out).toContain(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">`);
    expect(out).toContain('</html>');
  });

  test('covers every section heading and the limitations note', () => {
    const out = renderReportHtml(realReport);
    expect(out).toContain('OWASP Web Security Assessment');
    expect(out).toContain('OWASP Secure Headers');
    expect(out).toContain('Transport &amp; TLS');
    expect(out).toContain('Findings');
    expect(out).toContain('Limitations');
    expect(out).toContain('This assessment is browser-side only.');
    // The seeded insecure session cookie surfaces a finding in the report body.
    expect(out).toContain('Sensitive cookie without Secure');
  });

  test('is self-contained: no scripts, event handlers, or external references', () => {
    const out = renderReportHtml(realReport);
    expect(out).not.toMatch(/<script/i);
    expect(out).not.toMatch(/\son\w+\s*=/i);   // no inline event handlers on benign data
    expect(out).not.toMatch(/href\s*=/i);
    expect(out).not.toMatch(/src\s*=/i);
    expect(out).not.toMatch(/<link/i);
    expect(out).not.toMatch(/@import/i);
    expect(out).not.toMatch(/url\(/i);
    expect(count(out, '<style>')).toBe(1);
  });

  test('renders a not-captured notice when no document response exists', () => {
    const out = renderReportHtml(makeReport({ headers: makeHeaderReport({ primaryRequest: null }) }));
    expect(out).toContain('No document response was captured');
  });

  test('renders an empty-state line when there are no findings', () => {
    const out = renderReportHtml(makeReport({ findings: [] }));
    expect(out).toContain('No cookie, token, storage, header, transport, or LLM/AI findings');
  });
});

// ── XSS vectors ───────────────────────────────────────────────────────────────

describe('renderReportHtml — injection safety', () => {
  test('escapes a script breakout in finding evidence', () => {
    const out = renderReportHtml(makeReport({
      findings: [makeFinding({ evidence: '</script><script>alert(1)</script>' })],
      severityCounts: { high: 1, medium: 0, low: 0, info: 0 },
    }));
    expect(out).not.toContain('<script');
    expect(out).toContain('&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  test('escapes an img/onerror payload in a finding title', () => {
    const out = renderReportHtml(makeReport({
      findings: [makeFinding({ title: '<img src=x onerror=alert(1)>' })],
      severityCounts: { high: 1, medium: 0, low: 0, info: 0 },
    }));
    expect(out).not.toContain('<img');
    expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  test('escapes an attribute breakout in a header observed value', () => {
    const out = renderReportHtml(makeReport({
      headers: makeHeaderReport({
        checks: [makeHeaderCheck({ observedValues: ['"><img src=x onerror=alert(1)>'] })],
        summary: { pass: 0, fail: 1, warn: 0, 'not-applicable': 0 },
      }),
    }));
    expect(out).not.toContain('<img');
    expect(out).not.toContain('"><img');
    expect(out).toContain('&quot;&gt;&lt;img');
  });

  test('does not turn a javascript: URL into a link', () => {
    const out = renderReportHtml(makeReport({ activeUrl: 'javascript:alert(1)' }));
    expect(out).not.toMatch(/href\s*=/i);
    expect(out).toContain('javascript:alert(1)'); // present, but as inert text only
  });

  test('escapes an SVG payload in the active URL', () => {
    const out = renderReportHtml(makeReport({ activeUrl: 'https://ex.com/?q=<svg onload=alert(1)>' }));
    expect(out).not.toContain('<svg');
    expect(out).toContain('&lt;svg onload=alert(1)&gt;');
  });

  test('escapes quotes, apostrophes, and ampersands in evidence', () => {
    const out = renderReportHtml(makeReport({
      findings: [makeFinding({ evidence: 'it\'s <b>bold</b> & "quoted"' })],
      severityCounts: { high: 1, medium: 0, low: 0, info: 0 },
    }));
    expect(out).not.toContain('<b>bold</b>');
    expect(out).toContain('&#39;');
    expect(out).toContain('&quot;');
    expect(out).toContain('&amp;');
    expect(out).toContain('&lt;b&gt;bold&lt;/b&gt;');
  });

  test('a style breakout in transport guidance cannot open a second style block', () => {
    const out = renderReportHtml(makeReport({
      transport: makeTransportReport({
        checks: [makeTransportCheck({ status: 'warn', guidance: ['</style><style>body{display:none}</style>'] })],
        summary: { pass: 0, fail: 0, warn: 1, inconclusive: 0 },
      }),
    }));
    expect(count(out, '<style>')).toBe(1);
    expect(count(out, '</style>')).toBe(1);
    expect(out).toContain('&lt;/style&gt;&lt;style&gt;');
  });
});
