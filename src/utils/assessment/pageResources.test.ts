import { describe, expect, test } from 'vitest';
import type {
  CachedRequest,
  ObservedPageResource,
  ObservedWebSocket,
  PageResourceObservation,
  TransportDomObservation,
  TransportObservedForm,
} from '../../types';
import {
  assessMixedContent,
  assessSubresourceIntegrity,
  assessThirdParties,
  assessWebSockets,
} from './pageResources';
import { detectDowngradeSignals } from '../transportTls/detectors';

// ── Fixtures ─────────────────────────────────────────────────────────────────

function resource(overrides: Partial<ObservedPageResource> = {}): ObservedPageResource {
  return {
    url: 'https://cdn.other.com/lib.js',
    kind: 'script',
    crossOrigin: true,
    hasIntegrity: false,
    ...overrides,
  };
}

function pageResources(overrides: Partial<PageResourceObservation> = {}): PageResourceObservation {
  return {
    pageUrl: 'https://app.example.com/',
    scannedAt: '2026-01-01T00:00:00.000Z',
    scripts: [],
    stylesheets: [],
    truncated: false,
    ...overrides,
  };
}

function form(overrides: Partial<TransportObservedForm> = {}): TransportObservedForm {
  return {
    action: 'https://app.example.com/login',
    method: 'POST',
    hasPasswordField: true,
    passwordFieldCount: 1,
    sensitiveFieldNames: ['password'],
    ...overrides,
  };
}

function dom(overrides: Partial<TransportDomObservation> = {}): TransportDomObservation {
  return {
    pageUrl: 'https://app.example.com/',
    scannedAt: '2026-01-01T00:00:00.000Z',
    absoluteHttpLinks: [],
    forms: [],
    passwordFieldCount: 0,
    ...overrides,
  };
}

function request(url: string): CachedRequest {
  return { method: 'GET', resourceType: 'xmlhttprequest', responseHeaders: [], statusCode: 200, timestamp: 0, url };
}

function ws(url: string): ObservedWebSocket {
  return { url, secure: url.startsWith('wss://'), timestamp: 0 };
}

// ── Subresource Integrity ────────────────────────────────────────────────────

describe('assessSubresourceIntegrity', () => {
  test('flags a cross-origin script without integrity (medium)', () => {
    const findings = assessSubresourceIntegrity(pageResources({ scripts: [resource()] }));
    expect(findings.map(f => f.title)).toContain('Cross-origin script without Subresource Integrity');
    expect(findings[0]?.severity).toBe('medium');
  });

  test('ignores same-origin resources', () => {
    const findings = assessSubresourceIntegrity(pageResources({
      scripts: [resource({ url: 'https://app.example.com/app.js', crossOrigin: false })],
    }));
    expect(findings).toHaveLength(0);
  });

  test('ignores cross-origin resources that already declare integrity', () => {
    const findings = assessSubresourceIntegrity(pageResources({
      scripts: [resource({ hasIntegrity: true, integrityValid: true })],
    }));
    expect(findings).toHaveLength(0);
  });

  test('flags a cross-origin stylesheet without integrity (low)', () => {
    const findings = assessSubresourceIntegrity(pageResources({
      stylesheets: [resource({ kind: 'stylesheet', url: 'https://cdn.other.com/x.css' })],
    }));
    expect(findings[0]?.title).toBe('Cross-origin stylesheet without Subresource Integrity');
    expect(findings[0]?.severity).toBe('low');
  });

  test('flags a malformed integrity attribute (low)', () => {
    const findings = assessSubresourceIntegrity(pageResources({
      scripts: [resource({ hasIntegrity: true, integrityValid: false })],
    }));
    expect(findings[0]?.title).toBe('Subresource integrity attribute is malformed');
  });

  test('returns nothing when no observation is available', () => {
    expect(assessSubresourceIntegrity(null)).toHaveLength(0);
  });
});

// ── Third-party inventory ─────────────────────────────────────────────────────

describe('assessThirdParties', () => {
  const url = 'https://app.example.com/account';

  test('groups same-site subdomains and flags third-party origins', () => {
    const findings = assessThirdParties(url, [
      request('https://cdn.example.com/lib.js'),
      request('https://analytics.google.com/collect'),
    ], []);
    const titles = findings.map(f => `${f.title}:${f.evidence}`);
    expect(titles.some(t => t.includes('analytics.google.com'))).toBe(true);
    expect(titles.some(t => t.includes('cdn.example.com'))).toBe(false);
  });

  test('handles two-level public suffixes correctly', () => {
    const findings = assessThirdParties('https://shop.example.co.uk/', [
      request('https://cdn.example.co.uk/lib.js'),
      request('https://tracker.other.co.uk/px'),
    ], []);
    const evidence = findings.map(f => f.evidence).join('\n');
    expect(evidence).toContain('tracker.other.co.uk');
    expect(evidence).not.toContain('cdn.example.co.uk');
  });

  test('flags third-party cookies', () => {
    const cookie = { name: 'id', domain: '.doubleclick.net' } as chrome.cookies.Cookie;
    const findings = assessThirdParties(url, [], [cookie]);
    expect(findings.map(f => f.title)).toContain('Third-party cookie present');
    expect(findings.every(f => f.severity === 'info')).toBe(true);
  });
});

// ── WebSockets ─────────────────────────────────────────────────────────────────

describe('assessWebSockets', () => {
  test('flags ws:// from an HTTPS page as high and adds an inventory info', () => {
    const findings = assessWebSockets('https://app.example.com/', [ws('ws://app.example.com/live')]);
    const titles = findings.map(f => f.title);
    expect(titles).toContain('Insecure WebSocket (ws://) from an HTTPS page');
    expect(titles).toContain('WebSocket connections observed');
    expect(findings.find(f => f.title.startsWith('Insecure'))?.severity).toBe('high');
  });

  test('does not flag wss:// as insecure', () => {
    const findings = assessWebSockets('https://app.example.com/', [ws('wss://app.example.com/live')]);
    expect(findings.map(f => f.title)).not.toContain('Insecure WebSocket (ws://) from an HTTPS page');
    expect(findings).toHaveLength(1);
  });

  test('returns nothing when no sockets were observed', () => {
    expect(assessWebSockets('https://app.example.com/', [])).toHaveLength(0);
  });
});

// ── Mixed content / insecure forms ─────────────────────────────────────────────

describe('assessMixedContent', () => {
  const url = 'https://app.example.com/login';

  test('flags a sensitive form submitting over HTTP', () => {
    const inputs = { activeUrl: url, requests: [], domObservation: dom({ forms: [form({ action: 'http://app.example.com/login' })] }) };
    const findings = assessMixedContent(url, inputs.requests, null, inputs.domObservation);
    expect(findings.map(f => f.title)).toContain('Sensitive form submits over HTTP');
    // Consistency: the shared downgrade helper must not report "pass" for the same inputs.
    expect(detectDowngradeSignals(inputs).status).not.toBe('pass');
  });

  test('flags absolute HTTP links as passive mixed content', () => {
    const inputs = { activeUrl: url, requests: [], domObservation: dom({ absoluteHttpLinks: ['http://tracker.example/px'] }) };
    const findings = assessMixedContent(url, inputs.requests, null, inputs.domObservation);
    expect(findings.map(f => f.title)).toContain('HTTP references from an HTTPS page');
    expect(detectDowngradeSignals(inputs).status).not.toBe('pass');
  });

  test('flags an HTTP cross-origin script as active mixed content', () => {
    const findings = assessMixedContent(url, [], pageResources({
      scripts: [resource({ url: 'http://cdn.other.com/lib.js' })],
    }), null);
    expect(findings.map(f => f.title)).toContain('Active mixed content on an HTTPS page');
    expect(findings.find(f => f.title.startsWith('Active'))?.severity).toBe('high');
  });

  test('raises nothing for an all-HTTPS page', () => {
    const findings = assessMixedContent(url, [request('https://api.example.com/x')], pageResources(), dom());
    expect(findings).toHaveLength(0);
  });

  test('returns nothing when the page is not HTTPS', () => {
    const findings = assessMixedContent('http://app.example.com/', [], null, dom({ pageUrl: 'http://app.example.com/' }));
    expect(findings).toHaveLength(0);
  });
});
