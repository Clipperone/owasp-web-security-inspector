import type {
  CachedRequest,
  StorageScanResult,
  TransportDomObservation,
  TransportTlsCheck,
  TransportTlsConfidence,
  TransportTlsCoverage,
  TransportTlsEvidenceKind,
  TransportTlsEvidenceReference,
  TransportTlsReport,
  TransportTlsStatus,
} from '../../types';

export interface TransportTlsInputs {
  activeUrl: string;
  requests: CachedRequest[];
  domObservation: TransportDomObservation | null;
  storageScan?: StorageScanResult | null;
}

const SENSITIVE_QUERY_NAME_RE = /(token|access|refresh|reset|session|auth|bearer|secret|api[_-]?key|code|password)/i;

export function buildTransportCheck(check: TransportTlsCheck): TransportTlsCheck {
  return check;
}

export function buildEvidence(kind: TransportTlsEvidenceKind, label: string, detail: string): TransportTlsEvidenceReference {
  return { kind, label, detail };
}

export function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

export function isHttpsUrl(url: string): boolean {
  return url.startsWith('https://');
}

export function isHttpUrl(url: string): boolean {
  return url.startsWith('http://');
}

export function sameHostname(url: string, expectedHost: string): boolean {
  return hostnameFromUrl(url) === expectedHost;
}

export function getHeaderValues(request: CachedRequest, name: string): string[] {
  const expected = name.toLowerCase();
  return request.responseHeaders
    .filter(header => header.name.toLowerCase() === expected)
    .map(header => header.value);
}

export function getFirstHeaderValue(request: CachedRequest, name: string): string | undefined {
  return getHeaderValues(request, name)[0];
}

export function formatUrlForEvidence(url: string): string {
  try {
    const parsed = new URL(url);
    for (const [key, value] of parsed.searchParams.entries()) {
      if (SENSITIVE_QUERY_NAME_RE.test(key) || looksSecretLike(value)) {
        parsed.searchParams.set(key, maskSensitiveValue(value));
      }
    }
    return parsed.toString();
  } catch {
    return url;
  }
}

export function maskSensitiveValue(value: string): string {
  if (value.length <= 4) return '*'.repeat(Math.max(value.length, 3));
  if (value.length <= 10) return `${value.slice(0, 2)}***${value.slice(-1)}`;
  return `${value.slice(0, 4)}***${value.slice(-2)}`;
}

export function looksSensitiveQueryParam(name: string, value: string): boolean {
  return SENSITIVE_QUERY_NAME_RE.test(name) || looksSecretLike(value);
}

export function looksSecretLike(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 12) return false;
  if (/^Bearer\s+[A-Za-z0-9\-._~+/]+=*$/i.test(trimmed)) return true;
  if (/^[A-Za-z0-9\-._~+/]+=*$/.test(trimmed) && trimmed.length >= 24) return true;
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(trimmed);
}

export function summarizeChecks(checks: TransportTlsCheck[]): Record<TransportTlsStatus, number> {
  return checks.reduce<Record<TransportTlsStatus, number>>((acc, check) => {
    acc[check.status] += 1;
    return acc;
  }, {
    pass: 0,
    fail: 0,
    warn: 0,
    inconclusive: 0,
  });
}

export function deriveOverallStatus(checks: TransportTlsCheck[]): TransportTlsStatus {
  if (checks.some(check => check.status === 'fail')) return 'fail';
  if (checks.some(check => check.status === 'warn')) return 'warn';
  if (checks.some(check => check.status === 'pass')) return 'pass';
  return 'inconclusive';
}

export function deriveOverallCoverage(checks: TransportTlsCheck[]): TransportTlsCoverage {
  if (checks.some(check => check.coverage === 'limited')) return 'limited';
  if (checks.some(check => check.coverage === 'partial')) return 'partial';
  return 'broad';
}

export function deriveOverallConfidence(checks: TransportTlsCheck[]): TransportTlsConfidence {
  if (checks.some(check => check.confidence === 'low')) return 'low';
  if (checks.some(check => check.confidence === 'medium')) return 'medium';
  return 'high';
}

export function buildOverview(summary: Record<TransportTlsStatus, number>): string {
  if (summary.fail > 0) {
    return 'Potential transport weaknesses were observed in the current session. Review insecure flows, downgrade signals, and missing transport protections.';
  }
  if (summary.warn > 0) {
    return 'The observed session shows mixed or incomplete transport signals. Review the warning areas before treating the transport posture as strong.';
  }
  if (summary.pass > 0) {
    return 'Observed good practice across the current session, with no transport weakness detected from the passive evidence collected here.';
  }
  return 'Inconclusive due to limited evidence. The current session does not expose enough browser-visible transport data to support a stronger conclusion.';
}

export function emptyTransportReport(activeUrl: string): TransportTlsReport {
  return {
    activeUrl,
    primaryHost: hostnameFromUrl(activeUrl),
    capturedRequestCount: 0,
    observedHttpRequestCount: 0,
    observedHttpsRequestCount: 0,
    domObservation: null,
    checks: [],
    summary: {
      pass: 0,
      fail: 0,
      warn: 0,
      inconclusive: 0,
    },
    overallStatus: 'inconclusive',
    overview: 'Inconclusive due to limited evidence. No transport observations were available for the active tab.',
    coverage: 'limited',
    confidence: 'low',
  };
}