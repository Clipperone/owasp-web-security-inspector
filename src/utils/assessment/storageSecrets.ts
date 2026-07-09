/**
 * Maps storage detection hits (secrets / PII found by `utils/detection`) to
 * OWASP-style assessment findings.
 *
 * Pure over the passed-in entries — no chrome APIs. Evidence uses only the
 * redacted `sample` carried on each hit, never a raw value. Finding IDs are
 * content-derived (`secret-<detectorId>-<area>-<key>`) so they are stable across
 * re-scans and future Snapshot Diff comparisons.
 */
import type {
  AssessmentFinding,
  DetectionCategory,
  DetectionHit,
  StorageEntry,
} from '../../types';

interface SecretMeta {
  title: string;
  summary: string;
  whyItMatters: string;
  remediation: string;
}

const CATEGORY_META: Record<DetectionCategory, SecretMeta> = {
  'private-key': {
    title: 'Private key exposed in web storage',
    summary: 'A PEM-encoded private key was found in browser storage.',
    whyItMatters: 'Private keys in client-reachable storage can be exfiltrated by any script running in the origin (e.g. via XSS) and used to impersonate the server, sign tokens, or decrypt traffic.',
    remediation: 'Never store private keys in the browser. Keep signing/decryption keys server-side and expose only short-lived, scoped tokens to the client.',
  },
  'api-key': {
    title: 'API key or provider secret in web storage',
    summary: 'A value matching a known API key / provider secret format was found in browser storage.',
    whyItMatters: 'Long-lived API keys reachable by page scripts can be stolen through XSS or malicious dependencies and reused from anywhere until manually rotated.',
    remediation: 'Move privileged API calls behind your backend, scope keys narrowly, and prefer short-lived tokens over static keys in the browser. Rotate any key that reached the client.',
  },
  'high-entropy-secret': {
    title: 'High-entropy secret in web storage',
    summary: 'A long, high-entropy string that looks like a secret was found in browser storage.',
    whyItMatters: 'Opaque high-entropy values are frequently credentials or bearer secrets; when readable by page scripts they are exposed to XSS-driven theft.',
    remediation: 'Confirm whether this value is a credential. If so, avoid persisting it in web storage; prefer HttpOnly cookies or short-lived in-memory tokens.',
  },
  'credential': {
    title: 'Embedded credentials in web storage',
    summary: 'A password or credential string was found inside a stored value.',
    whyItMatters: 'Plaintext credentials in web storage can be read by any script in the origin and leak through XSS, shared devices, or debugging tools.',
    remediation: 'Do not persist plaintext credentials in the browser. Exchange them for a session token at sign-in and discard the raw credential.',
  },
  'connection-string': {
    title: 'Database connection string with credentials in web storage',
    summary: 'A database connection string containing embedded credentials was found in browser storage.',
    whyItMatters: 'Connection strings expose host, database, and password; if they reach the browser they can be harvested and used to reach the backing datastore directly.',
    remediation: 'Connection strings belong only in server-side configuration. Remove them from client code and rotate the exposed credentials.',
  },
  'pii-email': {
    title: 'Email addresses stored in web storage',
    summary: 'One or more email addresses were found in browser storage.',
    whyItMatters: 'Personal data in web storage widens the blast radius of XSS and shared-device exposure and may carry data-protection (GDPR) obligations.',
    remediation: 'Store only the minimum personal data the client needs, and prefer opaque identifiers over raw PII where possible.',
  },
  'pii-card': {
    title: 'Payment card number in web storage',
    summary: 'A Luhn-valid payment card number was found in browser storage.',
    whyItMatters: 'Storing PANs in the browser is a serious exposure and typically breaches PCI DSS; the value is readable by any script in the origin.',
    remediation: 'Never store full card numbers client-side. Use a PCI-compliant processor and keep only tokens or the last four digits.',
  },
  'pii-phone': {
    title: 'Phone numbers stored in web storage',
    summary: 'One or more phone numbers were found in browser storage.',
    whyItMatters: 'Phone numbers are personal data; persisting them client-side widens exposure through XSS and shared devices.',
    remediation: 'Minimize personal data stored in the browser and prefer server-side storage with opaque client references.',
  },
  'pii-iban': {
    title: 'IBAN stored in web storage',
    summary: 'A checksum-valid IBAN was found in browser storage.',
    whyItMatters: 'Bank account identifiers are sensitive personal/financial data; client-side exposure invites fraud and data-protection issues.',
    remediation: 'Avoid persisting IBANs in the browser. Keep financial identifiers server-side and expose only masked or tokenized forms.',
  },
  'pii-codice-fiscale': {
    title: 'Italian tax code (Codice Fiscale) in web storage',
    summary: 'A checksum-valid Codice Fiscale was found in browser storage.',
    whyItMatters: 'National identifiers are sensitive personal data under GDPR; storing them client-side broadens their exposure.',
    remediation: 'Store national identifiers server-side only and keep the client footprint to opaque references.',
  },
  'eu-vat': {
    title: 'EU VAT number in web storage',
    summary: 'An EU VAT number was found in browser storage.',
    whyItMatters: 'VAT numbers are business identifiers and generally public, but their presence signals that business/customer records are cached client-side and worth reviewing.',
    remediation: 'Confirm the client genuinely needs this data cached; otherwise keep customer records server-side.',
  },
};

/** Number of entry keys to name in an aggregated PII finding. */
const MAX_AGGREGATE_KEYS = 5;

function secretFinding(
  id: string,
  severity: AssessmentFinding['severity'],
  meta: SecretMeta,
  evidence: string,
): AssessmentFinding {
  return {
    id,
    category: 'storage',
    severity,
    title: meta.title,
    summary: meta.summary,
    whyItMatters: meta.whyItMatters,
    evidence,
    remediation: meta.remediation,
  };
}

/** True for the low-noise categories aggregated into one finding per detector. */
function isAggregated(hit: DetectionHit): boolean {
  return hit.severity === 'low' || hit.severity === 'info';
}

export function assessStorageSecrets(entries: StorageEntry[]): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  const aggregates = new Map<string, { hit: DetectionHit; keys: string[] }>();

  for (const entry of entries) {
    if (!entry.detections || entry.detections.length === 0) continue;
    const entryLabel = `${entry.area}:${entry.key}`;

    for (const hit of entry.detections) {
      if (isAggregated(hit)) {
        const group = aggregates.get(hit.detectorId);
        if (group) group.keys.push(entryLabel);
        else aggregates.set(hit.detectorId, { hit, keys: [entryLabel] });
        continue;
      }

      const countSuffix = hit.matchCount > 1 ? ` (${hit.matchCount} matches)` : '';
      findings.push(secretFinding(
        `secret-${hit.detectorId}-${entry.area}-${entry.key}`,
        hit.severity,
        CATEGORY_META[hit.category],
        `${entryLabel} → ${hit.sample}${countSuffix}`,
      ));
    }
  }

  for (const [detectorId, group] of aggregates) {
    const { hit, keys } = group;
    const shown = keys.slice(0, MAX_AGGREGATE_KEYS).join(', ');
    const more = keys.length > MAX_AGGREGATE_KEYS ? `, +${keys.length - MAX_AGGREGATE_KEYS} more` : '';
    findings.push(secretFinding(
      `secret-${detectorId}-aggregate`,
      hit.severity,
      CATEGORY_META[hit.category],
      `Found in ${keys.length} storage ${keys.length === 1 ? 'entry' : 'entries'}: ${shown}${more}. Example: ${hit.sample}`,
    ));
  }

  return findings;
}
