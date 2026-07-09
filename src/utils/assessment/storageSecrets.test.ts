import { describe, expect, test } from 'vitest';
import type { DetectionHit, StorageEntry } from '../../types';
import { assessStorageSecrets } from './storageSecrets';

function entry(overrides: Partial<StorageEntry> & { detections: DetectionHit[] }): StorageEntry {
  return {
    area: 'localStorage',
    key: 'k',
    value: '[redacted]',
    hints: [],
    isJwt: false,
    ...overrides,
  };
}

function hit(overrides: Partial<DetectionHit> = {}): DetectionHit {
  return {
    detectorId: 'aws-access-key-id',
    category: 'api-key',
    severity: 'high',
    sample: 'AKIA…MPLE',
    matchCount: 1,
    validated: true,
    ...overrides,
  };
}

describe('assessStorageSecrets', () => {
  test('raises one finding per (entry, detector) for high-severity hits', () => {
    const findings = assessStorageSecrets([
      entry({ area: 'localStorage', key: 'aws', detections: [hit()] }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('storage');
    expect(findings[0].id).toBe('secret-aws-access-key-id-localStorage-aws');
    expect(findings[0].evidence).toContain('AKIA…MPLE');
  });

  test('finding IDs are content-derived and stable across re-scans', () => {
    const input = [entry({ area: 'sessionStorage', key: 'tok', detections: [hit()] })];
    expect(assessStorageSecrets(input)[0].id).toBe(assessStorageSecrets(input)[0].id);
    expect(assessStorageSecrets(input)[0].id).toBe('secret-aws-access-key-id-sessionStorage-tok');
  });

  test('aggregates low/info PII into a single finding per detector', () => {
    const emailHit = hit({ detectorId: 'pii-email', category: 'pii-email', severity: 'low', sample: 'a…@example.com' });
    const findings = assessStorageSecrets([
      entry({ key: 'profile', detections: [emailHit] }),
      entry({ key: 'contacts', detections: [emailHit] }),
      entry({ key: 'backup', detections: [emailHit] }),
    ]);
    const emailFindings = findings.filter(f => f.id.startsWith('secret-pii-email'));
    expect(emailFindings).toHaveLength(1);
    expect(emailFindings[0].id).toBe('secret-pii-email-aggregate');
    expect(emailFindings[0].evidence).toContain('Found in 3 storage entries');
    expect(emailFindings[0].evidence).toContain('localStorage:profile');
  });

  test('caps the number of named keys in an aggregate finding', () => {
    const emailHit = hit({ detectorId: 'pii-email', category: 'pii-email', severity: 'low', sample: 'a…@x.com' });
    const entries = Array.from({ length: 8 }, (_, i) => entry({ key: `k${i}`, detections: [emailHit] }));
    const finding = assessStorageSecrets(entries).find(f => f.id === 'secret-pii-email-aggregate');
    expect(finding?.evidence).toContain('Found in 8 storage entries');
    expect(finding?.evidence).toContain('+3 more');
  });

  test('ignores entries without detections', () => {
    expect(assessStorageSecrets([{ area: 'localStorage', key: 'k', value: 'v', hints: ['key-name'], isJwt: false }])).toEqual([]);
  });

  test('every finding carries whyItMatters and a remediation', () => {
    const findings = assessStorageSecrets([
      entry({ key: 'pk', detections: [hit({ detectorId: 'pem-private-key', category: 'private-key', sample: '[redacted, 1700 chars]' })] }),
    ]);
    expect(findings[0].whyItMatters).toBeTruthy();
    expect(findings[0].remediation).toBeTruthy();
  });
});
