import { describe, expect, test } from 'vitest';
import { buildReportFilename } from './exporter';

describe('buildReportFilename', () => {
  test('sanitizes the host and strips milliseconds/Z from the timestamp', () => {
    expect(buildReportFilename('app.example.com', '2026-07-03T14:32:15.123Z', 'md'))
      .toBe('owasp-assessment-app.example.com-2026-07-03T14-32-15.md');
  });

  test('falls back to unknown-host and keeps the extension', () => {
    expect(buildReportFilename('', '2026-07-03T14:32:15.000Z', 'json'))
      .toBe('owasp-assessment-unknown-host-2026-07-03T14-32-15.json');
  });

  test('replaces filesystem-unsafe characters in the host', () => {
    expect(buildReportFilename('foo/bar:8080', '2026-01-01T00:00:00.000Z', 'md'))
      .toBe('owasp-assessment-foo_bar_8080-2026-01-01T00-00-00.md');
  });
});
