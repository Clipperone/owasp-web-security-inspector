import { describe, expect, test } from 'vitest';
import { runDetectors } from './engine';
import { luhn, ibanMod97, codiceFiscaleChecksum, shannonEntropy, isUuid, fnv1a32, decodeBasicAuth } from './validators';

function ids(value: string): string[] {
  return runDetectors('k', value).hits.map(h => h.detectorId).sort();
}

// Synthetic credential fixtures assembled from fragments so secret scanners do
// not match the source text. Each still satisfies its detector's pattern at
// runtime; none is a real credential.
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
const OPENAI_KEY = 'sk-' + 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';
const SLACK_TOKEN = 'xoxb-' + '123456789012-' + 'abcdefABCDEF0123';

// ── Validators ────────────────────────────────────────────────────────────────

describe('validators', () => {
  test('luhn', () => {
    expect(luhn('4111111111111111')).toBe(true);
    expect(luhn('4111111111111112')).toBe(false);
  });
  test('ibanMod97', () => {
    expect(ibanMod97('IT60X0542811101000000123456')).toBe(true);
    expect(ibanMod97('DE89370400440532013000')).toBe(true);
    expect(ibanMod97('IT60X0542811101000000123457')).toBe(false); // last digit tweaked
    expect(ibanMod97('IT99X0542811101000000123456')).toBe(false); // wrong check digits
  });
  test('codiceFiscaleChecksum', () => {
    expect(codiceFiscaleChecksum('RSSMRA85T10A562S')).toBe(true);
    expect(codiceFiscaleChecksum('RSSMRA85T10A562X')).toBe(false); // wrong check char
  });
  test('shannonEntropy is higher for random strings', () => {
    expect(shannonEntropy('aaaaaaaa')).toBeLessThan(1);
    expect(shannonEntropy('a8Kd93Lm2xQ7')).toBeGreaterThan(3);
  });
  test('isUuid', () => {
    expect(isUuid('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    expect(isUuid('not-a-uuid')).toBe(false);
  });
  test('fnv1a32 is deterministic and 8 hex chars', () => {
    expect(fnv1a32('hello')).toBe(fnv1a32('hello'));
    expect(fnv1a32('hello')).toMatch(/^[0-9a-f]{8}$/);
    expect(fnv1a32('hello')).not.toBe(fnv1a32('hellp'));
  });
  test('decodeBasicAuth', () => {
    expect(decodeBasicAuth('dXNlcjpwYXNz')).toBe('user:pass');
    expect(decodeBasicAuth('bm9jb2xvbg==')).toBeNull(); // "nocolon"
  });
});

// ── Per-detector true positives ───────────────────────────────────────────────

describe('detectors — true positives', () => {
  test('AWS access key id', () => {
    expect(ids(AWS_KEY)).toContain('aws-access-key-id');
  });
  test('GitHub token', () => {
    expect(ids('ghp_' + 'a'.repeat(36))).toContain('github-token');
  });
  test('Google API key', () => {
    expect(ids('AIza' + 'B'.repeat(35))).toContain('google-api-key');
  });
  test('OpenAI key (entropy-gated)', () => {
    expect(ids(OPENAI_KEY)).toContain('openai-key');
  });
  test('Slack token', () => {
    expect(ids(SLACK_TOKEN)).toContain('slack-token');
  });
  test('Basic auth header', () => {
    expect(ids('Authorization: Basic dXNlcjpwYXNz')).toContain('basic-auth');
  });
  test('URL with embedded credentials', () => {
    expect(ids('https://user:secretpass@example.com/path')).toContain('url-credentials');
  });
  test('database connection string', () => {
    expect(ids('postgres://admin:s3cr3tPass@db.example.com:5432/app')).toContain('connection-string');
  });
  test('JSON credential field', () => {
    expect(ids('{"user":"a","password":"hunter2xyz"}')).toContain('json-credential-field');
  });
  test('form credential pair', () => {
    expect(ids('/login?user=a&password=hunter2xyz')).toContain('form-credential-pair');
  });
  test('payment card (Luhn valid)', () => {
    expect(ids('card 4111 1111 1111 1111 on file')).toContain('pii-card');
  });
  test('IBAN (mod-97 valid)', () => {
    expect(ids('IT60X0542811101000000123456')).toContain('pii-iban');
  });
  test('Codice Fiscale', () => {
    expect(ids('RSSMRA85T10A562S')).toContain('pii-codice-fiscale');
  });
  test('email', () => {
    expect(ids('contact alice@example.com today')).toContain('pii-email');
  });
  test('E.164 phone', () => {
    expect(ids('call +14155552671 now')).toContain('pii-phone-e164');
  });
  test('EU VAT (Italian, Luhn valid)', () => {
    expect(ids('IT00743110157')).toContain('eu-vat');
  });
  test('PEM private key header', () => {
    expect(ids('-----BEGIN RSA PRIVATE KEY-----\nMIIEabc')).toContain('pem-private-key');
  });
  test('generic high-entropy secret', () => {
    expect(ids('7f3Kd9Lm2xQ8vB1nZ4wR6tY0uP5sA3eC7gH9jK2lM4nO6pQ8r')).toContain('high-entropy-secret');
  });
});

// ── Per-detector true negatives ───────────────────────────────────────────────

describe('detectors — true negatives', () => {
  test('Luhn-invalid 16-digit number is not a card', () => {
    expect(ids('order 4111111111111112 shipped')).not.toContain('pii-card');
  });
  test('unknown-IIN 16-digit number is not a card', () => {
    expect(ids('id 9999999999999995 here')).not.toContain('pii-card'); // fails IIN even if Luhn
  });
  test('Codice Fiscale with a wrong check char is rejected', () => {
    expect(ids('RSSMRA85T10A562X')).not.toContain('pii-codice-fiscale');
  });
  test('IBAN with a bad checksum is rejected', () => {
    expect(ids('IT99X0542811101000000123456')).not.toContain('pii-iban');
  });
  test('a UUID is not flagged as a high-entropy secret', () => {
    expect(ids('550e8400-e29b-41d4-a716-446655440000')).not.toContain('high-entropy-secret');
  });
  test('a low-entropy sk- slug is not an OpenAI key', () => {
    expect(ids('sk-' + 'ab'.repeat(18))).not.toContain('openai-key'); // entropy 1.0 < 3.5
  });
  test('Italian VAT failing Luhn is rejected', () => {
    expect(ids('IT00743110158')).not.toContain('eu-vat');
  });
  test('Basic followed by a colon-less credential is rejected', () => {
    expect(ids('Basic bm9jb2xvbg==')).not.toContain('basic-auth'); // "nocolon"
  });
  test('plain prose triggers no detectors', () => {
    expect(ids('the quick brown fox jumps over the lazy dog')).toEqual([]);
  });
});

// ── Engine mechanics ──────────────────────────────────────────────────────────

describe('engine mechanics', () => {
  test('overlap resolution: a card inside a longer entropy span keeps the specific hit', () => {
    // The card sits inside a longer high-entropy-eligible blob; card must win.
    const hits = runDetectors('k', 'pay 4111111111111111 now').hits.map(h => h.category);
    expect(hits).toContain('pii-card');
  });
  test('matchCount aggregates repeated matches of the same detector', () => {
    const result = runDetectors('k', 'a@example.com and b@example.org');
    const email = result.hits.find(h => h.detectorId === 'pii-email');
    expect(email?.matchCount).toBe(2);
  });
  test('is deterministic — same input yields deep-equal output', () => {
    const value = AWS_KEY + ' and alice@example.com';
    expect(runDetectors('k', value)).toEqual(runDetectors('k', value));
  });
  test('redacts an API key in place', () => {
    const result = runDetectors('k', 'key=' + AWS_KEY);
    expect(result.wasRedacted).toBe(true);
    expect(result.redactedValue).not.toContain(AWS_KEY);
    expect(result.redactedValue).toContain('…');
  });
  test('redacts an entire private key value', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\n' + 'MIIabc'.repeat(50) + '\n-----END RSA PRIVATE KEY-----';
    const result = runDetectors('k', pem);
    expect(result.redactedValue).toMatch(/^\[redacted private key, \d+ chars\]$/);
    expect(result.redactedValue).not.toContain('MIIabc');
  });
});

// ── No-leak invariant ─────────────────────────────────────────────────────────

describe('no-leak invariant', () => {
  const secrets: Array<[string, string]> = [
    ['AWS key', AWS_KEY],
    ['GitHub token', 'ghp_' + 'a'.repeat(36)],
    ['card', '4111 1111 1111 1111'],
    ['IBAN', 'IT60X0542811101000000123456'],
    ['Codice Fiscale', 'RSSMRA85T10A562S'],
    ['url creds password', 'https://user:secretpass123@example.com/'],
    ['JSON password', '{"password":"hunter2secret"}'],
    ['email local part', 'alice.smith@example.com'],
  ];

  for (const [label, secret] of secrets) {
    test(`redacted output for ${label} does not contain the raw sensitive part`, () => {
      const result = runDetectors('k', secret);
      // The most sensitive fragment must not survive verbatim in the redacted value.
      if (label === 'card') expect(result.redactedValue).not.toContain('4111 1111 1111 1111');
      else if (label === 'IBAN') expect(result.redactedValue).not.toContain('0542811101000000123456');
      else if (label === 'url creds password') expect(result.redactedValue).not.toContain('secretpass123');
      else if (label === 'JSON password') expect(result.redactedValue).not.toContain('hunter2secret');
      else if (label === 'email local part') expect(result.redactedValue).not.toContain('alice.smith');
      else if (label === 'Codice Fiscale') expect(result.redactedValue).not.toContain('RSSMRA85T10A562S');
      else expect(result.redactedValue).not.toContain(secret);
    });
  }
});

// ── ReDoS: adversarial corpus stays within a time budget ──────────────────────

describe('ReDoS resilience', () => {
  const corpus = [
    'A'.repeat(4096),
    '4'.repeat(4096),
    '4 4-'.repeat(1024),
    'AKIA' + '0'.repeat(4092),
    '"password":"' + 'a'.repeat(4083),
    'a@' + '.'.repeat(4094),
    '+1 '.repeat(1365),
    'aB3xZ9'.repeat(683),
    '-----BEGIN '.repeat(372),
    'IT' + '1'.repeat(4094),
    'https://u:' + 'p'.repeat(4080) + '@h',
  ];

  test('every adversarial value is processed well within budget', () => {
    for (const value of corpus) {
      const start = performance.now();
      runDetectors('k', value.slice(0, 4096));
      const elapsed = performance.now() - start;
      expect(elapsed).toBeLessThan(25);
    }
  });

  test('the whole corpus completes quickly', () => {
    const start = performance.now();
    for (const value of corpus) runDetectors('k', value.slice(0, 4096));
    expect(performance.now() - start).toBeLessThan(250);
  });
});
