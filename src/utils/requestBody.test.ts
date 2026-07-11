import { describe, expect, test } from 'vitest';
import {
  MAX_SNIPPET_LENGTH,
  buildCapturedRequestBody,
  decodeRequestBody,
  detectSystemPrompt,
} from './requestBody';

// Synthetic key assembled from fragments so scanners don't match the source.
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

function rawBodyFrom(text: string): chrome.webRequest.OnBeforeRequestDetails['requestBody'] {
  return { raw: [{ bytes: new TextEncoder().encode(text).buffer as ArrayBuffer }] };
}

describe('decodeRequestBody', () => {
  test('decodes raw UTF-8 bytes (JSON prompt body)', () => {
    const json = '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}';
    expect(decodeRequestBody(rawBodyFrom(json))).toBe(json);
  });

  test('serializes formData bodies', () => {
    const decoded = decodeRequestBody({ formData: { prompt: ['hello'], model: ['gpt-4'] } });
    expect(decoded).toContain('prompt=hello');
    expect(decoded).toContain('model=gpt-4');
  });

  test('returns null for an absent or empty body', () => {
    expect(decodeRequestBody(undefined)).toBeNull();
    expect(decodeRequestBody({})).toBeNull();
    expect(decodeRequestBody({ raw: [] })).toBeNull();
  });
});

describe('detectSystemPrompt', () => {
  test('flags a chat message with role system', () => {
    expect(detectSystemPrompt('{"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hi"}]}')).toBe(true);
  });
  test('flags a chat message with role developer', () => {
    expect(detectSystemPrompt('{"messages":[{"role":"developer","content":"rules"}]}')).toBe(true);
  });
  test('flags a top-level system field (Anthropic style)', () => {
    expect(detectSystemPrompt('{"system":"You are a helpful assistant","messages":[]}')).toBe(true);
  });
  test('flags a top-level instructions field', () => {
    expect(detectSystemPrompt('{"instructions":"follow the policy"}')).toBe(true);
  });
  test('does not flag a user-only payload', () => {
    expect(detectSystemPrompt('{"messages":[{"role":"user","content":"hi"}]}')).toBe(false);
  });
  test('falls back to a string test when the body is not valid JSON (e.g. truncated)', () => {
    expect(detectSystemPrompt('...{"role":"system","content":"be ter')).toBe(true);
    expect(detectSystemPrompt('plain text with no roles')).toBe(false);
  });
});

describe('buildCapturedRequestBody — redaction invariant', () => {
  test('a secret in the body is detected but never survives in the clear', () => {
    const rawBody = `{"messages":[{"role":"user","content":"my key is ${AWS_KEY}"}]}`;
    const entry = buildCapturedRequestBody({ url: 'https://api.openai.com/v1/chat/completions', method: 'POST', rawBody, timestamp: 123 });

    expect(entry.detections?.some(hit => hit.detectorId === 'aws-access-key-id')).toBe(true);
    expect(entry.redactedSnippet).not.toContain(AWS_KEY);
    expect(entry.valueFingerprint).toMatch(/^[0-9a-f]{8}$/);
    expect(entry.valueLength).toBe(rawBody.length);
    expect(entry.timestamp).toBe(123);
  });

  test('sets hasSystemPrompt when the payload carries a system message', () => {
    const entry = buildCapturedRequestBody({
      url: 'https://api.openai.com/v1/chat/completions',
      method: 'POST',
      rawBody: '{"messages":[{"role":"system","content":"secret rules"}]}',
      timestamp: 0,
    });
    expect(entry.hasSystemPrompt).toBe(true);
  });

  test('omits detections and hasSystemPrompt for a clean user-only body', () => {
    const entry = buildCapturedRequestBody({
      url: 'https://api.openai.com/v1/chat/completions',
      method: 'POST',
      rawBody: '{"messages":[{"role":"user","content":"hello there"}]}',
      timestamp: 0,
    });
    expect(entry.detections).toBeUndefined();
    expect(entry.hasSystemPrompt).toBeUndefined();
  });

  test('bounds the redacted snippet length', () => {
    const rawBody = 'x'.repeat(10_000);
    const entry = buildCapturedRequestBody({ url: 'https://api.openai.com/v1/', method: 'POST', rawBody, timestamp: 0 });
    expect(entry.redactedSnippet.length).toBeLessThanOrEqual(MAX_SNIPPET_LENGTH);
    expect(entry.valueLength).toBe(10_000);
  });
});
