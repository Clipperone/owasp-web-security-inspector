/**
 * @file requestBody.ts
 * @description Pure helpers that turn a captured outgoing request body into a
 * redacted `CapturedRequestBody`. Kept out of the service worker so the core
 * invariant — raw secrets/PII never persist in the clear — is unit-testable
 * without a chrome runtime. The worker owns only the webRequest wiring and the
 * `Date.now()` timestamp.
 */
import type { CapturedRequestBody } from '../types';
import { runDetectors, fnv1a32 } from './detection';

/** Detection input cap — mirrors the content script's MAX_VALUE_LENGTH. */
export const MAX_BODY_LENGTH = 4096;
/** Bounded, redacted snippet kept for evidence (detected secrets already masked). */
export const MAX_SNIPPET_LENGTH = 256;

/** The `requestBody` payload shape carried by `onBeforeRequest` details. */
type RequestBody = chrome.webRequest.OnBeforeRequestDetails['requestBody'];

/** Decode an outgoing body to a string, bounded in length. Returns null when empty/binary. */
export function decodeRequestBody(requestBody: RequestBody): string | null {
  if (!requestBody) return null;
  try {
    if (requestBody.formData) {
      const parts: string[] = [];
      for (const [name, values] of Object.entries(requestBody.formData)) {
        const rendered = values.map(value => (typeof value === 'string' ? value : '[binary]')).join(',');
        parts.push(`${name}=${rendered}`);
        if (parts.join('&').length > MAX_BODY_LENGTH) break;
      }
      const joined = parts.join('&');
      return joined.length > 0 ? joined : null;
    }
    if (requestBody.raw && requestBody.raw.length > 0) {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      let out = '';
      for (const chunk of requestBody.raw) {
        if (chunk.bytes) out += decoder.decode(chunk.bytes, { stream: true });
        if (out.length > MAX_BODY_LENGTH) break;
      }
      out += decoder.decode();
      return out.length > 0 ? out : null;
    }
  } catch { /* non-UTF-8 / file upload — skip */ }
  return null;
}

/**
 * True when the payload carries a system/developer instruction (an LLM07
 * signal): a chat message with role `system`/`developer`, or a top-level
 * `system`/`instructions` field. Falls back to a cheap string test when the
 * (possibly truncated) body is not valid JSON.
 */
export function detectSystemPrompt(body: string): boolean {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      if (typeof obj.system === 'string' && obj.system.length > 0) return true;
      if (typeof obj.instructions === 'string' && obj.instructions.length > 0) return true;
      if (Array.isArray(obj.messages)) {
        return obj.messages.some(message =>
          message !== null && typeof message === 'object'
          && ['system', 'developer'].includes((message as { role?: unknown }).role as string),
        );
      }
    }
    return false;
  } catch {
    return /"role"\s*:\s*"(system|developer)"/.test(body) || /"(system|instructions)"\s*:\s*"/.test(body);
  }
}

/**
 * Build the cached record from a decoded body. Runs the detection engine and
 * keeps only the redacted output, so no raw secret/PII is ever returned here.
 */
export function buildCapturedRequestBody(input: {
  url: string;
  method: string;
  rawBody: string;
  timestamp: number;
}): CapturedRequestBody {
  const truncated = input.rawBody.slice(0, MAX_BODY_LENGTH);
  const detection = runDetectors('', truncated);
  return {
    url: input.url,
    method: input.method,
    redactedSnippet: detection.redactedValue.slice(0, MAX_SNIPPET_LENGTH),
    ...(detection.hits.length > 0 ? { detections: detection.hits } : {}),
    ...(detectSystemPrompt(truncated) ? { hasSystemPrompt: true } : {}),
    valueLength: input.rawBody.length,
    valueFingerprint: fnv1a32(input.rawBody),
    timestamp: input.timestamp,
  };
}
