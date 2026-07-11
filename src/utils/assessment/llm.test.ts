import { describe, expect, test } from 'vitest';
import type {
  CachedRequest,
  CapturedRequestBody,
  DetectionHit,
  PageResourceObservation,
  StorageEntry,
} from '../../types';
import {
  assessLlm,
  assessLlmOutgoingPrompts,
  assessLlmOutputHandling,
  assessLlmSystemPromptLeak,
} from './llm';
import { buildAssessmentFindings } from './findings';

function req(url: string, overrides: Partial<CachedRequest> = {}): CachedRequest {
  return {
    url,
    method: 'GET',
    resourceType: 'xmlhttprequest',
    statusCode: 200,
    timestamp: 0,
    responseHeaders: [],
    ...overrides,
  };
}

function storageEntry(overrides: Partial<StorageEntry> & { key: string }): StorageEntry {
  return {
    area: 'localStorage',
    value: '[redacted]',
    hints: [],
    isJwt: false,
    ...overrides,
  };
}

function body(overrides: Partial<CapturedRequestBody> & { url: string }): CapturedRequestBody {
  return {
    method: 'POST',
    redactedSnippet: '',
    valueLength: 0,
    valueFingerprint: '00000000',
    timestamp: 0,
    ...overrides,
  };
}

function pageResources(scriptUrls: string[]): PageResourceObservation {
  return {
    pageUrl: 'https://app.example.com/',
    scannedAt: '2026-01-01T00:00:00.000Z',
    scripts: scriptUrls.map(url => ({ url, kind: 'script', crossOrigin: true, hasIntegrity: false })),
    stylesheets: [],
    truncated: false,
  };
}

// ── LLM02: direct provider endpoint calls ─────────────────────────────────────

describe('assessLlm — direct provider endpoints', () => {
  test('flags a direct browser-to-provider API call as high', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [req('https://api.openai.com/v1/chat/completions', { method: 'POST' })],
      storageEntries: [],
    });
    const endpoint = findings.find(f => f.id === 'llm-direct-endpoint-api.openai.com');
    expect(endpoint?.severity).toBe('high');
    expect(endpoint?.category).toBe('llm');
    expect(endpoint?.summary).toContain('OpenAI');
  });

  test('matches subdomain providers by dot-suffix (Azure OpenAI)', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [req('https://my-resource.openai.azure.com/openai/deployments/x/chat/completions')],
      storageEntries: [],
    });
    expect(findings.some(f => f.id === 'llm-direct-endpoint-my-resource.openai.azure.com')).toBe(true);
  });

  test('deduplicates repeated calls to the same endpoint', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [
        req('https://api.anthropic.com/v1/messages', { method: 'POST' }),
        req('https://api.anthropic.com/v1/messages', { method: 'POST' }),
      ],
      storageEntries: [],
    });
    expect(findings.filter(f => f.id === 'llm-direct-endpoint-api.anthropic.com')).toHaveLength(1);
  });
});

// ── LLM03: third-party AI chatbot widgets ─────────────────────────────────────

describe('assessLlm — AI chatbot widgets', () => {
  test('flags a known widget loaded as a page script', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [],
      storageEntries: [],
      pageResources: pageResources(['https://www.chatbase.co/embed.min.js']),
    });
    const widget = findings.find(f => f.id === 'llm-widget-www.chatbase.co');
    expect(widget?.severity).toBe('info');
    expect(widget?.summary).toContain('Chatbase');
  });
});

// ── LLM05: output handling (CSP-inferred XSS surface) ─────────────────────────

describe('assessLlmOutputHandling', () => {
  const primary = (csp?: string) =>
    req('https://app.example.com/', {
      resourceType: 'main_frame',
      responseHeaders: csp === undefined ? [] : [{ name: 'content-security-policy', value: csp }],
    });

  test('flags a weak CSP that permits inline script without Trusted Types', () => {
    const findings = assessLlmOutputHandling('https://app.example.com/', [primary("script-src 'self' 'unsafe-inline'")]);
    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe('llm-output-handling-app.example.com');
    expect(findings[0].severity).toBe('low');
  });

  test('flags an absent CSP', () => {
    const findings = assessLlmOutputHandling('https://app.example.com/', [primary(undefined)]);
    expect(findings[0].evidence).toContain('absent');
  });

  test('does not flag when CSP requires Trusted Types', () => {
    const findings = assessLlmOutputHandling('https://app.example.com/', [primary("script-src 'self' 'unsafe-inline'; require-trusted-types-for 'script'")]);
    expect(findings).toEqual([]);
  });

  test('does not flag a strict CSP without unsafe-inline', () => {
    const findings = assessLlmOutputHandling('https://app.example.com/', [primary("script-src 'self'")]);
    expect(findings).toEqual([]);
  });

  test('returns nothing when no request was captured', () => {
    expect(assessLlmOutputHandling('https://app.example.com/', [])).toEqual([]);
  });
});

// ── LLM02: conversation history at rest + the isLikelyLlmApp gate ─────────────

describe('assessLlm — softer findings are gated by an LLM signal', () => {
  const chatEntry = storageEntry({ key: 'chat_history', area: 'localStorage' });

  test('does not surface conversation-at-rest on a non-LLM page', () => {
    const findings = assessLlm({
      activeUrl: 'https://shop.example.com/',
      requests: [],
      storageEntries: [chatEntry],
    });
    expect(findings).toEqual([]);
  });

  test('surfaces conversation-at-rest once a strong LLM signal is present', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [req('https://api.openai.com/v1/chat/completions', { method: 'POST' })],
      storageEntries: [chatEntry],
    });
    const conv = findings.find(f => f.id === 'llm-conversation-at-rest-app.example.com');
    expect(conv?.severity).toBe('low');
    expect(conv?.evidence).toContain('localStorage:chat_history');
    // Key names only — the redacted value must not be dumped into evidence.
    expect(conv?.evidence).not.toContain('[redacted]');
  });

  test('a strongly named storage key alone is enough to gate softer findings', () => {
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [],
      storageEntries: [storageEntry({ key: 'openai_thread', area: 'localStorage' })],
    });
    expect(findings.some(f => f.id === 'llm-conversation-at-rest-app.example.com')).toBe(true);
  });

  test('a provider key in storage is a signal but does not itself add an LLM finding', () => {
    const keyHit: DetectionHit = {
      detectorId: 'anthropic-key',
      category: 'api-key',
      severity: 'high',
      sample: 'sk-ant-…AB12',
      matchCount: 1,
      validated: true,
    };
    const findings = assessLlm({
      activeUrl: 'https://app.example.com/',
      requests: [],
      storageEntries: [storageEntry({ key: 'apiKey', detections: [keyHit] })],
    });
    // The exposed key is reported under the Storage category by assessStorageSecrets,
    // not duplicated here; with no other LLM surface, the LLM assessor stays quiet.
    expect(findings).toEqual([]);
  });
});

// ── LLM02: sensitive data in outgoing prompts ─────────────────────────────────

describe('assessLlmOutgoingPrompts', () => {
  test('flags a prompt body carrying a detected secret at the hit severity', () => {
    const hit: DetectionHit = {
      detectorId: 'aws-access-key-id',
      category: 'api-key',
      severity: 'high',
      sample: 'AKIA…MPLE',
      matchCount: 1,
      validated: true,
    };
    const findings = assessLlmOutgoingPrompts([
      body({ url: 'https://api.openai.com/v1/chat/completions', detections: [hit] }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].category).toBe('llm');
    expect(findings[0].evidence).toContain('AKIA…MPLE');
  });

  test('ignores bodies without detections', () => {
    expect(assessLlmOutgoingPrompts([body({ url: 'https://api.openai.com/v1/chat/completions' })])).toEqual([]);
  });
});

// ── LLM07: system prompt leakage ──────────────────────────────────────────────

describe('assessLlmSystemPromptLeak', () => {
  test('flags a body that carries a system/developer instruction', () => {
    const findings = assessLlmSystemPromptLeak([
      body({ url: 'https://api.openai.com/v1/chat/completions', hasSystemPrompt: true }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].id).toMatch(/^llm-system-prompt-/);
  });

  test('ignores bodies without a system prompt', () => {
    expect(assessLlmSystemPromptLeak([body({ url: 'https://api.openai.com/v1/chat/completions' })])).toEqual([]);
  });
});

// ── End-to-end through the aggregate pipeline ─────────────────────────────────

describe('buildAssessmentFindings — LLM findings flow end-to-end', () => {
  test('a realistic direct-to-OpenAI RAG page yields sorted, llm-tagged findings', () => {
    const keyHit: DetectionHit = {
      detectorId: 'aws-access-key-id',
      category: 'api-key',
      severity: 'high',
      sample: 'AKIA…MPLE',
      matchCount: 1,
      validated: true,
    };
    const findings = buildAssessmentFindings({
      activeUrl: 'https://chat.example.com/',
      cookies: [],
      storageEntries: [storageEntry({ key: 'chat_history', area: 'localStorage' })],
      requests: [
        req('https://chat.example.com/', {
          resourceType: 'main_frame',
          responseHeaders: [{ name: 'content-security-policy', value: "script-src 'self' 'unsafe-inline'" }],
        }),
        req('https://api.openai.com/v1/chat/completions', { method: 'POST' }),
      ],
      requestBodies: [
        body({ url: 'https://api.openai.com/v1/chat/completions', hasSystemPrompt: true, detections: [keyHit] }),
      ],
    });

    const llm = findings.filter(f => f.category === 'llm');
    const ids = llm.map(f => f.id);
    expect(ids).toContain('llm-direct-endpoint-api.openai.com');       // high
    expect(ids.some(id => id.startsWith('llm-prompt-sensitive-'))).toBe(true);   // high (AWS key)
    expect(ids.some(id => id.startsWith('llm-system-prompt-'))).toBe(true);      // medium (LLM07)
    expect(ids).toContain('llm-output-handling-chat.example.com');     // low (gated)
    expect(ids).toContain('llm-conversation-at-rest-chat.example.com'); // low (gated)

    // All are the new category, and the aggregate keeps global severity ordering.
    expect(llm.every(f => f.category === 'llm')).toBe(true);
    const weight = { high: 0, medium: 1, low: 2, info: 3 } as const;
    for (let i = 1; i < findings.length; i++) {
      expect(weight[findings[i - 1].severity]).toBeLessThanOrEqual(weight[findings[i].severity]);
    }
  });
});
