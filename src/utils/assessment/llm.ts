/**
 * @file llm.ts
 * @description Passive analysis for chatbot / LLM / RAG web apps, aligned with
 * the OWASP Top 10 for LLM Applications 2025. All findings use the `llm`
 * category and surface under the LLM/AI assessment subtab.
 *
 * Everything here is browser-side and passive: it only reads already-captured
 * signals (response headers, DOM subresources, web-storage entries, and — from
 * the background — redacted outgoing request bodies). It never calls an LLM
 * endpoint, probes, or forces requests.
 *
 * Passive-detectability mapping (OWASP LLM Top 10 2025):
 *   - LLM02 Sensitive Information Disclosure — direct browser→provider API
 *     calls, PII/secrets inside outgoing prompt payloads, conversation history
 *     persisted at rest. (Provider keys in web storage surface under Storage.)
 *   - LLM07 System Prompt Leakage — system/instruction prompts embedded in
 *     client-visible outgoing payloads.
 *   - LLM03 Supply Chain (partial) — third-party AI chatbot widgets.
 *   - LLM05 Improper Output Handling (partial) — weak CSP where model output is
 *     rendered (XSS / prompt-injection-to-XSS surface).
 *
 * Out of scope (not browser-observable): LLM04 poisoning, LLM06 excessive
 * agency, LLM08 vector/embedding weaknesses, LLM09 misinformation, LLM10
 * unbounded consumption.
 */
import type {
  AssessmentFinding,
  CachedRequest,
  CapturedRequestBody,
  DetectionHit,
  PageResourceObservation,
  StorageEntry,
} from '../../types';
import { firstHeaderValue, getPrimaryRequest, hostnameFromUrl } from './shared';
import { fnv1a32 } from '../detection';

// ── Known LLM provider API endpoints (direct browser → provider calls) ────────
// Matched by exact host or dot-suffix, so `resource.openai.azure.com` matches
// `openai.azure.com` and `api.openrouter.ai` matches `openrouter.ai`.
const LLM_PROVIDER_HOSTS: Array<{ suffix: string; provider: string }> = [
  { suffix: 'api.openai.com', provider: 'OpenAI' },
  { suffix: 'api.anthropic.com', provider: 'Anthropic' },
  { suffix: 'generativelanguage.googleapis.com', provider: 'Google Gemini' },
  { suffix: 'openai.azure.com', provider: 'Azure OpenAI' },
  { suffix: 'api.cohere.ai', provider: 'Cohere' },
  { suffix: 'api.cohere.com', provider: 'Cohere' },
  { suffix: 'api.mistral.ai', provider: 'Mistral' },
  { suffix: 'api-inference.huggingface.co', provider: 'Hugging Face' },
  { suffix: 'api.huggingface.co', provider: 'Hugging Face' },
  { suffix: 'api.replicate.com', provider: 'Replicate' },
  { suffix: 'api.groq.com', provider: 'Groq' },
  { suffix: 'api.perplexity.ai', provider: 'Perplexity' },
  { suffix: 'api.together.xyz', provider: 'Together AI' },
  { suffix: 'api.together.ai', provider: 'Together AI' },
  { suffix: 'openrouter.ai', provider: 'OpenRouter' },
];

// ── Known embeddable AI chatbot widgets (non-exhaustive) ──────────────────────
const LLM_WIDGET_HOSTS: Array<{ suffix: string; name: string }> = [
  { suffix: 'chatbase.co', name: 'Chatbase' },
  { suffix: 'voiceflow.com', name: 'Voiceflow' },
  { suffix: 'botpress.cloud', name: 'Botpress' },
  { suffix: 'kommunicate.io', name: 'Kommunicate' },
  { suffix: 'chatbotkit.com', name: 'ChatBotKit' },
];

/** Detection ids (from utils/detection) that specifically indicate an LLM provider key. */
const LLM_PROVIDER_KEY_DETECTORS = new Set([
  'openai-key',
  'anthropic-key',
  'huggingface-token',
  'replicate-token',
]);

/** Storage key names that strongly imply an LLM/RAG app (used to gate findings). */
const STRONG_LLM_KEY_RE = /(openai|anthropic|claude|chatgpt|gpt-?[0-9]|\bllm\b|chatbot|copilot|assistant|gemini|mistral|langchain)/i;
/** Storage key names that look like persisted conversation state. */
const CHAT_HISTORY_KEY_RE = /(chat|conversation|messages?|thread|assistant|copilot|prompt|dialog)/i;

const MAX_LISTED_KEYS = 5;

function matchSuffix<T extends { suffix: string }>(hostname: string, table: T[]): T | undefined {
  const host = hostname.toLowerCase();
  return table.find(entry => host === entry.suffix || host.endsWith(`.${entry.suffix}`));
}

function severityWeight(severity: AssessmentFinding['severity']): number {
  return { high: 0, medium: 1, low: 2, info: 3 }[severity];
}

/** Build an `llm`-category finding with a whyItMatters rationale. */
function llmFinding(
  id: string,
  severity: AssessmentFinding['severity'],
  title: string,
  summary: string,
  whyItMatters: string,
  evidence: string,
  remediation: string,
): AssessmentFinding {
  return { id, category: 'llm', severity, title, summary, whyItMatters, evidence, remediation };
}

// ── Signal collection ─────────────────────────────────────────────────────────

interface LlmSignals {
  /** Distinct provider endpoints observed in captured requests. */
  providerEndpoints: Array<{ host: string; provider: string }>;
  /** Distinct AI chatbot widget hosts seen in requests or page scripts. */
  widgets: Array<{ host: string; name: string }>;
  /** At least one LLM provider key was detected in web storage. */
  providerKeyInStorage: boolean;
  /** At least one storage key name strongly implies an LLM app. */
  strongStorageKey: boolean;
  /** At least one captured outgoing body targeted a likely-LLM endpoint. */
  hasPromptBody: boolean;
  /** Aggregate: is this page likely an LLM/RAG app? Gates the softer findings. */
  isLikelyLlmApp: boolean;
}

function collectLlmSignals(input: {
  requests: CachedRequest[];
  pageResources?: PageResourceObservation | null;
  storageEntries: StorageEntry[];
  requestBodies?: CapturedRequestBody[];
}): LlmSignals {
  const providerEndpoints = new Map<string, { host: string; provider: string }>();
  for (const request of input.requests) {
    const host = hostnameFromUrl(request.url);
    const match = host ? matchSuffix(host, LLM_PROVIDER_HOSTS) : undefined;
    if (match) providerEndpoints.set(host, { host, provider: match.provider });
  }

  const widgets = new Map<string, { host: string; name: string }>();
  const widgetSources = [
    ...input.requests.map(request => request.url),
    ...(input.pageResources?.scripts ?? []).map(script => script.url),
  ];
  for (const url of widgetSources) {
    const host = hostnameFromUrl(url);
    const match = host ? matchSuffix(host, LLM_WIDGET_HOSTS) : undefined;
    if (match) widgets.set(host, { host, name: match.name });
  }

  const providerKeyInStorage = input.storageEntries.some(entry =>
    (entry.detections ?? []).some(hit => LLM_PROVIDER_KEY_DETECTORS.has(hit.detectorId)),
  );
  const strongStorageKey = input.storageEntries.some(entry => STRONG_LLM_KEY_RE.test(entry.key));
  const hasPromptBody = (input.requestBodies ?? []).length > 0;

  const isLikelyLlmApp =
    providerEndpoints.size > 0 ||
    widgets.size > 0 ||
    providerKeyInStorage ||
    strongStorageKey ||
    hasPromptBody;

  return {
    providerEndpoints: [...providerEndpoints.values()],
    widgets: [...widgets.values()],
    providerKeyInStorage,
    strongStorageKey,
    hasPromptBody,
    isLikelyLlmApp,
  };
}

// ── LLM02 — direct browser → provider API calls ───────────────────────────────

export function assessLlmProviderEndpoints(signals: LlmSignals): AssessmentFinding[] {
  return signals.providerEndpoints.map(({ host, provider }) =>
    llmFinding(
      `llm-direct-endpoint-${host}`,
      'high',
      'Direct browser-to-LLM-provider API call',
      `The page contacts the ${provider} API (${host}) directly from the browser.`,
      'Calling a model provider straight from the browser means the API key travels with the client, so it is exposable via DevTools, XSS, or a malicious dependency and can be reused to run up cost until it is rotated. It also removes the server-side boundary where request/response guardrails would run.',
      `Requests to ${host} (${provider}) were observed from the page context.`,
      'Proxy model calls through your backend, keep the provider key server-side, and apply rate limiting and prompt/response guardrails there. If a browser-side "bring your own key" flow is intended, confirm the key is user-owned and scoped, and never ship your own key to the client.',
    ),
  );
}

// ── LLM03 — third-party AI chatbot widgets ────────────────────────────────────

export function assessLlmWidgets(signals: LlmSignals): AssessmentFinding[] {
  return signals.widgets.map(({ host, name }) =>
    llmFinding(
      `llm-widget-${host}`,
      'info',
      'Third-party AI chatbot widget detected',
      `An embeddable AI chatbot widget (${name}, ${host}) is loaded on the page.`,
      'A third-party AI widget runs in your page context and can see the DOM, forwards user input to an external service, and expands the supply-chain and data-flow surface (OWASP LLM03). Its script integrity and the data it receives are worth reviewing.',
      `Resources from ${host} (${name}) were observed.`,
      'Review what the widget can access and transmit, pin its script with Subresource Integrity where possible, and confirm the data-sharing arrangement meets your privacy obligations.',
    ),
  );
}

// ── LLM05 — improper output handling (XSS surface, CSP-inferred) ───────────────

export function assessLlmOutputHandling(activeUrl: string, requests: CachedRequest[]): AssessmentFinding[] {
  const primary = getPrimaryRequest(requests, activeUrl);
  if (!primary) return [];

  const csp = firstHeaderValue(primary, 'content-security-policy');
  const cspLower = csp?.toLowerCase() ?? '';
  const allowsInlineScript = cspLower === '' || cspLower.includes("'unsafe-inline'");
  const hasTrustedTypes = cspLower.includes('require-trusted-types-for');
  if (!allowsInlineScript || hasTrustedTypes) return [];

  const host = hostnameFromUrl(activeUrl);
  const cspState = csp ? 'permits inline script and does not require Trusted Types' : 'is absent';
  return [
    llmFinding(
      `llm-output-handling-${host}`,
      'low',
      'Model output may be rendered without strong XSS controls',
      'The page has an LLM/RAG surface, and its Content-Security-Policy does not constrain inline script or enforce Trusted Types.',
      'LLM output is frequently rendered as HTML or Markdown. If the model can be steered (directly or via poisoned retrieved content) into emitting active markup, weak output handling turns that into DOM XSS (OWASP LLM05). This is a surface signal inferred from CSP posture, not proof the output is unsanitized.',
      `The primary response CSP ${cspState}.`,
      'Sanitize model output before rendering (treat it as untrusted), prefer text or a hardened Markdown renderer over raw HTML, and tighten CSP (drop unsafe-inline, adopt Trusted Types) so an injected payload cannot execute.',
    ),
  ];
}

// ── LLM02 — conversation history persisted at rest ────────────────────────────

export function assessLlmConversationAtRest(storageEntries: StorageEntry[], activeUrl: string): AssessmentFinding[] {
  const chatKeys = storageEntries
    .filter(entry => CHAT_HISTORY_KEY_RE.test(entry.key))
    .map(entry => `${entry.area}:${entry.key}`);
  if (chatKeys.length === 0) return [];

  const host = hostnameFromUrl(activeUrl);
  const shown = chatKeys.slice(0, MAX_LISTED_KEYS).join(', ');
  const more = chatKeys.length > MAX_LISTED_KEYS ? `, +${chatKeys.length - MAX_LISTED_KEYS} more` : '';
  return [
    llmFinding(
      `llm-conversation-at-rest-${host}`,
      'low',
      'Conversation history persisted in browser storage',
      `${chatKeys.length} storage ${chatKeys.length === 1 ? 'entry looks' : 'entries look'} like persisted chat/conversation state.`,
      'Conversation transcripts often contain user PII and whatever the user pasted into the chat. Persisting them in web storage keeps that content readable by any script in the origin (XSS) and leaves it on shared devices (OWASP LLM02).',
      `Conversation-like keys: ${shown}${more}. (Key names only — values are not included here.)`,
      'Avoid persisting full conversation transcripts client-side; keep history server-side behind auth, or store only a minimal, non-sensitive reference and clear it on logout.',
    ),
  ];
}

// ── LLM02 — sensitive data inside outgoing prompt payloads ────────────────────

function detectionCategories(hits: DetectionHit[]): string {
  return [...new Set(hits.map(hit => hit.category))].join(', ');
}

function maxHitSeverity(hits: DetectionHit[]): AssessmentFinding['severity'] {
  return hits
    .map(hit => hit.severity)
    .sort((a, b) => severityWeight(a) - severityWeight(b))[0] ?? 'info';
}

export function assessLlmOutgoingPrompts(requestBodies: CapturedRequestBody[]): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  for (const body of requestBodies) {
    const hits = body.detections ?? [];
    if (hits.length === 0) continue;
    const host = hostnameFromUrl(body.url) || 'the endpoint';
    findings.push(llmFinding(
      `llm-prompt-sensitive-${fnv1a32(body.url)}`,
      maxHitSeverity(hits),
      'Sensitive data sent to the model in an outgoing prompt',
      `An outgoing request to ${host} carried values matching ${detectionCategories(hits)}.`,
      'Whatever the client sends to the model leaves your trust boundary and may be logged or retained by the provider and stored in conversation history. Secrets or PII placed in a prompt are disclosed to a third party and can resurface in later completions (OWASP LLM02).',
      `${body.method} ${host} → ${hits.map(hit => hit.sample).join(', ')}`,
      'Strip or tokenize secrets and PII before they enter a prompt, and mediate model calls through a backend that enforces this. Review what user content is forwarded to the provider.',
    ));
  }
  return findings;
}

// ── LLM07 — system prompt leakage ─────────────────────────────────────────────

export function assessLlmSystemPromptLeak(requestBodies: CapturedRequestBody[]): AssessmentFinding[] {
  const leaking = requestBodies.filter(body => body.hasSystemPrompt);
  return leaking.map(body => {
    const host = hostnameFromUrl(body.url) || 'the endpoint';
    return llmFinding(
      `llm-system-prompt-${fnv1a32(body.url)}`,
      'medium',
      'System prompt is visible in a client-side request',
      `An outgoing request to ${host} includes a system/developer instruction assembled in the browser.`,
      'When the system prompt is built and sent from the client, it is fully visible in page scripts and network traffic (OWASP LLM07). Attackers can read the instructions and any guardrails, embedded examples, or hidden context to craft bypasses.',
      `${body.method} ${host} carries a system/developer role message or a system/instructions field.`,
      'Assemble the system prompt server-side and send only the user turn from the browser. Do not rely on a client-supplied system prompt for security, and keep sensitive context out of it.',
    );
  });
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

export function assessLlm(input: {
  activeUrl: string;
  requests: CachedRequest[];
  pageResources?: PageResourceObservation | null;
  storageEntries: StorageEntry[];
  requestBodies?: CapturedRequestBody[];
}): AssessmentFinding[] {
  const requestBodies = input.requestBodies ?? [];
  const signals = collectLlmSignals({
    requests: input.requests,
    pageResources: input.pageResources,
    storageEntries: input.storageEntries,
    requestBodies,
  });

  const findings: AssessmentFinding[] = [
    // These carry their own signal, so they are not gated.
    ...assessLlmProviderEndpoints(signals),
    ...assessLlmWidgets(signals),
    ...assessLlmOutgoingPrompts(requestBodies),
    ...assessLlmSystemPromptLeak(requestBodies),
  ];

  // Softer, inference-based findings only fire once the page looks like an LLM app.
  if (signals.isLikelyLlmApp) {
    findings.push(
      ...assessLlmOutputHandling(input.activeUrl, input.requests),
      ...assessLlmConversationAtRest(input.storageEntries, input.activeUrl),
    );
  }

  return findings;
}
