/**
 * @file csp.ts
 * @description Per-directive Content-Security-Policy analyzer (milestone M2).
 *
 * The graded OWASP Secure Headers check in `headers.ts` only reports whether a
 * CSP is present and free of the substring `unsafe`. This module goes deeper:
 * it parses each policy into directives and source lists and raises dedicated
 * `AssessmentFinding`s (category `headers`) with precise remediation, following
 * the OWASP Content Security Policy Cheat Sheet.
 *
 * Scope / limitations (browser-side only):
 *   - Only CSP delivered via response headers is visible. A policy set through a
 *     `<meta http-equiv="Content-Security-Policy">` tag is not observable here,
 *     so a header-less page that relies on a meta CSP may surface `csp-missing`.
 *   - `Content-Security-Policy-Report-Only` policies are analyzed but their
 *     findings are downgraded one severity level (they do not enforce anything).
 *   - Multiple enforced policies are combined for "missing directive" checks
 *     (a directive counts as missing only when no policy defines it) but their
 *     true intersection semantics for source lists are not fully modeled.
 */

import type { AssessmentFinding, AssessmentSeverity, CachedRequest } from '../../types';
import { allHeaderValues, finding, headerFinding, hostnameFromUrl } from './shared';

// ─────────────────────────────────────────────────────────────────────────────
// Parsed model
// ─────────────────────────────────────────────────────────────────────────────

/** A single CSP source expression, keeping the original quoting for keywords. */
interface CspSource {
  raw: string;
  lower: string;
}

/** One parsed policy (from a single header value). */
interface CspPolicy {
  reportOnly: boolean;
  /** Directive name (lowercased) → ordered source list. First occurrence wins. */
  directives: Map<string, CspSource[]>;
}

/** Directives that fall back to `default-src` when absent. */
const FALLBACK_DIRECTIVES = new Set(['script-src', 'object-src', 'style-src']);

// ─────────────────────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────────────────────

function parseCspHeaderValue(value: string, reportOnly: boolean): CspPolicy {
  const directives = new Map<string, CspSource[]>();

  value
    .split(';')
    .map(segment => segment.trim())
    .filter(Boolean)
    .forEach(segment => {
      const tokens = segment.split(/\s+/).filter(Boolean);
      if (tokens.length === 0) return;

      const name = tokens[0].toLowerCase();
      // A duplicate directive in the same policy is ignored by the browser
      // (the first declaration wins), so mirror that here.
      if (directives.has(name)) return;

      const sources: CspSource[] = tokens.slice(1).map(token => ({
        raw: token,
        lower: token.toLowerCase(),
      }));
      directives.set(name, sources);
    });

  return { reportOnly, directives };
}

function collectCspPolicies(req: CachedRequest): { enforced: CspPolicy[]; reportOnly: CspPolicy[] } {
  const enforced = allHeaderValues(req, 'content-security-policy')
    .map(value => parseCspHeaderValue(value, false));
  const reportOnly = allHeaderValues(req, 'content-security-policy-report-only')
    .map(value => parseCspHeaderValue(value, true));

  return { enforced, reportOnly };
}

// ─────────────────────────────────────────────────────────────────────────────
// Source-list inspection
// ─────────────────────────────────────────────────────────────────────────────

interface SourceFlags {
  unsafeInline: boolean;
  unsafeEval: boolean;
  wildcard: boolean;
  httpScheme: boolean;
  dataScheme: boolean;
  blobScheme: boolean;
  hasNonce: boolean;
  hasHash: boolean;
  strictDynamic: boolean;
}

function scanSources(sources: CspSource[]): SourceFlags {
  return {
    unsafeInline: sources.some(s => s.lower === "'unsafe-inline'"),
    unsafeEval: sources.some(s => s.lower === "'unsafe-eval'"),
    wildcard: sources.some(s => s.lower === '*'),
    httpScheme: sources.some(s => s.lower === 'http:' || s.lower.startsWith('http://')),
    dataScheme: sources.some(s => s.lower === 'data:'),
    blobScheme: sources.some(s => s.lower === 'blob:'),
    hasNonce: sources.some(s => s.lower.startsWith("'nonce-")),
    hasHash: sources.some(s => /^'sha(256|384|512)-/.test(s.lower)),
    strictDynamic: sources.some(s => s.lower === "'strict-dynamic'"),
  };
}

function isNone(sources: CspSource[]): boolean {
  return sources.some(s => s.lower === "'none'");
}

/** True when base-uri is restricted to a safe value (`'none'` or `'self'`). */
function baseUriRestricted(sources: CspSource[]): boolean {
  if (sources.some(s => s.lower === "'none'")) return true;
  return sources.some(s => s.lower === "'self'") && !sources.some(s => s.lower === '*');
}

/** Resolve the effective sources for a directive, applying default-src fallback. */
function effectiveSources(policy: CspPolicy, directive: string): { sources: CspSource[]; via: 'explicit' | 'default-src' | 'none' } {
  const explicit = policy.directives.get(directive);
  if (explicit) return { sources: explicit, via: 'explicit' };
  if (FALLBACK_DIRECTIVES.has(directive)) {
    const fallback = policy.directives.get('default-src');
    if (fallback) return { sources: fallback, via: 'default-src' };
  }
  return { sources: [], via: 'none' };
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity / id helpers (report-only findings are downgraded and suffixed)
// ─────────────────────────────────────────────────────────────────────────────

const DOWNGRADE: Record<AssessmentSeverity, AssessmentSeverity> = {
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};

function sev(base: AssessmentSeverity, reportOnly: boolean): AssessmentSeverity {
  return reportOnly ? DOWNGRADE[base] : base;
}

function id(base: string, reportOnly: boolean): string {
  return reportOnly ? `${base}-ro` : base;
}

function mode(reportOnly: boolean): string {
  return reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
}

// ─────────────────────────────────────────────────────────────────────────────
// Directive analyzers
// ─────────────────────────────────────────────────────────────────────────────

function analyzeMissingDirectives(policies: CspPolicy[], host: string, ro: boolean): AssessmentFinding[] {
  const out: AssessmentFinding[] = [];
  const header = mode(ro);

  if (!policies.some(p => p.directives.has('default-src'))) {
    out.push(headerFinding(
      id(`csp-default-src-missing-${host}`, ro),
      sev('low', ro),
      'CSP does not define default-src',
      'The policy has no default-src baseline, so directives without an explicit value are unrestricted.',
      'A missing default-src makes the policy harder to reason about and can leave fetch directives wide open.',
      `${header} does not declare default-src.`,
      "Define default-src 'self' (or 'none') as a safe baseline and allowlist only what each resource type needs.",
    ));
  }

  const objectRestricted = policies.some(p => isNone(effectiveSources(p, 'object-src').sources));
  const objectAddressed = policies.some(p => p.directives.has('object-src') || p.directives.has('default-src'));
  if (!objectRestricted) {
    if (objectAddressed) {
      out.push(headerFinding(
        id(`csp-object-src-not-none-${host}`, ro),
        sev('medium', ro),
        "CSP object-src is not 'none'",
        'Plugin and object content is not fully blocked by the policy.',
        "Legacy plugin content (Flash, applets, embeds) is a classic injection vector; 'none' removes it entirely.",
        `${header} does not restrict object-src to 'none'.`,
        "Set object-src 'none' unless the application genuinely embeds plugin content.",
      ));
    } else {
      out.push(headerFinding(
        id(`csp-object-src-missing-${host}`, ro),
        sev('medium', ro),
        'CSP object-src is missing',
        'Neither object-src nor default-src is defined, so plugin and object content is unrestricted.',
        "Legacy plugin content is a classic injection vector; 'none' removes it entirely.",
        `${header} declares neither object-src nor default-src.`,
        "Add object-src 'none' to block plugin and object content.",
      ));
    }
  }

  const baseUriPolicies = policies.filter(p => p.directives.has('base-uri'));
  if (baseUriPolicies.length === 0) {
    out.push(headerFinding(
      id(`csp-base-uri-missing-${host}`, ro),
      sev('medium', ro),
      'CSP base-uri directive is missing',
      'Without base-uri, an injected <base> tag can rewrite relative URLs across the page.',
      'base-uri does not fall back to default-src, so it must be set explicitly to prevent base-tag injection.',
      `${header} does not declare base-uri.`,
      "Add base-uri 'none' (or 'self') to prevent base-tag injection.",
    ));
  } else if (!baseUriPolicies.some(p => baseUriRestricted(p.directives.get('base-uri') ?? []))) {
    out.push(headerFinding(
      id(`csp-base-uri-weak-${host}`, ro),
      sev('low', ro),
      'CSP base-uri allows a broad source',
      "base-uri is defined but is not limited to 'none' or 'self'.",
      'A permissive base-uri weakens the protection against injected <base> tags.',
      `${header} base-uri is present but not restricted to 'none' or 'self'.`,
      "Restrict base-uri to 'none' or 'self'.",
    ));
  }

  if (!policies.some(p => p.directives.has('frame-ancestors'))) {
    out.push(headerFinding(
      id(`csp-frame-ancestors-missing-${host}`, ro),
      sev('medium', ro),
      'CSP frame-ancestors directive is missing',
      'Without frame-ancestors the page can be embedded by other origins, enabling clickjacking.',
      'frame-ancestors does not fall back to default-src and supersedes X-Frame-Options for modern browsers.',
      `${header} does not declare frame-ancestors.`,
      "Add frame-ancestors 'none' (or a trusted origin list) to prevent framing-based attacks.",
    ));
  }

  return out;
}

function analyzeScriptSources(policies: CspPolicy[], host: string, ro: boolean): AssessmentFinding[] {
  const out: AssessmentFinding[] = [];
  const header = mode(ro);
  const emitted = new Set<string>();
  const once = (key: string, fn: () => AssessmentFinding): void => {
    if (emitted.has(key)) return;
    emitted.add(key);
    out.push(fn());
  };

  for (const policy of policies) {
    const { sources, via } = effectiveSources(policy, 'script-src');
    if (sources.length === 0) continue;

    const flags = scanSources(sources);
    const mitigated = flags.hasNonce || flags.hasHash || flags.strictDynamic;
    const viaText = via === 'default-src' ? ' (via the default-src fallback)' : '';

    if (flags.unsafeInline) {
      if (mitigated) {
        once('mitigated', () => headerFinding(
          id(`csp-script-unsafe-inline-mitigated-${host}`, ro),
          sev('low', ro),
          "CSP script-src has a redundant 'unsafe-inline'",
          "'unsafe-inline' is present but ignored because a nonce, hash, or 'strict-dynamic' is also set.",
          "Keeping a redundant 'unsafe-inline' is confusing and risks accidental exposure if the nonce/hash is removed.",
          `${header} script-src${viaText} includes 'unsafe-inline' alongside a nonce/hash or 'strict-dynamic'.`,
          "Remove the redundant 'unsafe-inline'; rely on the nonce/hash allowlisting instead.",
        ));
      } else {
        once('unsafe-inline', () => headerFinding(
          id(`csp-script-unsafe-inline-${host}`, ro),
          sev('high', ro),
          "CSP script-src allows 'unsafe-inline'",
          "Inline scripts are permitted, which largely defeats CSP's protection against injected scripts.",
          "'unsafe-inline' lets an attacker execute injected inline <script> and event-handler payloads.",
          `${header} script-src${viaText} allows 'unsafe-inline' with no nonce or hash.`,
          "Remove 'unsafe-inline' and allowlist inline scripts with per-response nonces or hashes.",
        ));
      }
    }

    if (flags.unsafeEval) {
      once('unsafe-eval', () => headerFinding(
        id(`csp-script-unsafe-eval-${host}`, ro),
        sev('high', ro),
        "CSP script-src allows 'unsafe-eval'",
        "eval() and equivalent string-to-code APIs are permitted.",
        "'unsafe-eval' re-enables dynamic code evaluation, a common escalation path for injected content.",
        `${header} script-src${viaText} allows 'unsafe-eval'.`,
        "Remove 'unsafe-eval' and refactor code that relies on eval/new Function/setTimeout(string).",
      ));
    }

    if (flags.wildcard && !flags.strictDynamic) {
      once('wildcard', () => headerFinding(
        id(`csp-script-wildcard-${host}`, ro),
        sev('high', ro),
        'CSP script-src uses a wildcard source',
        'A bare * source allows scripts from any origin.',
        'A wildcard script source lets attacker-controlled hosts serve executable code to the page.',
        `${header} script-src${viaText} contains a bare * source.`,
        "Replace * with an explicit host allowlist, or use nonces/hashes with 'strict-dynamic'.",
      ));
    }

    if ((flags.httpScheme || flags.dataScheme || flags.blobScheme) && !flags.strictDynamic) {
      once('scheme', () => headerFinding(
        id(`csp-script-insecure-scheme-${host}`, ro),
        sev('high', ro),
        'CSP script-src allows an insecure or broad scheme',
        'script-src permits an http:, data:, or blob: source.',
        'Broad scheme sources let scripts load over cleartext or from attacker-crafted data/blob URLs.',
        `${header} script-src${viaText} allows an http:, data:, or blob: source.`,
        'Remove http:/data:/blob: script sources and serve scripts from HTTPS allowlisted hosts.',
      ));
    }
  }

  return out;
}

function analyzePositives(policies: CspPolicy[], host: string): AssessmentFinding[] {
  const out: AssessmentFinding[] = [];

  const trustedTypes = policies.some(policy => {
    const sources = policy.directives.get('require-trusted-types-for');
    return sources?.some(s => s.lower === "'script'") ?? false;
  });
  if (trustedTypes) {
    out.push(finding(
      `csp-trusted-types-${host}`,
      'headers',
      'info',
      'CSP enforces Trusted Types for scripts',
      "The policy sets require-trusted-types-for 'script', neutralizing many DOM-XSS sinks.",
      'require-trusted-types-for was observed in the policy.',
      'Good practice — keep Trusted Types enforced and maintain the associated trusted-types policy list.',
    ));
  }

  const reporting = policies.some(p => p.directives.has('report-to') || p.directives.has('report-uri'));
  if (reporting) {
    out.push(finding(
      `csp-reporting-${host}`,
      'headers',
      'info',
      'CSP configures violation reporting',
      'The policy declares report-to or report-uri, so violations can be monitored.',
      'A report-to or report-uri directive was observed in the policy.',
      'Good practice — keep a monitored reporting endpoint to detect regressions and attempted injections.',
    ));
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Analyze the Content-Security-Policy of the primary document response and
 * return per-directive findings. Returns a single `csp-missing` finding when no
 * CSP header (enforced or report-only) is present.
 */
export function assessCsp(primaryRequest: CachedRequest): AssessmentFinding[] {
  const host = hostnameFromUrl(primaryRequest.url);
  const { enforced, reportOnly } = collectCspPolicies(primaryRequest);

  if (enforced.length === 0 && reportOnly.length === 0) {
    return [headerFinding(
      `csp-missing-${host}`,
      'medium',
      'No Content-Security-Policy on the document response',
      'The primary response does not deliver a Content-Security-Policy header.',
      'A CSP is the main browser-enforced defense-in-depth control against script injection and framing abuse.',
      'No Content-Security-Policy or Content-Security-Policy-Report-Only header was observed on the primary response.',
      "Add a Content-Security-Policy starting from default-src 'none' and allowlist only the sources the application needs.",
    )];
  }

  const findings: AssessmentFinding[] = [];

  if (enforced.length > 0) {
    findings.push(...analyzeMissingDirectives(enforced, host, false));
    findings.push(...analyzeScriptSources(enforced, host, false));
  }

  if (reportOnly.length > 0) {
    findings.push(...analyzeMissingDirectives(reportOnly, host, true));
    findings.push(...analyzeScriptSources(reportOnly, host, true));
    findings.push(finding(
      `csp-report-only-${host}`,
      'headers',
      'info',
      'CSP is delivered in report-only mode',
      'A Content-Security-Policy-Report-Only header was observed; it monitors violations but does not block anything.',
      'The policy was delivered via Content-Security-Policy-Report-Only.',
      'Once the policy is tuned, promote it to an enforcing Content-Security-Policy header.',
    ));
  }

  findings.push(...analyzePositives([...enforced, ...reportOnly], host));

  return findings;
}
