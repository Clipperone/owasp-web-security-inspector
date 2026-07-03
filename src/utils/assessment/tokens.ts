import type {
  AssessmentFinding,
  StorageEntry,
  TokenAssessmentOrigin,
  TokenAssessmentSummary,
} from '../../types';
import { checkNotBefore, decodeJwt, isJwt } from '../jwtUtils';
import { finding } from './shared';
import {
  SENSITIVE_CLAIM_RE,
  isOpaqueTokenValue,
  isSensitiveStorageKey,
  shouldTreatCookieAsToken,
} from './classification';

interface TokenCandidate {
  origin: TokenAssessmentOrigin;
  label: string;
  raw: string;
  isJwt: boolean;
}

function collectTokenCandidates(
  cookies: chrome.cookies.Cookie[],
  entries: StorageEntry[],
  manualValue?: string,
): TokenCandidate[] {
  const candidates: TokenCandidate[] = [];

  cookies.forEach(cookie => {
    if (!shouldTreatCookieAsToken(cookie)) return;
    candidates.push({
      origin: 'cookie',
      label: `cookie:${cookie.name}`,
      raw: cookie.value,
      isJwt: isJwt(cookie.value),
    });
  });

  entries.forEach(entry => {
    const opaqueToken = !entry.isJwt && (isSensitiveStorageKey(entry) || isOpaqueTokenValue(entry.value));
    if (!entry.isJwt && !opaqueToken) return;

    candidates.push({
      origin: entry.area,
      label: `${entry.area}:${entry.key}`,
      raw: entry.value,
      isJwt: entry.isJwt,
    });
  });

  const trimmedManual = manualValue?.trim();
  if (trimmedManual && isJwt(trimmedManual)) {
    candidates.push({
      origin: 'manual',
      label: 'manual:input',
      raw: trimmedManual,
      isJwt: true,
    });
  }

  return candidates;
}

export function assessStorageTokens(entries: StorageEntry[]): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];

  for (const entry of entries) {
    const looksSensitive = isSensitiveStorageKey(entry);
    if (!looksSensitive) continue;

    if (entry.area === 'localStorage') {
      findings.push(finding(
        `storage-local-${entry.area}-${entry.key}`,
        'storage',
        'high',
        'Sensitive token stored in localStorage',
        'Tokens in localStorage survive browser restarts and remain reachable from JavaScript in the page context.',
        `${entry.key} was found in localStorage on ${entry.area}.`,
        'Prefer HttpOnly cookies for session identifiers or, when browser-side token storage is required, prefer shorter-lived sessionStorage with strong XSS defenses.',
      ));
    } else if (entry.area === 'indexedDB') {
      findings.push(finding(
        `storage-idb-${entry.key}`,
        'storage',
        'high',
        'Sensitive token stored in IndexedDB',
        'Tokens in IndexedDB survive browser restarts and remain reachable from JavaScript in the page context.',
        `${entry.key} was found in IndexedDB.`,
        'Prefer HttpOnly cookies for session identifiers or, when browser-side token storage is required, prefer shorter-lived sessionStorage with strong XSS defenses.',
      ));
    } else {
      findings.push(finding(
        `storage-session-${entry.area}-${entry.key}`,
        'storage',
        'medium',
        'Sensitive token stored in sessionStorage',
        'sessionStorage reduces persistence but the token is still exposed to JavaScript and XSS in the page context.',
        `${entry.key} was found in sessionStorage.`,
        'If browser-side token storage is required, keep token lifetime short and harden the application with strong CSP and XSS defenses.',
      ));
    }

    if (!entry.isJwt) continue;
    const decoded = decodeJwt(entry.value);
    if (!decoded.ok) continue;

    const { token } = decoded;
    if (token.header.alg.toLowerCase() === 'none') {
      findings.push(finding(
        `token-none-${entry.area}-${entry.key}`,
        'tokens',
        'high',
        'JWT uses alg=none',
        'Unsigned JWTs should not be trusted for authentication or authorization decisions.',
        `${entry.key} decodes with header alg=none.`,
        'Reject unsigned tokens in the application and require a specific expected signing algorithm during validation.',
      ));
    }

    if (token.expiresAt === undefined) {
      findings.push(finding(
        `token-no-exp-${entry.area}-${entry.key}`,
        'tokens',
        'high',
        'JWT without expiry claim',
        'A token without exp has no built-in browser-visible expiration boundary.',
        `${entry.key} has no exp claim.`,
        'Issue JWTs with explicit expiration and keep access token lifetime short.',
      ));
    } else {
      const lifetimeSeconds = token.payload.iat !== undefined ? token.payload.exp! - token.payload.iat : undefined;
      if (lifetimeSeconds !== undefined && lifetimeSeconds > 60 * 60 * 8) {
        findings.push(finding(
          `token-lifetime-${entry.area}-${entry.key}`,
          'tokens',
          'medium',
          'JWT has a long validity window',
          'Long-lived access tokens increase replay impact if the token is stolen from the browser.',
          `${entry.key} has a visible lifetime longer than 8 hours.`,
          'Use shorter-lived access tokens and rely on rotation or refresh mechanisms with stricter controls.',
        ));
      }

      if (token.isExpired) {
        findings.push(finding(
          `token-expired-${entry.area}-${entry.key}`,
          'tokens',
          'info',
          'Expired JWT still present in browser storage',
          'Expired tokens left in storage are not necessarily exploitable, but they often signal stale client-side auth state.',
          `${entry.key} is expired but still present in ${entry.area}.`,
          'Clear expired tokens during logout and token refresh flows to reduce confusion and stale session artifacts.',
        ));
      }
    }

    const notBefore = checkNotBefore(token);
    if (notBefore) {
      findings.push(finding(
        `token-nbf-future-${entry.area}-${entry.key}`,
        'tokens',
        'info',
        'JWT is not yet valid (nbf in the future)',
        'The token declares a not-before (nbf) time that has not been reached, so it should not be accepted yet.',
        `${entry.key} in ${entry.area} is not valid until ${notBefore.at.toLocaleString()}.`,
        'If this is a deliberately pre-issued token, wait until the nbf time. Otherwise review token issuance and server clock synchronization.',
      ));
    }

    const sensitiveClaims = Object.keys(token.payload).filter(key => SENSITIVE_CLAIM_RE.test(key));
    if (sensitiveClaims.length > 0) {
      findings.push(finding(
        `token-claims-${entry.area}-${entry.key}`,
        'tokens',
        'low',
        'JWT payload exposes potentially sensitive claims',
        'JWT payloads are only encoded, not encrypted, unless the application adds extra protection beyond signing.',
        `${entry.key} contains claims such as ${sensitiveClaims.slice(0, 4).join(', ')}.`,
        'Keep JWT payloads minimal and avoid embedding sensitive personal or authorization details unless there is a clear need.',
      ));
    }
  }

  return findings;
}

function assessTokenCandidate(candidate: TokenCandidate): AssessmentFinding[] {
  const findings: AssessmentFinding[] = [];
  const originLabel = candidate.origin === 'manual' ? 'manual input' : candidate.origin;

  if (!candidate.isJwt) {
    if (candidate.origin === 'localStorage') {
      findings.push(finding(
        `opaque-token-local-${candidate.label}`,
        'storage',
        'high',
        'Opaque token-like value stored in localStorage',
        'A non-JWT token-like value was found in localStorage, where it stays reachable from page JavaScript and survives browser restarts.',
        `${candidate.label} contains a long opaque token-like value in localStorage.`,
        'Prefer HttpOnly cookies for browser session state, or reduce token lifetime and harden the application against XSS if browser-side storage is required.',
      ));
    } else if (candidate.origin === 'sessionStorage') {
      findings.push(finding(
        `opaque-token-session-${candidate.label}`,
        'storage',
        'medium',
        'Opaque token-like value stored in sessionStorage',
        'A non-JWT token-like value was found in sessionStorage, which reduces persistence but still exposes the token to page JavaScript.',
        `${candidate.label} contains a long opaque token-like value in sessionStorage.`,
        'Keep browser-stored opaque tokens short-lived and rely on strong XSS defenses if client-side storage cannot be avoided.',
      ));
    } else if (candidate.origin === 'indexedDB') {
      findings.push(finding(
        `opaque-token-idb-${candidate.label}`,
        'storage',
        'high',
        'Opaque token-like value stored in IndexedDB',
        'A non-JWT token-like value was found in IndexedDB, where it stays reachable from page JavaScript and survives browser restarts.',
        `${candidate.label} contains a long opaque token-like value in IndexedDB.`,
        'Prefer HttpOnly cookies for browser session state, or reduce token lifetime and harden the application against XSS if browser-side storage is required.',
      ));
    } else if (candidate.origin === 'cookie') {
      findings.push(finding(
        `opaque-token-cookie-${candidate.label}`,
        'tokens',
        'info',
        'Opaque token-like value observed in a cookie',
        'The cookie value looks token-like rather than a simple identifier, so it is worth reviewing how the backend treats it.',
        `${candidate.label} contains a long opaque token-like cookie value.`,
        'Review whether the cookie carries a bearer-like token and ensure cookie protections and backend validation rules are appropriate.',
      ));
    }

    return findings;
  }

  const decoded = decodeJwt(candidate.raw);
  if (!decoded.ok) return findings;

  const { token } = decoded;

  if (candidate.origin === 'localStorage') {
    findings.push(finding(
      `jwt-local-${candidate.label}`,
      'storage',
      'high',
      'JWT stored in localStorage',
      'A JWT found in localStorage is accessible to page scripts and survives browser restarts, which increases replay impact if the application is exposed to XSS.',
      `${candidate.label} stores a JWT in localStorage.`,
      'Prefer HttpOnly cookies for browser session tokens, or combine short JWT lifetime with strong XSS defenses when client-side storage is unavoidable.',
    ));
  } else if (candidate.origin === 'sessionStorage') {
    findings.push(finding(
      `jwt-session-${candidate.label}`,
      'storage',
      'medium',
      'JWT stored in sessionStorage',
      'sessionStorage reduces persistence but the JWT is still exposed to page JavaScript in the browser context.',
      `${candidate.label} stores a JWT in sessionStorage.`,
      'Keep session-stored JWTs short-lived and combine them with strong CSP and XSS defenses.',
    ));
  } else if (candidate.origin === 'indexedDB') {
    findings.push(finding(
      `jwt-idb-${candidate.label}`,
      'storage',
      'high',
      'JWT stored in IndexedDB',
      'A JWT found in IndexedDB is accessible to page scripts and survives browser restarts, which increases replay impact if the application is exposed to XSS.',
      `${candidate.label} stores a JWT in IndexedDB.`,
      'Prefer HttpOnly cookies for browser session tokens, or combine short JWT lifetime with strong XSS defenses when client-side storage is unavoidable.',
    ));
  } else if (candidate.origin === 'cookie') {
    findings.push(finding(
      `jwt-cookie-${candidate.label}`,
      'tokens',
      'info',
      'JWT observed in a cookie value',
      'The browser is carrying a structured JWT inside a cookie rather than an opaque session identifier.',
      `${candidate.label} contains a JWT-shaped cookie value.`,
      'Review whether the backend intentionally uses self-contained tokens in cookies and keep cookie protections aligned with the token sensitivity.',
    ));
  } else if (candidate.origin === 'manual') {
    findings.push(finding(
      `jwt-manual-${candidate.label}`,
      'tokens',
      'info',
      'Manual JWT review is based on structure, not trust',
      'The manual token preview can assess payload and expiry signals, but it still does not verify the signature or backend revocation state.',
      'Manual token input is being evaluated without access to the signing key or revocation system.',
      'Treat manual JWT review as a structural inspection aid rather than proof that the token is trusted by the backend.',
    ));
  }

  if (token.header.alg.toLowerCase() === 'none') {
    findings.push(finding(
      `token-none-${candidate.label}`,
      'tokens',
      'high',
      'JWT uses alg=none',
      'Unsigned JWTs should not be trusted for authentication or authorization decisions.',
      `${candidate.label} from ${originLabel} decodes with header alg=none.`,
      'Reject unsigned tokens in the application and require a specific expected signing algorithm during validation.',
    ));
  }

  if (token.expiresAt === undefined) {
    findings.push(finding(
      `token-no-exp-${candidate.label}`,
      'tokens',
      'high',
      'JWT without expiry claim',
      'A token without exp has no built-in browser-visible expiration boundary.',
      `${candidate.label} from ${originLabel} has no exp claim.`,
      'Issue JWTs with explicit expiration and keep access token lifetime short.',
    ));
  } else {
    const lifetimeSeconds = token.payload.iat !== undefined ? token.payload.exp! - token.payload.iat : undefined;
    if (lifetimeSeconds !== undefined && lifetimeSeconds > 60 * 60 * 8) {
      findings.push(finding(
        `token-lifetime-${candidate.label}`,
        'tokens',
        'medium',
        'JWT has a long validity window',
        'Long-lived access tokens increase replay impact if the token is stolen from the browser.',
        `${candidate.label} from ${originLabel} has a visible lifetime longer than 8 hours.`,
        'Use shorter-lived access tokens and rely on rotation or refresh mechanisms with stricter controls.',
      ));
    }

    if (token.isExpired) {
      findings.push(finding(
        `token-expired-${candidate.label}`,
        'tokens',
        candidate.origin === 'manual' ? 'low' : 'info',
        'Expired JWT still present in review context',
        'Expired tokens are not necessarily exploitable, but they often signal stale client-side auth state or confusing operational handling.',
        `${candidate.label} from ${originLabel} is expired but still present in the current review context.`,
        'Clear expired tokens during logout and refresh flows, and review whether expired examples are still being distributed or persisted.',
      ));
    }
  }

  const notBefore = checkNotBefore(token);
  if (notBefore) {
    findings.push(finding(
      `token-nbf-future-${candidate.label}`,
      'tokens',
      'info',
      'JWT is not yet valid (nbf in the future)',
      'The token declares a not-before (nbf) time that has not been reached, so it should not be accepted yet.',
      `${candidate.label} from ${originLabel} is not valid until ${notBefore.at.toLocaleString()}.`,
      'If this is a deliberately pre-issued token, wait until the nbf time. Otherwise review token issuance and server clock synchronization.',
    ));
  }

  const payloadKeys = Object.keys(token.payload);
  const sensitiveClaims = payloadKeys.filter(key => SENSITIVE_CLAIM_RE.test(key));
  if (sensitiveClaims.length > 0) {
    findings.push(finding(
      `token-claims-${candidate.label}`,
      'tokens',
      'low',
      'JWT payload exposes potentially sensitive claims',
      'JWT payloads are only encoded, not encrypted, unless the application adds extra protection beyond signing.',
      `${candidate.label} from ${originLabel} contains claims such as ${sensitiveClaims.slice(0, 4).join(', ')}.`,
      'Keep JWT payloads minimal and avoid embedding sensitive personal or authorization details unless there is a clear need.',
    ));
  }

  if (payloadKeys.length > 12 || candidate.raw.length > 1500) {
    findings.push(finding(
      `token-excessive-${candidate.label}`,
      'tokens',
      'low',
      'JWT payload is claim-heavy or oversized',
      'Large or claim-heavy JWTs often carry more information than the browser needs and increase exposure if the token is leaked.',
      `${candidate.label} from ${originLabel} has ${payloadKeys.length} payload claims and raw length ${candidate.raw.length}.`,
      'Review whether the JWT can be reduced to the minimum claims required by the browser and backend flow.',
    ));
  }

  return findings;
}

export function assessBrowserTokens(cookies: chrome.cookies.Cookie[], entries: StorageEntry[]): AssessmentFinding[] {
  return collectTokenCandidates(cookies, entries).flatMap(candidate => assessTokenCandidate(candidate));
}

export function assessManualToken(raw: string): AssessmentFinding[] {
  return collectTokenCandidates([], [], raw).flatMap(candidate => assessTokenCandidate(candidate));
}

export function getTokenAssessmentSummary(
  cookies: chrome.cookies.Cookie[],
  entries: StorageEntry[],
  manualValue?: string,
): TokenAssessmentSummary {
  const candidates = collectTokenCandidates(cookies, entries, manualValue);
  const counts: Record<TokenAssessmentOrigin, number> = {
    cookie: 0,
    localStorage: 0,
    sessionStorage: 0,
    indexedDB: 0,
    manual: 0,
  };
  let jwtCount = 0;
  let opaqueCount = 0;
  const labels = new Set<string>();

  candidates.forEach(candidate => {
    counts[candidate.origin] += 1;
    if (candidate.isJwt) jwtCount += 1;
    else opaqueCount += 1;
    labels.add(candidate.label);
  });

  return {
    observedCount: candidates.length,
    jwtCount,
    opaqueCount,
    counts,
    labels: [...labels].slice(0, 8),
  };
}
