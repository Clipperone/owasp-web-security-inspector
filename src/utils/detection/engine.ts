/**
 * Detection engine.
 *
 * Runs the detector catalog over a single storage value, resolves overlapping
 * matches (specific/validated detectors win over the generic entropy one), and
 * returns the aggregated hits plus a redacted copy of the value with every
 * surviving match masked in place.
 *
 * Redaction is deterministic (same input → same output) so a future Snapshot
 * Diff never reports spurious changes for an unchanged secret.
 */
import type { DetectionHit } from '../../types';
import { DETECTORS, CATEGORY_PRIORITY, type DetectorSpec } from './detectors';
import { fullMask } from './redact';

/** Total matched spans kept per value, across all detectors. */
const MAX_SPANS_PER_VALUE = 24;
const DEFAULT_MAX_MATCHES = 5;
/** Hard safety bound on exec iterations per detector (values are ≤4096 chars). */
const MAX_ITERATIONS = 2000;

export interface DetectionResult {
  hits: DetectionHit[];
  /** The value with every surviving match masked; equals the input when nothing matched. */
  redactedValue: string;
  wasRedacted: boolean;
}

interface Span {
  start: number;
  end: number;
  spec: DetectorSpec;
  text: string;
  validated: boolean;
}

function collectSpans(value: string): Span[] {
  const spans: Span[] = [];
  const lower = value.toLowerCase();

  for (const spec of DETECTORS) {
    if (spans.length >= MAX_SPANS_PER_VALUE) break;
    if (spec.prefilter && !spec.prefilter(lower)) continue;

    // Fresh regex so lastIndex never leaks between values.
    const re = new RegExp(spec.pattern.source, spec.pattern.flags);
    const maxMatches = spec.maxMatches ?? DEFAULT_MAX_MATCHES;
    let kept = 0;
    let iterations = 0;
    let match: RegExpExecArray | null;

    while ((match = re.exec(value)) !== null) {
      if (++iterations > MAX_ITERATIONS) break;
      const text = match[0];
      // Guard against zero-length matches stalling the loop.
      if (match.index === re.lastIndex) re.lastIndex++;
      if (spec.validate && !spec.validate(text)) continue;

      spans.push({ start: match.index, end: match.index + text.length, spec, text, validated: Boolean(spec.validate) });
      if (++kept >= maxMatches || spans.length >= MAX_SPANS_PER_VALUE) break;
    }
  }

  return spans;
}

function resolveOverlaps(spans: Span[]): Span[] {
  // Highest-priority (lowest number), validated-first, earliest-first.
  const ordered = [...spans].sort((a, b) => {
    const pa = CATEGORY_PRIORITY[a.spec.category];
    const pb = CATEGORY_PRIORITY[b.spec.category];
    if (pa !== pb) return pa - pb;
    if (a.validated !== b.validated) return a.validated ? -1 : 1;
    return a.start - b.start;
  });

  const kept: Span[] = [];
  for (const span of ordered) {
    const overlaps = kept.some(k => span.start < k.end && k.start < span.end);
    if (!overlaps) kept.push(span);
  }
  return kept;
}

function buildHits(kept: Span[]): DetectionHit[] {
  // Group by detector, preserving the earliest match for the sample.
  const byDetector = new Map<string, Span[]>();
  for (const span of kept) {
    const list = byDetector.get(span.spec.id);
    if (list) list.push(span);
    else byDetector.set(span.spec.id, [span]);
  }

  const hits: DetectionHit[] = [];
  for (const list of byDetector.values()) {
    list.sort((a, b) => a.start - b.start);
    const first = list[0];
    hits.push({
      detectorId: first.spec.id,
      category: first.spec.category,
      severity: first.spec.severity,
      sample: first.spec.redact(first.text),
      matchCount: list.length,
      ...(first.validated ? { validated: true } : {}),
    });
  }
  return hits;
}

/**
 * Runs every detector over `value`, returning aggregated hits and a redacted
 * copy. `key` is currently unused for matching but kept in the signature so
 * key-aware heuristics can be added without touching call sites.
 */
export function runDetectors(_key: string, value: string): DetectionResult {
  const spans = collectSpans(value);
  if (spans.length === 0) {
    return { hits: [], redactedValue: value, wasRedacted: false };
  }

  const kept = resolveOverlaps(spans);
  const hits = buildHits(kept);

  // Any private-key hit redacts the entire value — a truncated key body must
  // never survive splicing.
  if (kept.some(span => span.spec.category === 'private-key')) {
    return { hits, redactedValue: fullMask(value, 'redacted private key'), wasRedacted: true };
  }

  // Splice masks in descending index order so earlier offsets stay valid.
  let redactedValue = value;
  for (const span of [...kept].sort((a, b) => b.start - a.start)) {
    redactedValue = redactedValue.slice(0, span.start) + span.spec.redact(span.text) + redactedValue.slice(span.end);
  }

  return { hits, redactedValue, wasRedacted: redactedValue !== value };
}
