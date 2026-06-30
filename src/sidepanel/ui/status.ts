/**
 * Central source of truth for status/severity → visual tone mapping.
 *
 * Every assessment surface (headers, transport, cookies, tokens, storage)
 * collapses its own status union into a small set of shared tones so that
 * colours and labels stay consistent across the whole UI. Components must use
 * these helpers instead of hand-writing Tailwind colour strings.
 */
import type {
  AssessmentSeverity,
  HeaderAssessmentStatus,
  TransportTlsStatus,
} from '../../types';

/** The shared visual vocabulary used by every badge, count, and accent. */
export type Tone = 'ok' | 'bad' | 'warn' | 'info' | 'neutral';

const TONE_BADGE_CLASSES: Record<Tone, string> = {
  ok: 'text-emerald-300 bg-emerald-950/40 border-emerald-900/60',
  bad: 'text-red-300 bg-red-950/40 border-red-900/60',
  warn: 'text-amber-300 bg-amber-950/40 border-amber-900/60',
  info: 'text-sky-300 bg-sky-950/40 border-sky-900/60',
  neutral: 'text-gray-300 bg-gray-900/60 border-gray-700',
};

const TONE_TEXT_CLASSES: Record<Tone, string> = {
  ok: 'text-emerald-300',
  bad: 'text-red-300',
  warn: 'text-amber-300',
  info: 'text-sky-300',
  neutral: 'text-gray-400',
};

/** Badge styling (text + background + border) for a tone. */
export function toneBadgeClasses(tone: Tone): string {
  return TONE_BADGE_CLASSES[tone];
}

/** Plain coloured-text styling for a tone, used in inline counters. */
export function toneTextClasses(tone: Tone): string {
  return TONE_TEXT_CLASSES[tone];
}

export function headerStatusTone(status: HeaderAssessmentStatus): Tone {
  switch (status) {
    case 'pass':
      return 'ok';
    case 'fail':
      return 'bad';
    case 'warn':
      return 'warn';
    case 'not-applicable':
      return 'neutral';
  }
}

export function headerStatusLabel(status: HeaderAssessmentStatus): string {
  switch (status) {
    case 'pass':
      return 'Pass';
    case 'fail':
      return 'Fail';
    case 'warn':
      return 'Warn';
    case 'not-applicable':
      return 'N/A';
  }
}

export function transportStatusTone(status: TransportTlsStatus): Tone {
  switch (status) {
    case 'pass':
      return 'ok';
    case 'fail':
      return 'bad';
    case 'warn':
      return 'warn';
    case 'inconclusive':
      return 'info';
  }
}

export function transportStatusLabel(status: TransportTlsStatus): string {
  switch (status) {
    case 'pass':
      return 'Pass';
    case 'fail':
      return 'Fail';
    case 'warn':
      return 'Warn';
    case 'inconclusive':
      return 'Inconclusive';
  }
}

export function severityTone(severity: AssessmentSeverity): Tone {
  switch (severity) {
    case 'high':
      return 'bad';
    case 'medium':
      return 'warn';
    case 'low':
      return 'info';
    case 'info':
      return 'neutral';
  }
}

export function severityLabel(severity: AssessmentSeverity): string {
  switch (severity) {
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    case 'info':
      return 'Info';
  }
}
