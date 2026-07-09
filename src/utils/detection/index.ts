/**
 * Storage secret/PII detection engine — pure, ReDoS-safe, shared by the content
 * script (page-side scan) and the assessment findings layer.
 */
export { runDetectors, type DetectionResult } from './engine';
export { DETECTORS, CATEGORY_PRIORITY, type DetectorSpec } from './detectors';
export { fnv1a32 } from './validators';
