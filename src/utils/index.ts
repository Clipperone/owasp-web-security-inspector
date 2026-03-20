/**
 * Shared utility barrel.
 * Each module follows the Single Responsibility Principle.
 * JWT decoding is done here (in-process) — never delegated to the background.
 */

// JWT validation and Base64Url decoding (local, no external libs)
export * from './jwtUtils';

// Typed wrappers around chrome.storage.local
export * from './storageUtils';

// Phase 2 stubs — will be populated in upcoming phases
export * from './cookieUtils';
export * from './headerUtils';
