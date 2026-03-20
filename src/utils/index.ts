/**
 * Shared utility barrel.
 * Each module follows the Single Responsibility Principle.
 * JWT decoding is done here (in-process) — never delegated to the background.
 */

// JWT validation and Base64Url decoding (local, no external libs)
export * from './jwtUtils';

// Typed wrappers around chrome.storage.local
export * from './storageUtils';

export * from './cookieUtils';
export * from './headerUtils';

// Cookie and header export utilities (cURL, Netscape cookies.txt)
export * from './exporter';
