/**
 * Cookie utilities — helpers shared across the cookie UI and any future
 * background-side cookie logic.
 */

/**
 * Builds the URL required by chrome.cookies APIs from cookie attributes.
 * Leading dots on the domain are stripped (they denote host-only cookies).
 * When a page URL is available, its protocol is preferred over the cookie's
 * Secure flag so existing HTTPS pages can still update non-secure cookies.
 */
export function cookieUrl(domain: string, path: string, secure: boolean, pageUrl?: string): string {
  const host = domain.replace(/^\.+/, '');
  let protocol = secure ? 'https' : 'http';

  if (pageUrl) {
    try {
      const pageProtocol = new URL(pageUrl).protocol;
      if (pageProtocol === 'https:' || pageProtocol === 'http:') {
        protocol = pageProtocol.slice(0, -1);
      }
    } catch {
      // Ignore invalid page URLs and fall back to the cookie security flag.
    }
  }

  return `${protocol}://${host}${path || '/'}`;
}

/**
 * Returns a stable string key that uniquely identifies a cookie within
 * a cookie store (name + domain + path is the RFC 6265 primary key).
 */
export function cookieId(c: chrome.cookies.Cookie): string {
  return `${c.name}|${c.domain}|${c.path}`;
}

/**
 * Converts a Unix timestamp (seconds) to the `YYYY-MM-DDTHH:mm` format
 * expected by `<input type="datetime-local">`.
 * Returns an empty string for undefined / falsy values (session cookies).
 */
export function unixToLocalInput(unix: number | undefined): string {
  if (!unix) return '';
  const date = new Date(unix * 1000);
  const offsetMs = date.getTimezoneOffset() * 60 * 1000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

/**
 * Converts a `<input type="datetime-local">` value back to a Unix timestamp
 * in seconds. Returns `undefined` when the string is empty or unparseable.
 */
export function localInputToUnix(s: string): number | undefined {
  if (!s) return undefined;
  const t = new Date(s).getTime();
  return isNaN(t) ? undefined : Math.floor(t / 1000);
}
