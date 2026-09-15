/**
 * Cookie knowledge base.
 *
 * A typed, curated module mapping cookie names to plain-language explanations, mirroring the
 * pattern of `src/shared/trackers.ts`: no JSON, no remote fetch, so the list is versioned with
 * the code, auditable by anyone and works offline. Every entry is sourced from the vendor's own
 * product documentation.
 *
 * Classification is deliberately conservative: a cookie is only marked `safeToDelete: 'yes'`
 * when the knowledge base explicitly knows it is a tracking cookie. Session, security and
 * unknown cookies are `'no'`, `'will-log-out'` or `'unknown'` — never a green light (see
 * `inferUnknownCookie` for the generic fallback rules).
 */

import type { CookieCategory, CookiePurpose, CookieSafeToDelete } from '../core/types';

export type { CookieCategory, CookiePurpose, CookieSafeToDelete };

export interface CookieEntry {
  /** Exact cookie name (`_ga`) or a regular expression (`/^_ga_[A-Za-z0-9-]+$/`). */
  namePattern: string | RegExp;
  /** One plain-language sentence a user can read in the popup. */
  description: string;
  category: CookieCategory;
  purpose: CookiePurpose;
  safeToDelete: CookieSafeToDelete;
  /** User-facing name of who sets it, e.g. `Google Analytics`. */
  setBy: string;
}

/** The knowledge base: 50 hand-curated cookies, each from vendor product documentation. */
export const COOKIE_ENTRIES: readonly CookieEntry[] = [
  // ------------------------------------------------------------- Google Analytics
  {
    namePattern: '_ga',
    description: 'Google Analytics device identifier. It distinguishes visitors and links visits on the same device across sessions.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Analytics',
  },
  {
    namePattern: '_gid',
    description: 'Google Analytics short-lived identifier that distinguishes visitors over a 24-hour window.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Analytics',
  },
  {
    namePattern: /^_ga_[A-Za-z0-9-]+$/,
    description: 'Google Analytics 4 session identifier. The suffix is the property\'s measurement stream id.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Analytics',
  },
  {
    namePattern: /^_gat(_.+)?$/,
    description: 'Google Analytics request-rate throttling cookie, limiting how often analytics requests are sent.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Analytics',
  },
  // ------------------------------------------------------------------ Google Ads
  {
    namePattern: '_gcl_au',
    description: 'Google Marketing Platform conversion-measurement cookie used to attribute ad clicks.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Ads',
  },
  {
    namePattern: '_gcl_aw',
    description: 'Google Ads ad-click identifier, recording that this browser clicked a specific ad.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Ads',
  },
  {
    namePattern: /^_gac_.+$/,
    description: 'Google Ads campaign-attribution cookie written on the landing page\'s domain after an ad click.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Google Ads',
  },
  // ------------------------------------------------------------ Facebook / Meta
  {
    namePattern: '_fbp',
    description: 'Meta Pixel browser identifier, used to measure ad performance and target advertising.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Meta',
  },
  {
    namePattern: '_fbc',
    description: 'Meta Pixel click identifier, carrying the `fbclid` parameter of an ad click into the browser.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Meta',
  },
  {
    namePattern: 'fr',
    description: 'Facebook identifier used for ad delivery, frequency capping and measurement across sites.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Meta',
  },
  // --------------------------------------------------------------------- TikTok
  {
    namePattern: '_ttp',
    description: 'TikTok Pixel visitor identifier used for ad attribution and audience building.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'TikTok',
  },
  {
    namePattern: '_tt_enable_cookie',
    description: 'TikTok Pixel marker recording that cookie-based tracking is enabled in this browser.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'TikTok',
  },
  // ------------------------------------------------------------------- LinkedIn
  {
    namePattern: 'li_sugr',
    description: 'LinkedIn probability identifier used to match this browser to a LinkedIn member.',
    category: 'social',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'LinkedIn',
  },
  {
    namePattern: 'bcookie',
    description: 'LinkedIn browser identifier, used for analytics and ad targeting on LinkedIn-embedded pages.',
    category: 'social',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'LinkedIn',
  },
  {
    namePattern: 'lidc',
    description: 'LinkedIn routing identifier used to pick a data centre for LinkedIn requests.',
    category: 'social',
    purpose: 'session',
    safeToDelete: 'unknown',
    setBy: 'LinkedIn',
  },
  {
    namePattern: 'UserMatchHistory',
    description: 'LinkedIn ad-sync cookie, matching this browser to advertising identifiers for audience matching.',
    category: 'social',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'LinkedIn',
  },
  // ------------------------------------------------------------------ Twitter/X
  {
    namePattern: '_twitter_sess',
    description: 'X (Twitter) web session token for embedded timelines and the site itself.',
    category: 'social',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'X (Twitter)',
  },
  {
    namePattern: 'guest_id',
    description: 'X (Twitter) guest identifier, personalising content and measuring engagement for logged-out visitors.',
    category: 'social',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'X (Twitter)',
  },
  {
    namePattern: 'personalization_id',
    description: 'X (Twitter) identifier used to personalise content and measure ad interactions.',
    category: 'social',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'X (Twitter)',
  },
  // ------------------------------------------------------------------ Microsoft
  {
    namePattern: '_uetvid',
    description: 'Microsoft Clarity / Bing Ads visitor identifier, used for analytics and remarketing.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Microsoft',
  },
  {
    namePattern: '_uetsid',
    description: 'Microsoft Clarity / Bing Ads session identifier for the current visit.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Microsoft',
  },
  {
    namePattern: 'MUID',
    description: 'Microsoft user identifier for advertising and personalisation across Microsoft properties.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Microsoft',
  },
  // -------------------------------------------------------------------- Hotjar
  {
    namePattern: '_hjSessionUser',
    description: 'Hotjar device identifier, linking visits of session-recording and heatmap data together.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Hotjar',
  },
  {
    namePattern: '_hjSession',
    description: 'Hotjar session identifier for the current recording window.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Hotjar',
  },
  {
    namePattern: '_hjAbsoluteSessionInProgress',
    description: 'Hotjar marker recording that a session-recording session is currently active.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Hotjar',
  },
  // ------------------------------------------------------------------- Segment
  {
    namePattern: /^ajs_.+$/,
    description: 'Segment analytics identifier: the anonymous visitor id or a consent-group state cookie.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Segment',
  },
  // ------------------------------------------------------------------- HubSpot
  {
    namePattern: 'hubspotutk',
    description: 'HubSpot visitor identifier, used to attribute form submissions to a contact record.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'HubSpot',
  },
  {
    namePattern: '__hstc',
    description: 'HubSpot main visitor identifier, combining hub and user tracking across visits.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'HubSpot',
  },
  {
    namePattern: '__hssc',
    description: 'HubSpot session identifier for the current visit.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'HubSpot',
  },
  {
    namePattern: '__hssrc',
    description: 'HubSpot marker that the visitor cookie already existed when the page loaded.',
    category: 'analytics',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'HubSpot',
  },
  // ---------------------------------------------------------------- Cloudflare
  {
    namePattern: '__cf_bm',
    description: 'Cloudflare bot-management cookie, distinguishing real visitors from automated traffic. Essential: deleting it makes the site re-run bot checks on every request.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Cloudflare',
  },
  {
    namePattern: 'cf_clearance',
    description: 'Cloudflare challenge-clearance cookie proving a security challenge was passed. Essential: deleting it can lock the browser out of the site until the challenge is repeated.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Cloudflare',
  },
  // --------------------------------------------------- Google sign-in (essential)
  {
    namePattern: 'SID',
    description: 'Google account sign-in cookie. Essential: it keeps you signed in to Google services, and deleting it signs you out everywhere.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Google',
  },
  {
    namePattern: 'HSID',
    description: 'Google account security cookie. Essential: deleting it signs you out of Google services.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Google',
  },
  {
    namePattern: 'SSID',
    description: 'Google account security cookie. Essential: deleting it signs you out of Google services.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Google',
  },
  {
    namePattern: 'SAPISID',
    description: 'Google account authentication cookie used by Google APIs. Essential: deleting it signs you out.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Google',
  },
  {
    namePattern: 'APISID',
    description: 'Google account authentication cookie used by embedded Google services. Essential: deleting it signs you out.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'Google',
  },
  // ----------------------------------------------------- DoubleClick (advertising)
  {
    namePattern: 'IDE',
    description: 'Google DoubleClick advertising identifier used to serve and measure ads.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'DoubleClick',
  },
  {
    namePattern: 'test_cookie',
    description: 'DoubleClick cookie that checks whether the browser accepts cookies before serving ads.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'DoubleClick',
  },
  // ------------------------------------------------- Generic session / CSRF names
  {
    namePattern: 'sessionid',
    description: 'Generic server-side session token (Django and many frameworks use this name). Deleting it logs you out.',
    category: 'essential',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'the site itself',
  },
  {
    namePattern: 'PHPSESSID',
    description: 'PHP session token. Deleting it ends the current login session.',
    category: 'essential',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'the site itself',
  },
  {
    namePattern: 'JSESSIONID',
    description: 'Java application server session token. Deleting it ends the current login session.',
    category: 'essential',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'the site itself',
  },
  {
    namePattern: 'ASP.NET_SessionId',
    description: 'ASP.NET session token. Deleting it ends the current login session.',
    category: 'essential',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'the site itself',
  },
  {
    namePattern: 'connect.sid',
    description: 'Express (Node.js) session token. Deleting it ends the current login session.',
    category: 'essential',
    purpose: 'session',
    safeToDelete: 'will-log-out',
    setBy: 'the site itself',
  },
  {
    namePattern: 'csrftoken',
    description: 'Cross-site request forgery token. Essential: the site\'s own forms need it to be accepted.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'the site itself',
  },
  {
    namePattern: 'XSRF-TOKEN',
    description: 'Cross-site request forgery token (common in ASP.NET and Angular applications). Essential for form submissions and API calls.',
    category: 'essential',
    purpose: 'security',
    safeToDelete: 'no',
    setBy: 'the site itself',
  },
  // -------------------------------------------------------------- Consent records
  {
    namePattern: 'CookieConsent',
    description: 'Cookiebot consent record, remembering your cookie choices so the banner does not reappear.',
    category: 'essential',
    purpose: 'consent',
    safeToDelete: 'unknown',
    setBy: 'the site itself',
  },
  {
    namePattern: 'OptanonConsent',
    description: 'OneTrust consent record, remembering your cookie choices so the banner does not reappear.',
    category: 'essential',
    purpose: 'consent',
    safeToDelete: 'unknown',
    setBy: 'the site itself',
  },
  // ------------------------------------------------------- Additional ad platforms
  {
    namePattern: '_pin_unauth',
    description: 'Pinterest ad-partner identifier used for conversion measurement on landing pages.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Pinterest',
  },
  {
    namePattern: '_scid',
    description: 'Snapchat Pixel device identifier used for ad attribution.',
    category: 'advertising',
    purpose: 'tracking',
    safeToDelete: 'yes',
    setBy: 'Snapchat',
  },
];

/** Stable, human-readable key for a pattern, used to detect duplicate coverage. */
export function cookiePatternKey(pattern: string | RegExp): string {
  return typeof pattern === 'string' ? `s:${pattern}` : `r:${pattern.source}/${pattern.flags}`;
}

/** Flattened lookup indexes, built once at module load. */
const EXACT_INDEX = new Map<string, CookieEntry>();
const REGEX_ENTRIES: { pattern: RegExp; entry: CookieEntry }[] = [];
for (const entry of COOKIE_ENTRIES) {
  if (typeof entry.namePattern === 'string') EXACT_INDEX.set(entry.namePattern, entry);
  else REGEX_ENTRIES.push({ pattern: entry.namePattern, entry });
}

export const COOKIE_ENTRY_COUNT = COOKIE_ENTRIES.length;

/**
 * The knowledge-base match for a cookie name, or `null` when it is not on the list.
 *
 * Exact string patterns win over regular expressions, so a specific entry (`_ga`) is never
 * shadowed by a broader one. Cookie names are case-sensitive, so lookup is too.
 */
export function lookupCookie(name: string): CookieEntry | null {
  if (name === '') return null;
  const exact = EXACT_INDEX.get(name);
  if (exact) return exact;
  for (const { pattern, entry } of REGEX_ENTRIES) {
    if (pattern.test(name)) return entry;
  }
  return null;
}

/** What the generic inference rules say about a cookie the knowledge base does not know. */
export interface CookieInference {
  category: CookieCategory;
  purpose: CookiePurpose;
  description: string;
  safeToDelete: CookieSafeToDelete;
}

const UNKNOWN_INFERENCE: CookieInference = {
  category: 'unknown',
  purpose: 'unknown',
  description: 'Not in Sentinel\'s knowledge base, so its purpose could not be determined. Sentinel does not claim it is safe to delete.',
  safeToDelete: 'unknown',
};

/**
 * Conservative inference from the name alone, for cookies the knowledge base does not know.
 *
 * The rules are ordered: security prefixes win over everything (a `__Host-` CSRF cookie is a
 * security cookie first), CSRF tokens win over the session heuristics, and only then does a
 * session-looking name get the `will-log-out` advice. Everything else stays `unknown` —
 * inferring "probably fine to delete" from a name is exactly the guess Sentinel refuses to make.
 */
export function inferUnknownCookie(name: string): CookieInference {
  if (name.startsWith('__Host-')) {
    return {
      category: 'essential',
      purpose: 'security',
      description: 'A `__Host-` security cookie: the browser pins it to this exact host and requires HTTPS. It usually carries a session or CSRF token, so deleting it can break the site\'s defences or your session.',
      safeToDelete: 'no',
    };
  }
  if (name.startsWith('__Secure-')) {
    return {
      category: 'essential',
      purpose: 'security',
      description: 'A `__Secure-` security cookie: the browser only allows it over HTTPS. It usually carries a session or security token, so deleting it is not recommended.',
      safeToDelete: 'no',
    };
  }
  if (/(csrf|xsrf)/i.test(name)) {
    return {
      category: 'essential',
      purpose: 'security',
      description: 'A cross-site request forgery (CSRF) token. Essential: the site\'s own forms and API calls need it to be accepted.',
      safeToDelete: 'no',
    };
  }
  if (name.endsWith('-sess') || /session/i.test(name)) {
    return {
      category: 'unknown',
      purpose: 'session',
      description: 'Likely a session token, from its name: deleting it will probably log you out of this site.',
      safeToDelete: 'will-log-out',
    };
  }
  return { ...UNKNOWN_INFERENCE };
}

