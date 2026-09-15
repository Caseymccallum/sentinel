/**
 * Cookie knowledge base tests (Task 2.6.2).
 *
 * The knowledge base is a product surface: its sentences appear in the popup and its
 * safeToDelete verdicts gate a destructive button. So the tests enforce structure (every entry
 * complete), hygiene (no duplicate patterns, regexes compile), and behaviour (expected
 * examples match, unknown names fall through to conservative inference).
 */

import { describe, expect, it } from 'vitest';
import {
  COOKIE_ENTRIES,
  COOKIE_ENTRY_COUNT,
  cookiePatternKey,
  inferUnknownCookie,
  lookupCookie,
} from './cookies';

describe('knowledge base structure', () => {
  it('covers at least 40 well-known cookies', () => {
    expect(COOKIE_ENTRY_COUNT).toBeGreaterThanOrEqual(40);
    expect(COOKIE_ENTRIES).toHaveLength(COOKIE_ENTRY_COUNT);
  });

  it('gives every entry all required fields, populated', () => {
    for (const entry of COOKIE_ENTRIES) {
      expect(entry.namePattern, JSON.stringify(entry)).toBeTruthy();
      expect(entry.description.length, entry.setBy).toBeGreaterThan(30);
      expect(entry.setBy.length).toBeGreaterThan(0);
      expect(['essential', 'analytics', 'advertising', 'social', 'preference', 'unknown']).toContain(
        entry.category,
      );
      expect(['tracking', 'session', 'security', 'personalization', 'consent', 'ab-testing', 'unknown']).toContain(
        entry.purpose,
      );
      expect(['yes', 'no', 'will-log-out', 'unknown']).toContain(entry.safeToDelete);
    }
  });

  it('only marks safeToDelete yes for cookies whose purpose is tracking', () => {
    for (const entry of COOKIE_ENTRIES) {
      if (entry.safeToDelete === 'yes') {
        expect(entry.purpose, entry.setBy).toBe('tracking');
      }
    }
  });

  it('has no duplicate patterns', () => {
    const keys = COOKIE_ENTRIES.map((entry) => cookiePatternKey(entry.namePattern));
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('compiles every regex pattern by matching a probe string', () => {
    for (const entry of COOKIE_ENTRIES) {
      const pattern = entry.namePattern;
      if (pattern instanceof RegExp) {
        expect(() => pattern.test('probe_cookie_name')).not.toThrow();
      }
    }
  });


  it('covers the categories the brief requires', () => {
    const names = COOKIE_ENTRIES.map((entry) =>
      entry.namePattern instanceof RegExp ? entry.namePattern.source : entry.namePattern,
    );
    for (const required of ['_ga', '_gid', '_gcl_au', '_fbp', 'fr', '_ttp', 'bcookie', 'guest_id', 'MUID', 'hubspotutk', '__cf_bm', 'cf_clearance', 'sessionid', 'csrftoken', 'XSRF-TOKEN']) {
      expect(names.some((name) => name.includes(required)), required).toBe(true);
    }
  });
});

describe('lookupCookie', () => {
  it('matches exact names', () => {
    const entry = lookupCookie('_ga');
    expect(entry?.category).toBe('analytics');
    expect(entry?.setBy).toBe('Google Analytics');
    expect(entry?.safeToDelete).toBe('yes');
  });

  it('matches regex patterns at any well-formed suffix', () => {
    expect(lookupCookie('_ga_AB12CD34')?.category).toBe('analytics');
    expect(lookupCookie('_gat_gtag_UA-1')?.category).toBe('analytics');
    expect(lookupCookie('_gac_1234567890')?.category).toBe('advertising');
    expect(lookupCookie('ajs_anonymous_id')?.category).toBe('analytics');
    expect(lookupCookie('_hjAbsoluteSessionInProgress')?.category).toBe('analytics');
    expect(lookupCookie('_gat')?.category).toBe('analytics');
  });

  it('returns null for names it does not know', () => {
    expect(lookupCookie('totally_made_up')).toBeNull();
    expect(lookupCookie('')).toBeNull();
  });
});

describe('inferUnknownCookie (generic patterns, Task 2.2.3)', () => {
  it('treats __Host- cookies as security cookies that must not be deleted', () => {
    const inference = inferUnknownCookie('__Host-session');
    expect(inference.category).toBe('essential');
    expect(inference.purpose).toBe('security');
    expect(inference.safeToDelete).toBe('no');
  });

  it('treats __Secure- cookies as security cookies that must not be deleted', () => {
    const inference = inferUnknownCookie('__Secure-next-auth.session-token');
    expect(inference.category).toBe('essential');
    expect(inference.safeToDelete).toBe('no');
  });

  it('treats csrf and xsrf names as CSRF tokens that must not be deleted', () => {
    expect(inferUnknownCookie('myapp_csrf').safeToDelete).toBe('no');
    expect(inferUnknownCookie('XSRF_unknown').safeToDelete).toBe('no');
  });

  it('treats session-looking names as will-log-out, not as deletable', () => {
    expect(inferUnknownCookie('app_session').safeToDelete).toBe('will-log-out');
    expect(inferUnknownCookie('rememberme-sess').safeToDelete).toBe('will-log-out');
    expect(inferUnknownCookie('app_session').category).toBe('unknown');
  });

  it('stays unknown for anything else — never invents a green light', () => {
    const inference = inferUnknownCookie('weird_thing');
    expect(inference.category).toBe('unknown');
    expect(inference.safeToDelete).toBe('unknown');
  });

  it('lets the security prefixes win over the session heuristic', () => {
    expect(inferUnknownCookie('__Host-myapp_session').safeToDelete).toBe('no');
    expect(inferUnknownCookie('__Secure-session_id').safeToDelete).toBe('no');
  });
});
