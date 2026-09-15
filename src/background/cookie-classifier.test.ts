/**
 * Cookie classifier tests (Task 2.6.3).
 *
 * Classification is what turns raw metadata into something a user can act on, so the tests pin
 * the conservative behaviour: known trackers classified, unknowns unknown, security prefixes
 * respected, session vs persistent distinguished, and the summary arithmetic exact.
 */

import { describe, expect, it } from 'vitest';
import type { CookieRecord } from '../core/types';
import {
  classifyCookie,
  classifyCookies,
  removalTargetFor,
  removalUrlFor,
  summarizeCookies,
  trackingCookies,
} from './cookie-classifier';

const NOW = 1_700_000_000_000;
const DAY = 86_400_000;

function record(overrides: Partial<CookieRecord> = {}): CookieRecord {
  return {
    name: 'theme',
    domain: 'shop.example.com',
    hostOnly: true,
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'lax',
    session: true,
    storeId: '0',
    valueLength: 0,
    firstParty: true,
    ...overrides,
  };
}

describe('classifyCookie', () => {
  it('classifies known tracking cookies with the knowledge base verdicts', () => {
    const classified = classifyCookie(record({ name: '_fbp', domain: '.facebook.com', firstParty: false }));

    expect(classified.known).toBe(true);
    expect(classified.category).toBe('advertising');
    expect(classified.purpose).toBe('tracking');
    expect(classified.safeToDelete).toBe('yes');
    expect(classified.setBy).toBe('Meta');
    expect(classified.description).toContain('Meta Pixel');
  });

  it('classifies known essential cookies as not deletable', () => {
    expect(classifyCookie(record({ name: '__cf_bm' })).safeToDelete).toBe('no');
    expect(classifyCookie(record({ name: '__cf_bm' })).category).toBe('essential');
    expect(classifyCookie(record({ name: 'cf_clearance' })).category).toBe('essential');
  });

  it('classifies unknown cookies as unknown, and conservatively non-deletable', () => {
    const classified = classifyCookie(record({ name: 'mystery_blob', firstParty: false, domain: '.weird.io' }));

    expect(classified.known).toBe(false);
    expect(classified.category).toBe('unknown');
    expect(classified.safeToDelete).toBe('unknown');
    expect(classified.setBy).toBe('weird.io');
  });

  it('recognises __Host- and __Secure- prefixes as security cookies', () => {
    const host = classifyCookie(record({ name: '__Host-token' }));
    const secure = classifyCookie(record({ name: '__Secure-id' }));

    expect(host.known).toBe(false);
    expect(host.category).toBe('essential');
    expect(host.purpose).toBe('security');
    expect(host.safeToDelete).toBe('no');
    expect(secure.category).toBe('essential');
    expect(secure.safeToDelete).toBe('no');
  });

  it('treats session-looking unknown cookies as will-log-out', () => {
    const classified = classifyCookie(record({ name: 'portal_session' }));

    expect(classified.safeToDelete).toBe('will-log-out');
    expect(classified.description).toContain('log you out');
  });

  it('builds a stable id for every classified cookie', () => {
    const classified = classifyCookie(record({ name: '_ga', domain: '.google-analytics.com', storeId: '1' }));
    expect(classified.id).toBe('1|.google-analytics.com|/|_ga');
  });
});

describe('summarizeCookies', () => {
  it('produces the exact summary shape the brief specifies', () => {
    const summary = summarizeCookies(
      [
        classifyCookie(record({ name: 'csrftoken' })),
        classifyCookie(record({ name: 'sessionid' })),
        classifyCookie(record({ name: '_ga', domain: '.google-analytics.com', firstParty: false })),
        classifyCookie(record({ name: '_fbp', domain: '.facebook.com', firstParty: false })),
        classifyCookie(record({ name: 'guest_id', domain: '.twimg.com', firstParty: false })),
        classifyCookie(record({ name: 'mystery' })),
      ],
      NOW,
    );

    expect(summary.total).toBe(6);
    expect(summary.essential).toBe(2);
    expect(summary.analytics).toBe(1);
    expect(summary.advertising).toBe(1);
    expect(summary.social).toBe(1);
    expect(summary.unknown).toBe(1);
    expect(summary.thirdPartyCount).toBe(3);
    expect(summary.persistentCount).toBe(0);
    expect(summary.longestExpirationDays).toBe(0);
    expect(summary.longestExpirationName).toBeNull();
  });

  it('distinguishes session from persistent cookies, and finds the longest lifetime', () => {
    const summary = summarizeCookies(
      [
        classifyCookie(record({ name: 'flashy', session: true })),
        classifyCookie(record({ name: 'short', session: false, expirationDate: (NOW + 10 * DAY) / 1000 })),
        classifyCookie(record({ name: '_ga', session: false, expirationDate: (NOW + 730 * DAY) / 1000 })),
        classifyCookie(record({ name: 'mid', session: false, expirationDate: (NOW + 90 * DAY) / 1000 })),
      ],
      NOW,
    );

    expect(summary.persistentCount).toBe(3);
    expect(summary.longestExpirationDays).toBe(730);
    expect(summary.longestExpirationName).toBe('_ga');
  });

  it('never reports a negative lifetime for an expired cookie', () => {
    const summary = summarizeCookies(
      [classifyCookie(record({ name: 'stale', session: false, expirationDate: (NOW - 5 * DAY) / 1000 }))],
      NOW,
    );

    expect(summary.longestExpirationDays).toBe(0);
    expect(summary.longestExpirationName).toBeNull();
  });
});

describe('removal targets (the only writes Sentinel ever performs)', () => {
  it('builds the exact arguments chrome.cookies.remove() needs', () => {
    const cookie = classifyCookie(
      record({ name: '_fbp', domain: '.facebook.com', path: '/', storeId: '1', secure: true }),
    );
    const target = removalTargetFor(cookie);

    expect(target).toEqual({ name: '_fbp', domain: '.facebook.com', path: '/', storeId: '1', secure: true });
    expect(removalUrlFor(target)).toBe('https://facebook.com/');
  });

  it('keeps the scheme honest for non-secure cookies and normalises the path', () => {
    expect(removalUrlFor({ name: 'a', domain: 'example.com', path: 'sub', storeId: '0', secure: false })).toBe(
      'http://example.com/sub',
    );
    expect(removalUrlFor({ name: 'a', domain: '.example.com', path: '/', storeId: '0', secure: true })).toBe(
      'https://example.com/',
    );
  });
});

describe('trackingCookies (bulk delete selection)', () => {
  it('selects only tracking categories and never essential or unknown cookies', () => {
    const { cookies } = classifyCookies([
      record({ name: '_ga', domain: '.google-analytics.com', firstParty: false }),
      record({ name: '_fbp', domain: '.facebook.com', firstParty: false }),
      record({ name: '__cf_bm' }),
      record({ name: 'mystery' }),
    ]);

    expect(trackingCookies(cookies).map((cookie) => cookie.name).sort()).toEqual(['_fbp', '_ga']);
  });
});

describe('classifyCookies end to end', () => {
  it('classifies a whole list and summarises it in one call', () => {
    const { cookies, summary } = classifyCookies(
      [
        record({ name: '_ga', domain: '.google-analytics.com', firstParty: false }),
        record({ name: 'session', session: false, expirationDate: (NOW + 400 * DAY) / 1000 }),
      ],
      NOW,
    );

    expect(cookies).toHaveLength(2);
    expect(summary.total).toBe(2);
    expect(summary.analytics).toBe(1);
    expect(summary.longestExpirationDays).toBe(400);
  });
});


