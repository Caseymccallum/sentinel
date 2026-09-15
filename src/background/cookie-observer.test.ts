/**
 * Cookie observer tests.
 *
 * The critical test here is the safety proof: a canary value flows through the mock cookie API
 * and must appear nowhere in the observer's output — not as a property, not in a serialised
 * blob, nowhere. Everything else is ordinary enumeration behaviour: the two query shapes, the
 * merge/dedupe between them, first-party computation, and the empty/single/50-cookie cases.
 */

import { describe, expect, it } from 'vitest';
import {
  MAX_THIRD_PARTY_COOKIE_QUERIES,
  cookieKey,
  getCookiesForTab,
  mergeCookieRecords,
  observeCookies,
  toCookieRecord,
  type CookiesApi,
  type RawCookie,
} from './cookie-observer';

const PAGE_URL = 'https://shop.example.com/cart';
const PAGE_HOST = 'shop.example.com';
const CANARY = 'SECRET-CANARY-VALUE-do-not-leak';

function raw(overrides: Partial<RawCookie> = {}): RawCookie {
  return {
    name: '_ga',
    domain: '.shop.example.com',
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'lax',
    session: false,
    expirationDate: 1_900_000_000,
    storeId: '0',
    value: CANARY,
    ...overrides,
  };
}

/** A mock cookie store: answers `url` queries and per-`domain` queries from separate jars. */
function mockApi(jars: { url?: RawCookie[]; domains?: Record<string, RawCookie[]> } = {}): CookiesApi & {
  queries: { url?: string; domain?: string }[];
} {
  const queries: { url?: string; domain?: string }[] = [];
  return {
    queries,
    async getAll(details) {
      queries.push(details);
      if (details.url !== undefined) return [...(jars.url ?? [])];
      if (details.domain !== undefined) return [...(jars.domains?.[details.domain] ?? [])];
      return [];
    },
  };
}

describe('toCookieRecord (the safety contract)', () => {
  it('keeps the value length and never the value itself', () => {
    const record = toCookieRecord(raw(), PAGE_HOST);

    expect(record.valueLength).toBe(CANARY.length);
    expect('value' in record).toBe(false);
    expect((record as unknown as { value?: unknown }).value).toBeUndefined();
  });

  it('survives serialisation without leaking the value', () => {
    const records = [
      toCookieRecord(raw(), PAGE_HOST),
      toCookieRecord(raw({ name: '_fbp', domain: '.facebook.com' }), PAGE_HOST),
      toCookieRecord(raw({ name: 'sessionid', value: undefined }), PAGE_HOST),
    ];

    expect(JSON.stringify(records)).not.toContain(CANARY);
    expect(String(records)).not.toContain(CANARY);
  });

  it('computes firstParty from the page hostname at registrable-domain boundaries', () => {
    expect(toCookieRecord(raw({ domain: '.example.com' }), PAGE_HOST).firstParty).toBe(true);
    expect(toCookieRecord(raw({ domain: 'shop.example.com' }), PAGE_HOST).firstParty).toBe(true);
    expect(toCookieRecord(raw({ domain: '.facebook.com' }), PAGE_HOST).firstParty).toBe(false);
  });

  it('normalises missing fields to their honest defaults', () => {
    const record = toCookieRecord(
      raw({ session: true, expirationDate: undefined, sameSite: undefined, storeId: undefined, secure: false }),
      PAGE_HOST,
    );

    expect(record.session).toBe(true);
    expect(record.sameSite).toBe('unspecified');
    expect(record.storeId).toBe('0');
    expect(record.secure).toBe(false);
  });

  it('keeps the expiration date only for persistent cookies', () => {
    expect(toCookieRecord(raw({ session: false, expirationDate: 1_900_000_000 }), PAGE_HOST).expirationDate).toBe(
      1_900_000_000,
    );
    expect(
      toCookieRecord(raw({ session: true, expirationDate: 1_900_000_000 }), PAGE_HOST).expirationDate,
    ).toBeUndefined();
  });
});

describe('observeCookies', () => {
  it('handles an empty cookie list', async () => {
    const api = mockApi();
    const records = await observeCookies(PAGE_URL, PAGE_HOST, [], api);

    expect(records).toEqual([]);
    expect(api.queries).toEqual([{ url: PAGE_URL }]);
  });

  it('handles a single cookie', async () => {
    const api = mockApi({ url: [raw()] });
    const records = await observeCookies(PAGE_URL, PAGE_HOST, [], api);

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ name: '_ga', firstParty: true, valueLength: CANARY.length });
  });

  it('handles 50 cookies without dropping or mangling any', async () => {
    const jars = Array.from({ length: 50 }, (_, index) =>
      raw({ name: `cookie_${index}`, domain: '.shop.example.com', value: `v${index}`.repeat(3) }),
    );
    const api = mockApi({ url: jars });
    const records = await observeCookies(PAGE_URL, PAGE_HOST, [], api);

    expect(records).toHaveLength(50);
    for (const [index, record] of records.entries()) {
      expect(record.name).toBe(`cookie_${index}`);
      expect(record.valueLength).toBe(`v${index}`.repeat(3).length);
    }
    expect(JSON.stringify(records)).not.toContain(CANARY);
  });

  it('queries third-party origins the tracker observer detected and tags them', async () => {
    const api = mockApi({
      url: [raw({ name: 'session' })],
      domains: {
        'facebook.com': [raw({ name: '_fbp', domain: '.facebook.com' })],
        'google-analytics.com': [raw({ name: '_ga', domain: '.google-analytics.com' })],
      },
    });
    const records = await observeCookies(PAGE_URL, PAGE_HOST, ['facebook.com', 'google-analytics.com'], api);

    expect(records).toHaveLength(3);
    expect(api.queries).toEqual([
      { url: PAGE_URL },
      { domain: 'facebook.com' },
      { domain: 'google-analytics.com' },
    ]);
    const fbp = records.find((record) => record.name === '_fbp');
    expect(fbp?.observedOrigin).toBe('facebook.com');
    expect(fbp?.firstParty).toBe(false);
  });

  it('skips third-party origins that are actually the page itself, and caps the query count', async () => {
    const domains: Record<string, RawCookie[]> = {};
    for (let index = 0; index < MAX_THIRD_PARTY_COOKIE_QUERIES + 5; index += 1) {
      domains[`host${index}.example`] = [raw({ name: `c${index}` })];
    }
    const api = mockApi({ domains });
    const records = await observeCookies(
      PAGE_URL,
      PAGE_HOST,
      ['shop.example.com', 'other.shop.example.com', ...Object.keys(domains)],
      api,
    );

    // One query per capped third-party origin; `shop.example.com` shares the page's registrable
    // domain, so it is the page's own jar and is never queried separately.
    expect(api.queries).toHaveLength(MAX_THIRD_PARTY_COOKIE_QUERIES + 1);
    expect(records.every((record) => record.firstParty || record.observedOrigin !== undefined)).toBe(true);
  });

  it('merges the two passes without duplicating a cookie', async () => {
    const api = mockApi({
      url: [raw({ name: '_ga', domain: '.google-analytics.com' })],
      domains: {
        'google-analytics.com': [
          raw({ name: '_ga', domain: '.google-analytics.com' }),
          raw({ name: '_gid', domain: '.google-analytics.com' }),
        ],
      },
    });
    const records = await observeCookies(PAGE_URL, PAGE_HOST, ['google-analytics.com'], api);

    expect(records.map((record) => record.name).sort()).toEqual(['_ga', '_gid']);
  });
});

describe('getCookiesForTab', () => {
  it('returns null when the tab has no URL, so the caller records "could not look"', async () => {
    const records = await getCookiesForTab(1, [], {
      cookies: mockApi(),
      getTabUrl: async () => null,
    });

    expect(records).toBeNull();
  });

  it('returns null when the cookie API throws, never a fabricated empty list', async () => {
    const records = await getCookiesForTab(1, [], {
      cookies: {
        getAll: async () => {
          throw new Error('cookie store unavailable');
        },
      },
      getTabUrl: async () => PAGE_URL,
    });

    expect(records).toBeNull();
  });

  it('returns records for a healthy tab, still without values', async () => {
    const records = await getCookiesForTab(7, ['facebook.com'], {
      cookies: mockApi({
        url: [raw()],
        domains: { 'facebook.com': [raw({ name: '_fbp', domain: '.facebook.com' })] },
      }),
      getTabUrl: async () => PAGE_URL,
    });

    expect(records).toHaveLength(2);
    expect(JSON.stringify(records)).not.toContain(CANARY);
  });
});

describe('mergeCookieRecords and cookieKey', () => {
  it('deduplicates on store, domain, path and name, keeping the first sighting', () => {
    const first = toCookieRecord(raw({ name: '_ga', domain: '.google-analytics.com' }), PAGE_HOST);
    const second = toCookieRecord(
      raw({ name: '_ga', domain: '.google-analytics.com' }),
      PAGE_HOST,
      'google-analytics.com',
    );
    const other = toCookieRecord(raw({ name: '_gid', domain: '.google-analytics.com' }), PAGE_HOST, 'google-analytics.com');

    const merged = mergeCookieRecords([first], [second, other]);

    expect(merged).toHaveLength(2);
    expect(merged.find((record) => record.name === '_ga')?.observedOrigin).toBeUndefined();
    expect(merged.find((record) => record.name === '_gid')?.observedOrigin).toBe('google-analytics.com');
  });

  it('treats differing case in domains as the same cookie', () => {
    expect(cookieKey({ storeId: '0', domain: '.Example.com', path: '/', name: 'a' })).toBe(
      cookieKey({ storeId: '0', domain: '.example.com', path: '/', name: 'a' }),
    );
  });
});



