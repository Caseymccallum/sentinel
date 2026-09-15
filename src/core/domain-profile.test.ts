/**
 * DomainProfile tests.
 *
 * A profile is what Sentinel remembers about a site between visits, so the things worth
 * proving are: nothing is remembered that should not be (no URLs, no queries), the running
 * numbers (best/worst/average) can never drift, host lists stay bounded, the change digest
 * says something true about two consecutive scans, and the store persists through an
 * injected adapter so it can be tested without `chrome.storage`.
 */

import { describe, expect, it } from 'vitest';
import {
  DomainProfileStore,
  MAX_PROFILES,
  applyScan,
  createDomainProfile,
  createMemoryProfileAdapter,
  diffScans,
  findingsByModule,
  mergeHosts,
  profileAverage,
  scanSignature,
  summarizeProfile,
  summarizeScan,
} from './domain-profile';
import { TrustEngine } from './trust-engine';
import type { DomainProfile, ProfileChange } from './domain-profile';
import type { Finding, ScanResult, ScanSummary } from './types';
import { TRUST_SCORE_ANALYZERS } from '../modules/trust-score/signals';
import type { PageObservation, RequestRecord } from '../shared/observation';

const NOW = 1_700_000_000_000;
const engine = new TrustEngine({ analyzers: TRUST_SCORE_ANALYZERS, clock: () => NOW });

function request(hostname: string, kind: RequestRecord['kind'] = 'script'): RequestRecord {
  return {
    requestId: `req-${hostname}-${kind}`,
    url: `https://${hostname}/${kind}`,
    hostname,
    thirdParty: hostname !== 'shop.example.com',
    kind,
    initiatorHostname: 'shop.example.com',
    statusCode: 200,
    fromCache: false,
  };
}

function observation(overrides: Partial<PageObservation> = {}): PageObservation {
  return {
    observationId: 'obs-1',
    tabId: 7,
    frameId: 0,
    // Query strings and fragments are exactly what must never reach a stored profile.
    url: 'https://shop.example.com/checkout?token=secret#step-two',
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 900,
    updatedAt: NOW,
    mainDocument: {
      url: 'https://shop.example.com/checkout?token=secret',
      statusCode: 200,
      statusLine: 'HTTP/1.1 200 OK',
      serverIp: '203.0.113.7',
      fromCache: false,
      headers: [
        { name: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains' },
        { name: 'x-content-type-options', value: 'nosniff' },
      ],
      tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
    },
    requests: [],
    requestsTruncated: false,
    dom: null,
    warnings: [],
    ...overrides,
  };
}

function scanResult(overrides: Partial<PageObservation> = {}, now = NOW): ScanResult {
  return engine.run(observation(overrides), { now });
}

function summary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    scanId: 'scan-1',
    url: 'https://shop.example.com/checkout',
    domain: 'example.com',
    scannedAt: NOW,
    score: 90,
    grade: 'A-',
    trackerCount: 0,
    thirdPartyHostCount: 0,
    headerCount: 6,
    signalIds: ['connection.https', 'headers.csp'],
    signature: 'abc12345',
    ...overrides,
  };
}

function finding(signalId: string): Finding {
  return {
    signalId,
    title: signalId,
    measured: 100,
    confidence: 'high',
    detail: `${signalId} detail`,
    evidence: [],
    categoryId: 'headers',
    moduleId: 'trust-score',
    severity: 'info',
    maxImpact: 12,
    impact: 0,
  };
}

function details(changes: readonly ProfileChange[]): string[] {
  return changes.map((change) => change.detail);
}

describe('createDomainProfile', () => {
  it('starts empty and remembers nothing but counters', () => {
    const profile = createDomainProfile('example.com', 'shop.example.com', NOW);

    expect(profile).toEqual({
      domain: 'example.com',
      hostname: 'shop.example.com',
      createdAt: NOW,
      updatedAt: NOW,
      scanCount: 0,
      lastScan: null,
      best: null,
      worst: null,
      scoreSum: 0,
      scoreCount: 0,
      thirdPartyHosts: [],
      trackerHosts: [],
      certificateSubject: null,
      notes: [],
    });
  });
});

describe('profileAverage', () => {
  it('is null until at least one scan produced a score', () => {
    expect(profileAverage(createDomainProfile('example.com', 'example.com', NOW))).toBeNull();
  });

  it('rounds the running average to one decimal place', () => {
    const profile = { ...createDomainProfile('example.com', 'example.com', NOW), scoreSum: 295, scoreCount: 3 };
    expect(profileAverage(profile)).toBe(98.3);

    const halves = { ...profile, scoreSum: 255, scoreCount: 2 };
    expect(profileAverage(halves)).toBe(127.5);
  });
});

describe('mergeHosts', () => {
  it('puts the newest hosts first, removes duplicates and drops blanks', () => {
    expect(mergeHosts(['old.example'], ['new.example', 'old.example', ''])).toEqual([
      'new.example',
      'old.example',
    ]);
  });

  it('keeps the list bounded', () => {
    const existing = Array.from({ length: 10 }, (_, index) => `existing${index}.example`);
    const merged = mergeHosts(existing, ['new.example'], 3);

    expect(merged).toEqual(['new.example', 'existing0.example', 'existing1.example']);
  });
});

describe('scanSignature', () => {
  it('ignores the order the analysers reported in', () => {
    const base = scanResult();
    const shuffled: ScanResult = { ...base, findings: [...base.findings].reverse() };

    expect(scanSignature(shuffled)).toBe(scanSignature(base));
    expect(scanSignature(base)).toMatch(/^[0-9a-f]{8}$/);
  });

  it('changes when a measurement changes', () => {
    const base = scanResult();
    const changed: ScanResult = {
      ...base,
      findings: base.findings.map((entry) =>
        entry.signalId === 'connection.https' ? { ...entry, measured: 0 } : entry,
      ),
    };

    expect(scanSignature(changed)).not.toBe(scanSignature(base));
  });

  it('changes when the scheme, status code or extra facts change', () => {
    const base = scanResult();
    const insecure: ScanResult = { ...base, isSecureContext: false };
    const cached: ScanResult = { ...base, observation: { ...base.observation, statusCode: 304 } };

    expect(scanSignature(insecure)).not.toBe(scanSignature(base));
    expect(scanSignature(cached)).not.toBe(scanSignature(base));
    expect(scanSignature(base, ['extra'])).not.toBe(scanSignature(base));
    expect(scanSignature(base, ['extra'])).toBe(scanSignature(base, ['extra']));
  });
});

describe('summarizeScan', () => {
  it('keeps only the compact, security-relevant facts', () => {
    const result = scanResult({ requests: [request('www.google-analytics.com'), request('cdn.example.net')] });
    const stored = summarizeScan(result);

    expect(stored).toEqual({
      scanId: result.scanId,
      url: result.url,
      domain: 'example.com',
      scannedAt: NOW,
      score: result.score?.value ?? null,
      grade: result.score?.grade ?? null,
      trackerCount: result.observation.trackerCount,
      thirdPartyHostCount: result.observation.thirdPartyHostCount,
      headerCount: 2,
      signalIds: result.findings.map((entry) => entry.signalId),
      signature: scanSignature(result),
    });
    expect(stored.url).not.toContain('?');
    expect(stored.url).not.toContain('#');
    expect(stored.trackerCount).toBe(1);
    expect(stored.thirdPartyHostCount).toBe(2);
  });

  it('caps the remembered signal list', () => {
    const base = scanResult();
    const crowded: ScanResult = {
      ...base,
      findings: Array.from({ length: 70 }, (_, index) => finding(`signal.${index}`)),
    };

    expect(summarizeScan(crowded).signalIds).toHaveLength(60);
    expect(summarizeScan(crowded).signalIds[0]).toBe('signal.0');
  });
});

describe('applyScan', () => {
  it('folds a scan into a fresh profile and never mutates the input', () => {
    const profile = createDomainProfile('example.com', 'example.com', NOW - 1000);
    const untouched = structuredClone(profile);
    const result = scanResult();
    const value = result.score?.value ?? 0;

    const next = applyScan(profile, result, {}, NOW);

    expect(profile).toEqual(untouched);
    expect(next).not.toBe(profile);
    expect(next.scanCount).toBe(1);
    expect(next.updatedAt).toBe(NOW);
    expect(next.createdAt).toBe(NOW - 1000);
    expect(next.lastScan).toEqual(summarizeScan(result));
    expect(next.scoreSum).toBe(value);
    expect(next.scoreCount).toBe(1);
    expect(next.best).toBe(value);
    expect(next.worst).toBe(value);
  });

  it('tracks the best and worst score without keeping a history', () => {
    const base = scanResult();
    const baseValue = base.score?.value ?? 0;
    const higher: ScanResult = { ...base, score: { ...base.score!, value: 97, grade: 'A+' } };
    const lower: ScanResult = { ...base, score: { ...base.score!, value: 61, grade: 'D-' } };

    let profile = applyScan(createDomainProfile('example.com', 'example.com', NOW), base, {}, NOW);
    profile = applyScan(profile, higher, {}, NOW + 1);
    profile = applyScan(profile, lower, {}, NOW + 2);

    const expectedAverage = Math.round(((baseValue + 97 + 61) / 3) * 10) / 10;

    expect(profile.scanCount).toBe(3);
    expect(profile.best).toBe(97);
    expect(profile.worst).toBe(61);
    expect(profileAverage(profile)).toBe(expectedAverage);
  });

  it('leaves the score statistics alone when a scan could not be scored', () => {
    const scored = scanResult();
    const unscored: ScanResult = { ...scored, score: null };

    const once = applyScan(createDomainProfile('example.com', 'example.com', NOW), scored, {}, NOW);
    const twice = applyScan(once, unscored, {}, NOW + 1);

    expect(twice.scanCount).toBe(2);
    expect(twice.lastScan?.score).toBeNull();
    expect(twice.scoreCount).toBe(1);
    expect(twice.scoreSum).toBe(scored.score?.value);
    expect(twice.best).toBe(scored.score?.value);
    expect(twice.worst).toBe(scored.score?.value);
  });

  it('merges host lists, the certificate subject and the notes it was given', () => {
    const profile = createDomainProfile('example.com', 'example.com', NOW);
    const result = scanResult({ warnings: ['Headers were captured late.'] });

    const first = applyScan(
      profile,
      result,
      {
        hostname: 'shop.example.com',
        thirdPartyHosts: ['www.google-analytics.com', 'cdn.example.net'],
        trackerHosts: ['www.google-analytics.com'],
        certificateSubject: 'shop.example.com',
      },
      NOW,
    );
    const second = applyScan(
      first,
      result,
      { thirdPartyHosts: ['cdn.example.net', 'embed.example.org'], certificateSubject: 'other.example.com' },
      NOW + 1,
    );

    expect(first.hostname).toBe('shop.example.com');
    expect(first.certificateSubject).toBe('shop.example.com');
    expect(second.certificateSubject).toBe('other.example.com');
    expect(second.thirdPartyHosts).toEqual(['cdn.example.net', 'embed.example.org', 'www.google-analytics.com']);
    expect(second.trackerHosts).toEqual(['www.google-analytics.com']);
    expect(second.notes[0]).toBe('Headers were captured late.');
    expect(second.notes).toContain(
      'No page report arrived from the content script, so checks that need the page itself were skipped.',
    );
    expect(new Set(second.notes).size).toBe(second.notes.length);
  });

  it('falls back to the existing hostname and keeps the profile key', () => {
    const profile = createDomainProfile('example.com', 'www.example.com', NOW);
    const next = applyScan(profile, scanResult(), {}, NOW);

    expect(next.domain).toBe('example.com');
    expect(next.hostname).toBe('www.example.com');
  });
});

describe('summarizeProfile', () => {
  it('summarises a profile that has never been scanned', () => {
    const profile = createDomainProfile('example.com', 'www.example.com', NOW);

    expect(summarizeProfile(profile, NOW)).toEqual({
      domain: 'example.com',
      hostname: 'www.example.com',
      scanCount: 0,
      lastScore: null,
      averageScore: null,
      best: null,
      worst: null,
      trend: null,
      lastSeenLabel: 'just now',
      trackerHostCount: 0,
      thirdPartyHostCount: 0,
      certificateSubject: null,
    });
  });

  it('reports the trend once there is more than one scan to compare', () => {
    const base = scanResult();
    const baseValue = base.score?.value ?? 0;
    const higher: ScanResult = { ...base, score: { ...base.score!, value: 97, grade: 'A+' } };
    const lower: ScanResult = { ...base, score: { ...base.score!, value: 61, grade: 'D-' } };

    const single = applyScan(createDomainProfile('example.com', 'example.com', NOW), base, {}, NOW);
    const pair = applyScan(single, higher, {}, NOW + 1);
    const triple = applyScan(pair, lower, {}, NOW + 2);

    /** Mirrors the implementation: the average is rounded to one decimal, then subtracted. */
    const average = (values: readonly number[]) =>
      Math.round((values.reduce((total, value) => total + value, 0) / values.length) * 10) / 10;
    const trendFrom = (last: number, values: readonly number[]) => Math.round((last - average(values)) * 10) / 10;

    expect(summarizeProfile(single, NOW).trend).toBeNull();
    expect(summarizeProfile(pair, NOW).trend).toBe(trendFrom(97, [baseValue, 97]));
    expect(summarizeProfile(triple, NOW).trend).toBe(trendFrom(61, [baseValue, 97, 61]));
    expect(summarizeProfile(triple, NOW + 5 * 60 * 1000).lastSeenLabel).toBe('5 minutes ago');
  });

  it('carries the remembered host counts and certificate subject into the summary', () => {
    const result = scanResult();
    const profile = applyScan(
      createDomainProfile('example.com', 'example.com', NOW),
      result,
      {
        thirdPartyHosts: ['cdn.example.net', 'www.google-analytics.com'],
        trackerHosts: ['www.google-analytics.com'],
        certificateSubject: 'shop.example.com',
      },
      NOW,
    );

    expect(summarizeProfile(profile, NOW)).toMatchObject({
      trackerHostCount: 1,
      thirdPartyHostCount: 2,
      certificateSubject: 'shop.example.com',
      worst: result.score?.value ?? null,
    });
  });
});

/** U+2192 RIGHTWARDS ARROW, used by the count-change sentences. */
const ARROW = '\u2192';

function diff(previous: Partial<ScanSummary>, next: Partial<ScanSummary>): ProfileChange[] {
  return diffScans(summary({ ...previous, signature: 'prev' }), summary({ ...next, signature: 'next' }));
}

describe('diffScans', () => {
  it('announces a first visit', () => {
    expect(diffScans(null, summary())).toEqual([
      { kind: 'signals', detail: 'First time Sentinel has analysed example.com.', severity: 'info', worsened: false },
    ]);
  });

  it('says nothing security-relevant changed when the signatures match', () => {
    expect(diffScans(summary({ signature: 'same' }), summary({ signature: 'same' }))).toEqual([
      {
        kind: 'signals',
        detail: 'Nothing security-relevant changed since the last visit.',
        severity: 'info',
        worsened: false,
      },
    ]);
  });

  it('grades a score move by how far it fell or rose', () => {
    expect(diff({ score: 80 }, { score: 60 })).toEqual([
      { kind: 'score', detail: 'Trust score moved from 80 to 60 (-20).', severity: 'high', worsened: true },
    ]);
    expect(diff({ score: 80 }, { score: 75 })[0]).toMatchObject({ severity: 'medium', worsened: true });
    expect(diff({ score: 80 }, { score: 76 })[0]).toMatchObject({ severity: 'low', worsened: true });
    expect(diff({ score: 80 }, { score: 95 })[0]).toMatchObject({
      detail: 'Trust score moved from 80 to 95 (+15).',
      severity: 'low',
      worsened: false,
    });
  });

  it('handles a score that appears or disappears', () => {
    expect(diff({ score: null, grade: null }, { score: 60 })[0]).toEqual({
      kind: 'score',
      detail: 'Sentinel could measure this page for the first time and scored it 60.',
      severity: 'info',
      worsened: false,
    });
    expect(diff({ score: 60 }, { score: null, grade: null })[0]).toEqual({
      kind: 'score',
      detail: 'Sentinel could not measure enough of this page to score it this time.',
      severity: 'low',
      worsened: true,
    });
  });

  it('reports count changes in plain language, with the right noun', () => {
    expect(details(diff({ trackerCount: 0 }, { trackerCount: 2 }))).toEqual([
      `2 tracking requests more than last time (0 ${ARROW} 2).`,
    ]);
    expect(diff({ trackerCount: 0 }, { trackerCount: 2 })[0]).toMatchObject({
      kind: 'trackers',
      severity: 'low',
      worsened: true,
    });
    expect(diff({ thirdPartyHostCount: 1 }, { thirdPartyHostCount: 3 })[0]).toMatchObject({
      kind: 'third-party',
      detail: `2 third-party hosts more than last time (1 ${ARROW} 3).`,
      severity: 'low',
      worsened: true,
    });
    expect(diff({ headerCount: 6 }, { headerCount: 3 })[0]).toMatchObject({
      kind: 'headers',
      detail: `3 response headers fewer than last time (6 ${ARROW} 3).`,
      severity: 'info',
      worsened: false,
    });
    expect(diff({ headerCount: 0 }, { headerCount: 1 })[0]).toMatchObject({ severity: 'medium' });
  });

  it('notes checks that produced a result and checks that went missing', () => {
    const added = diff({ signalIds: ['a'] }, { signalIds: ['a', 'b'] });
    const removed = diff({ signalIds: ['a', 'b'] }, { signalIds: ['a'] });

    expect(added).toEqual([
      { kind: 'signals', detail: '1 new check produced a result: b.', severity: 'info', worsened: false },
    ]);
    expect(removed).toEqual([
      { kind: 'signals', detail: '1 previous check could not be measured: b.', severity: 'low', worsened: false },
    ]);
  });

  it('abbreviates a long list of changed checks', () => {
    const previous = { signalIds: ['a'] };
    const next = { signalIds: ['a', 'b', 'c', 'd', 'e', 'f'] };

    expect(diff(previous, next)[0]?.detail).toBe(
      '5 new checks produced a result: b, c, d, e, and more.',
    );
  });

  it('orders the digest worst first: score, hosts, headers, then checks', () => {
    const changes = diff(
      { score: 80, trackerCount: 0, thirdPartyHostCount: 0, headerCount: 6, signalIds: ['a'] },
      { score: 60, trackerCount: 2, thirdPartyHostCount: 3, headerCount: 4, signalIds: ['a', 'b'] },
    );

    expect(changes.map((change) => change.kind)).toEqual([
      'score',
      'trackers',
      'third-party',
      'headers',
      'signals',
    ]);
    expect(changes.filter((change) => change.worsened)).toHaveLength(3);
  });
});

describe('DomainProfileStore', () => {
  it('records a scan, reports the first visit and persists through the adapter', async () => {
    const adapter = createMemoryProfileAdapter();
    const store = new DomainProfileStore(adapter, () => NOW);

    const first = await store.record(scanResult(), { hostname: 'shop.example.com' });

    expect(first.profile.scanCount).toBe(1);
    expect(first.profile.updatedAt).toBe(NOW);
    expect(first.profile.hostname).toBe('shop.example.com');
    expect(details(first.changes)).toEqual(['First time Sentinel has analysed example.com.']);
    await expect(store.get('example.com')).resolves.toEqual(first.profile);
    await expect(store.get('other.example')).resolves.toBeNull();
  });

  it('diffs every scan against the previous one for the same domain', async () => {
    const adapter = createMemoryProfileAdapter();
    const store = new DomainProfileStore(adapter, () => NOW);
    const first = scanResult();
    const second: ScanResult = {
      ...first,
      isSecureContext: false,
      observation: { ...first.observation, trackerCount: 2, thirdPartyHostCount: 2 },
    };

    await store.record(first, { hostname: 'shop.example.com' });
    const recorded = await store.record(second, {
      hostname: 'shop.example.com',
      thirdPartyHosts: ['cdn.example.net', 'www.google-analytics.com'],
    });

    expect(recorded.profile.scanCount).toBe(2);
    expect(recorded.changes.map((change) => change.kind)).toEqual(['trackers', 'third-party']);
    expect(recorded.changes[0]?.detail).toBe(`2 tracking requests more than last time (0 ${ARROW} 2).`);
    expect(recorded.profile.thirdPartyHosts).toEqual(['cdn.example.net', 'www.google-analytics.com']);
  });

  it('says nothing changed when the same scan is recorded twice', async () => {
    const adapter = createMemoryProfileAdapter();
    const store = new DomainProfileStore(adapter, () => NOW);
    const result = scanResult();

    await store.record(result);
    const again = await store.record(result);

    expect(details(again.changes)).toEqual(['Nothing security-relevant changed since the last visit.']);
    expect(again.profile.scanCount).toBe(2);
    expect(again.profile.lastScan?.signature).toBe(summarizeScan(result).signature);
  });

  it('lists the most recently seen profiles first', async () => {
    const seed = [1, 2, 3].map((index) => ({
      ...createDomainProfile(`site${index}.example`, `site${index}.example`, index),
      updatedAt: index,
    }));
    const store = new DomainProfileStore(createMemoryProfileAdapter(seed), () => NOW);

    const listed = await store.list();

    expect(listed.map((profile) => profile.domain)).toEqual([
      'site3.example',
      'site2.example',
      'site1.example',
    ]);
  });

  it('forgets one domain, or everything', async () => {
    const store = new DomainProfileStore(createMemoryProfileAdapter(), () => NOW);
    await store.record(scanResult());
    await store.record({ ...scanResult(), domain: 'other.example', url: 'https://other.example/' });

    await store.forget('example.com');
    expect(await store.get('example.com')).toBeNull();
    expect(await store.get('other.example')).not.toBeNull();

    await store.clear();
    expect(await store.list()).toEqual([]);
  });

  it('prunes the least recently seen profile once the cap is exceeded', async () => {
    const seed = Array.from({ length: MAX_PROFILES }, (_, index) => ({
      ...createDomainProfile(`site${index}.example`, `site${index}.example`, index),
      updatedAt: index,
    }));
    const adapter = createMemoryProfileAdapter(seed);
    const store = new DomainProfileStore(adapter, () => NOW);

    await store.record(scanResult());

    const remaining = await adapter.list();
    expect(remaining).toHaveLength(MAX_PROFILES);
    expect(remaining.some((profile) => profile.domain === 'site0.example')).toBe(false);
    expect(remaining.some((profile) => profile.domain === 'example.com')).toBe(true);
  });
});

describe('findingsByModule', () => {
  it('counts the findings each module contributed', () => {
    const result = scanResult();

    // Phase 2: the cookie analyser contributes its three signals (unmeasured for this fixture,
    // which never collected cookies), so the counts span both active modules.
    expect(findingsByModule(result)).toEqual({
      'trust-score': result.findings.length - 3,
      'cookie-transparency': 3,
    });
    expect(findingsByModule({ ...result, findings: [] })).toEqual({});
  });
});