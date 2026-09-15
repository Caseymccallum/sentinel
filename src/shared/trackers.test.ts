/**
 * Tracker knowledge-base tests.
 *
 * The knowledge base is data, so what is worth pinning is its *shape* and the matching rule,
 * not the individual vendor list: every category must be described (the popup renders that
 * sentence), every domain must be a plausible registrable domain, no domain may appear twice,
 * and matching must happen on DNS-label boundaries so `notdoubleclick.net` is never reported
 * as `doubleclick.net`.
 */

import { describe, expect, it } from 'vitest';
import {
  TRACKER_CATEGORIES,
  TRACKER_DOMAIN_COUNT,
  TRACKER_ENTRIES,
  classifyTracker,
  trackerCategoryMeta,
  trackerDomains,
} from './trackers';

describe('tracker knowledge base', () => {
  it('declares every category exactly once, with a label, a description and a confidence', () => {
    const ids = TRACKER_CATEGORIES.map((category) => category.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.length).toBeGreaterThanOrEqual(5);

    for (const category of TRACKER_CATEGORIES) {
      expect(category.label.trim()).not.toBe('');
      expect(category.description.trim()).not.toBe('');
      expect(['high', 'medium']).toContain(category.confidence);
      expect(trackerCategoryMeta(category.id).label).toBe(category.label);
    }
  });

  it('gives every entry a domain, a vendor name and a category that exists', () => {
    const categoryIds = new Set(TRACKER_CATEGORIES.map((category) => category.id));

    for (const entry of TRACKER_ENTRIES) {
      expect(entry.domain).toBe(entry.domain.toLowerCase().trim());
      expect(entry.name.trim()).not.toBe('');
      expect(categoryIds.has(entry.category)).toBe(true);
      // A domain with no dot would match nothing meaningful (`com`, `net`).
      expect(entry.domain.includes('.')).toBe(true);
      expect(entry.domain.startsWith('.')).toBe(false);
    }
  });

  it('has no duplicate domains and reports the list length from its own size', () => {
    const domains = trackerDomains();
    expect(domains.length).toBe(TRACKER_ENTRIES.length);
    expect(new Set(domains).size).toBe(TRACKER_ENTRIES.length);
    expect(TRACKER_DOMAIN_COUNT).toBe(TRACKER_ENTRIES.length);
  });

  it('covers roughly 150 domains, so the list is curated rather than a stub', () => {
    expect(TRACKER_DOMAIN_COUNT).toBeGreaterThanOrEqual(150);
  });

  it('resolves a plain domain, its subdomains and its trailing-dot form to one entry', () => {
    const direct = classifyTracker('google-analytics.com');
    expect(direct?.matchedDomain).toBe('google-analytics.com');
    expect(direct?.name).toBe('Google Analytics');
    expect(direct?.category).toBe('analytics');

    const subdomain = classifyTracker('www.google-analytics.com');
    expect(subdomain?.hostname).toBe('www.google-analytics.com');
    expect(subdomain?.matchedDomain).toBe('google-analytics.com');
    expect(subdomain?.categoryLabel).toBe('Analytics');

    expect(classifyTracker('GOOGLE-ANALYTICS.COM.')?.matchedDomain).toBe('google-analytics.com');
  });

  it('walks multiple labels but never matches a label fragment', () => {
    expect(classifyTracker('a.b.c.doubleclick.net')?.matchedDomain).toBe('doubleclick.net');
    // The classic false positive: the tracker name is a suffix of a longer label.
    expect(classifyTracker('notdoubleclick.net')).toBeNull();
    expect(classifyTracker('doubleclick.net.example.com')).toBeNull();
    expect(classifyTracker('mygoogle-analytics.com')).toBeNull();
  });

  it('always reports a description, using the entry override when one exists', () => {
    for (const domain of trackerDomains()) {
      const match = classifyTracker(domain);
      expect(match, domain).not.toBeNull();
      expect(match?.description.trim(), domain).not.toBe('');
      expect(match?.name.trim(), domain).not.toBe('');
    }

    // Category description by default...
    expect(classifyTracker('doubleclick.net')?.description).toMatch(/Google's advertising exchange/);
    // ...and a per-entry override where the vendor's purpose needs its own sentence.
    expect(classifyTracker('connect.facebook.net')?.description).toMatch(/Meta/);
    expect(classifyTracker('hotjar.com')?.description).toMatch(/Records your session/);
  });

  it('keeps the hosts the end-to-end fixtures rely on on the list', () => {
    for (const host of [
      'www.google-analytics.com',
      'connect.facebook.net',
      'static.hotjar.com',
      'cdn.segment.com',
    ]) {
      expect(classifyTracker(host), host).not.toBeNull();
    }
  });

  it('returns null for a host it has never heard of, without throwing on odd input', () => {
    expect(classifyTracker('example.com')).toBeNull();
    expect(classifyTracker('')).toBeNull();
    expect(classifyTracker('   ')).toBeNull();
    expect(classifyTracker('localhost')).toBeNull();
    expect(classifyTracker('127.0.0.1')).toBeNull();
  });

  it('exposes a category lookup that agrees with the full match', () => {
    expect(classifyTracker('static.hotjar.com')?.category).toBe('session-replay');
    expect(classifyTracker('static.hotjar.com')?.confidence).toBe('high');
    expect(classifyTracker('hs-analytics.net')?.confidence).toBe('medium');
  });
});