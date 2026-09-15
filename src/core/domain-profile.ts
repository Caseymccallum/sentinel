/**
 * Per-domain memory.
 *
 * Sentinel remembers what it has seen before for each site so the Change Monitor can say
 * "this used to send a Content-Security-Policy and no longer does", and so the popup can
 * show history without keeping a log of pages you visited. Profiles are keyed by
 * *registrable domain* (`shop.example.com` and `www.example.com` share one profile) and
 * hold only counters, host lists and hashes — never paths, queries or page titles.
 *
 * Everything here is pure except `DomainProfileStore`, which persists through an injected
 * adapter so the core never imports a browser API directly.
 */

import { formatRelativeTime, pluralize, round, stableHash } from './util';
import type { ModuleId, ProfileChange, ProfileChangeKind, ScanResult, ScanSummary, Severity } from './types';

// The change contracts live in `src/core/types.ts` (so `ScanResult.changes` can carry them
// without a circular import); re-exported here so existing imports keep working.
export type { ProfileChange, ProfileChangeKind };

/** Cap on how many signal results a stored summary keeps. */
const MAX_SIGNALS_PER_PROFILE = 60;
/** Cap on remembered hosts per list, so a hostname-generating site cannot bloat storage. */
const MAX_KNOWN_HOSTS = 60;
const MAX_NOTES = 20;

export interface DomainProfile {
  /** Registrable domain, e.g. `example.com`. Also the storage key. */
  domain: string;
  /** Most recent hostname observed for this domain. */
  hostname: string;
  createdAt: number;
  updatedAt: number;
  scanCount: number;
  /** Most recent scan; `null` only for a freshly created profile. */
  lastScan: ScanSummary | null;
  best: number | null;
  worst: number | null;
  /** Running sum and count so the average never needs the full history. */
  scoreSum: number;
  scoreCount: number;
  /** Third-party hosts seen for this site, most recent first. */
  thirdPartyHosts: string[];
  /** Subset of `thirdPartyHosts` that matched the local tracker list. */
  trackerHosts: string[];
  /** Subject CN of the certificate last seen, for rotation notices. */
  certificateSubject: string | null;
  notes: string[];
}

export interface ProfileSummary {
  domain: string;
  hostname: string;
  scanCount: number;
  lastScore: number | null;
  averageScore: number | null;
  best: number | null;
  worst: number | null;
  /** Positive = improving versus this site's own average. `null` until two scans exist. */
  trend: number | null;
  lastSeenLabel: string;
  trackerHostCount: number;
  thirdPartyHostCount: number;
  certificateSubject: string | null;
}

export function createDomainProfile(domain: string, hostname: string, now: number): DomainProfile {
  return {
    domain,
    hostname,
    createdAt: now,
    updatedAt: now,
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
  };
}

/** Average score across every scan that produced one, or `null`. */
export function profileAverage(profile: DomainProfile): number | null {
  if (profile.scoreCount === 0) return null;
  return round(profile.scoreSum / profile.scoreCount, 1);
}

/**
 * Folds hostnames into a bounded, most-recent-first list.
 * Exported so tests can exercise the cap without building a whole scan.
 */
export function mergeHosts(
  existing: readonly string[],
  incoming: readonly string[],
  cap = MAX_KNOWN_HOSTS,
): string[] {
  const merged: string[] = [];
  for (const host of incoming) {
    if (host !== '' && !merged.includes(host)) merged.push(host);
  }
  for (const host of existing) {
    if (merged.length >= cap) break;
    if (!merged.includes(host)) merged.push(host);
  }
  return merged.slice(0, cap);
}

/**
 * The security-relevant fingerprint of a scan: which signals fired and what they measured.
 * Two scans sharing a signature behaved the same way, even if the page content changed.
 */
export function scanSignature(result: ScanResult, extra: readonly string[] = []): string {
  const parts = [
    result.isSecureContext ? 'https' : 'http',
    String(result.observation.statusCode ?? ''),
    ...result.findings.map((finding) => `${finding.signalId}=${finding.measured ?? 'na'}`).sort(),
    ...extra.slice().sort(),
  ];
  return stableHash(parts.join('|'));
}

/** The compact, persistent record of one scan. */
export function summarizeScan(result: ScanResult): ScanSummary {
  return {
    scanId: result.scanId,
    url: result.url,
    domain: result.domain,
    scannedAt: result.scannedAt,
    score: result.score?.value ?? null,
    grade: result.score?.grade ?? null,
    trackerCount: result.observation.trackerCount,
    thirdPartyHostCount: result.observation.thirdPartyHostCount,
    headerCount: result.observation.headerCount,
    signalIds: result.findings.map((finding) => finding.signalId).slice(0, MAX_SIGNALS_PER_PROFILE),
    signature: scanSignature(result),
  };
}

export interface RecordScanOptions {
  /** Hostname the scan was taken on; defaults to the existing value. */
  hostname?: string;
  /** Third-party hostnames observed; the profile keeps the most recent `MAX_KNOWN_HOSTS`. */
  thirdPartyHosts?: readonly string[];
  /** Subset of those hosts that matched the local tracker list. */
  trackerHosts?: readonly string[];
  /** Subject CN of the certificate seen this time. */
  certificateSubject?: string | null;
}

function mergeNotes(existing: readonly string[], incoming: readonly string[]): string[] {
  const merged: string[] = [];
  for (const note of incoming) {
    const text = note.trim();
    if (text !== '' && !merged.includes(text)) merged.push(text);
  }
  for (const note of existing) {
    if (merged.length >= MAX_NOTES) break;
    if (!merged.includes(note)) merged.push(note);
  }
  return merged.slice(0, MAX_NOTES);
}

/** Returns a new profile with the scan folded in. Never mutates the input. */
export function applyScan(
  profile: DomainProfile,
  result: ScanResult,
  options: RecordScanOptions = {},
  now: number = Date.now(),
): DomainProfile {
  const summary = summarizeScan(result);
  const score = summary.score;

  return {
    ...profile,
    hostname: options.hostname ?? profile.hostname,
    updatedAt: now,
    scanCount: profile.scanCount + 1,
    lastScan: summary,
    best: score === null ? profile.best : profile.best === null ? score : Math.max(profile.best, score),
    worst: score === null ? profile.worst : profile.worst === null ? score : Math.min(profile.worst, score),
    scoreSum: score === null ? profile.scoreSum : round(profile.scoreSum + score, 4),
    scoreCount: score === null ? profile.scoreCount : profile.scoreCount + 1,
    thirdPartyHosts: mergeHosts(profile.thirdPartyHosts, options.thirdPartyHosts ?? []),
    trackerHosts: mergeHosts(profile.trackerHosts, options.trackerHosts ?? []),
    certificateSubject: options.certificateSubject ?? profile.certificateSubject,
    notes: mergeNotes(profile.notes, [...result.warnings, ...result.observation.notes]),
  };
}

export function summarizeProfile(profile: DomainProfile, now: number = Date.now()): ProfileSummary {
  const average = profileAverage(profile);
  const last = profile.lastScan?.score ?? null;
  return {
    domain: profile.domain,
    hostname: profile.hostname,
    scanCount: profile.scanCount,
    lastScore: last,
    averageScore: average,
    best: profile.best,
    worst: profile.worst,
    trend: average === null || last === null || profile.scanCount < 2 ? null : round(last - average, 1),
    lastSeenLabel: formatRelativeTime(profile.updatedAt, now),
    trackerHostCount: profile.trackerHosts.length,
    thirdPartyHostCount: profile.thirdPartyHosts.length,
    certificateSubject: profile.certificateSubject,
  };
}

/** Human-readable form of a short list of signal ids. */
function shortList(ids: readonly string[], max = 4): string {
  return ids.length <= max ? ids.join(', ') : `${ids.slice(0, max).join(', ')}, and more`;
}

function pushCountChange(
  changes: ProfileChange[],
  kind: ProfileChangeKind,
  before: number,
  after: number,
  noun: string,
): void {
  if (before === after) return;
  const delta = after - before;
  changes.push({
    kind,
    detail: `${pluralize(Math.abs(delta), noun)} ${delta > 0 ? 'more' : 'fewer'} than last time (${before} → ${after}).`,
    severity: delta > 0 ? (kind === 'headers' ? 'medium' : 'low') : 'info',
    worsened: delta > 0,
  });
}

/** Compares two consecutive scans so the Change Monitor can show a digest, worst first. */
export function diffScans(previous: ScanSummary | null, next: ScanSummary): ProfileChange[] {
  if (!previous) {
    return [
      {
        kind: 'signals',
        detail: `First time Sentinel has analysed ${next.domain}.`,
        severity: 'info',
        worsened: false,
      },
    ];
  }

  if (previous.signature === next.signature) {
    return [
      {
        kind: 'signals',
        detail: 'Nothing security-relevant changed since the last visit.',
        severity: 'info',
        worsened: false,
      },
    ];
  }

  const changes: ProfileChange[] = [];

  if (previous.score !== null && next.score !== null && previous.score !== next.score) {
    const delta = next.score - previous.score;
    changes.push({
      kind: 'score',
      detail: `Trust score moved from ${previous.score} to ${next.score} (${delta > 0 ? '+' : ''}${delta}).`,
      severity: delta <= -15 ? 'high' : delta <= -5 ? 'medium' : 'low',
      worsened: delta < 0,
    });
  } else if (previous.score === null && next.score !== null) {
    changes.push({
      kind: 'score',
      detail: `Sentinel could measure this page for the first time and scored it ${next.score}.`,
      severity: 'info',
      worsened: false,
    });
  } else if (previous.score !== null && next.score === null) {
    changes.push({
      kind: 'score',
      detail: 'Sentinel could not measure enough of this page to score it this time.',
      severity: 'low',
      worsened: true,
    });
  }

  pushCountChange(changes, 'trackers', previous.trackerCount, next.trackerCount, 'tracking request');
  pushCountChange(changes, 'third-party', previous.thirdPartyHostCount, next.thirdPartyHostCount, 'third-party host');
  pushCountChange(changes, 'headers', previous.headerCount, next.headerCount, 'response header');

  const added = next.signalIds.filter((id) => !previous.signalIds.includes(id));
  if (added.length > 0) {
    changes.push({
      kind: 'signals',
      detail: `${added.length} new check${added.length === 1 ? '' : 's'} produced a result: ${shortList(added)}.`,
      severity: 'info',
      worsened: false,
    });
  }
  const removed = previous.signalIds.filter((id) => !next.signalIds.includes(id));
  if (removed.length > 0) {
    changes.push({
      kind: 'signals',
      detail: `${removed.length} previous check${removed.length === 1 ? '' : 's'} could not be measured: ${shortList(removed)}.`,
      severity: 'low',
      worsened: false,
    });
  }

  return changes;
}

/** Persistence boundary: implemented in `src/storage/`, never imported by analysers. */
export interface ProfileStorageAdapter {
  read(domain: string): Promise<DomainProfile | null>;
  write(profile: DomainProfile): Promise<void>;
  list(): Promise<DomainProfile[]>;
  remove(domain: string): Promise<void>;
  clear(): Promise<void>;
}

export interface RecordResult {
  profile: DomainProfile;
  changes: ProfileChange[];
}

/** Profiles are capped so storage can never grow without bound. */
export const MAX_PROFILES = 500;

export class DomainProfileStore {
  constructor(
    private readonly adapter: ProfileStorageAdapter,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Folds a completed scan into the site's profile and reports what changed. */
  async record(result: ScanResult, options: RecordScanOptions = {}): Promise<RecordResult> {
    const existing = await this.adapter.read(result.domain);
    const profile = existing ?? createDomainProfile(result.domain, result.domain, result.scannedAt);
    const previous = profile.lastScan;
    const next = applyScan(profile, result, options, this.now());
    await this.adapter.write(next);
    await this.prune();
    const summary = next.lastScan ?? summarizeScan(result);
    return { profile: next, changes: diffScans(previous, summary) };
  }

  async get(domain: string): Promise<DomainProfile | null> {
    return this.adapter.read(domain);
  }

  /** All profiles, most recently seen first. */
  async list(): Promise<DomainProfile[]> {
    const profiles = await this.adapter.list();
    return profiles.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  async forget(domain: string): Promise<void> {
    await this.adapter.remove(domain);
  }

  async clear(): Promise<void> {
    await this.adapter.clear();
  }

  /** Drops the least recently seen profiles once the cap is exceeded. */
  private async prune(): Promise<void> {
    const profiles = await this.adapter.list();
    if (profiles.length <= MAX_PROFILES) return;
    const excess = profiles.sort((a, b) => b.updatedAt - a.updatedAt).slice(MAX_PROFILES);
    for (const profile of excess) await this.adapter.remove(profile.domain);
  }
}

/** In-memory adapter for tests and for the "session only" setting. */
export function createMemoryProfileAdapter(seed: readonly DomainProfile[] = []): ProfileStorageAdapter {
  const map = new Map<string, DomainProfile>(seed.map((profile) => [profile.domain, profile]));
  return {
    async read(domain) {
      return map.get(domain) ?? null;
    },
    async write(profile) {
      map.set(profile.domain, profile);
    },
    async list() {
      return Array.from(map.values());
    },
    async remove(domain) {
      map.delete(domain);
    },
    async clear() {
      map.clear();
    },
  };
}

/** How many findings each module contributed; drives the popup's module list. */
export function findingsByModule(result: ScanResult): Partial<Record<ModuleId, number>> {
  const counts: Partial<Record<ModuleId, number>> = {};
  for (const finding of result.findings) {
    counts[finding.moduleId] = (counts[finding.moduleId] ?? 0) + 1;
  }
  return counts;
}
