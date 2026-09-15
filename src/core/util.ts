/** Small, dependency-free helpers shared across Sentinel. */

export function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

/** Rounds to `digits` decimal places without floating point noise. */
export function round(value: number, digits = 0): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** A short, collision-resistant id. Uses `crypto` when available (extension contexts). */
export function createId(prefix = ''): string {
  const random =
    typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function'
      ? Array.from(crypto.getRandomValues(new Uint8Array(6)), (byte) => byte.toString(16).padStart(2, '0')).join('')
      : Math.random().toString(16).slice(2, 14);
  return `${prefix}${Date.now().toString(36)}-${random}`;
}

/** `null` when `value` is not a finite number, so `measured: null` stays meaningful. */
export function toFiniteNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

export function unique<T>(items: readonly T[]): T[] {
  return Array.from(new Set(items));
}

/** Groups items, keeping the first-seen order of keys. */
export function groupBy<T, K extends string>(items: readonly T[], key: (item: T) => K): Map<K, T[]> {
  const map = new Map<K, T[]>();
  for (const item of items) {
    const groupKey = key(item);
    const bucket = map.get(groupKey);
    if (bucket) bucket.push(item);
    else map.set(groupKey, [item]);
  }
  return map;
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function listJoin(items: readonly string[], conjunction = 'and'): string {
  const list = items.filter((item) => item.length > 0);
  if (list.length === 0) return '';
  if (list.length === 1) return list[0] as string;
  if (list.length === 2) return `${list[0]} ${conjunction} ${list[1]}`;
  return `${list.slice(0, -1).join(', ')} ${conjunction} ${list[list.length - 1]}`;
}

/** Percentages rendered without dropping meaningful precision on small numbers. */
export function formatPercent(fraction: number): string {
  return `${round(fraction * 100, fraction < 0.1 ? 1 : 0)}%`;
}

export function formatDateTime(epochMs: number): string {
  const date = new Date(epochMs);
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

export function formatRelativeTime(epochMs: number, now: number = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - epochMs) / 1000));
  if (seconds < 60) return seconds <= 1 ? 'just now' : `${seconds} seconds ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return pluralize(minutes, 'minute') + ' ago';
  const hours = Math.round(minutes / 60);
  if (hours < 24) return pluralize(hours, 'hour') + ' ago';
  const days = Math.round(hours / 24);
  if (days < 31) return pluralize(days, 'day') + ' ago';
  const months = Math.round(days / 30);
  if (months < 12) return pluralize(months, 'month') + ' ago';
  return pluralize(Math.round(months / 12), 'year') + ' ago';
}

/**
 * Stable, order-insensitive hash used for profile signatures (Change Monitor) and
 * cache keys. FNV-1a — tiny, fast, and deterministic across browsers.
 */
export function stableHash(input: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}
