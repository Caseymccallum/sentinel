import { describe, expect, it } from 'vitest';
import { RECOMMENDED_HEADERS, buildHeaderDashboard } from './dashboard';
import type { MainDocumentObservation } from '../../shared/observation';

function mainDocument(
  headers: MainDocumentObservation['headers'],
  overrides: Partial<MainDocumentObservation> = {},
): MainDocumentObservation {
  return {
    url: 'https://shop.example.com/',
    statusCode: 200,
    statusLine: 'HTTP/1.1 200 OK',
    serverIp: '203.0.113.7',
    fromCache: false,
    headers,
    tls: null,
    ...overrides,
  };
}

describe('buildHeaderDashboard', () => {
  it('reports "not observed" honestly when there is no main document', () => {
    const report = buildHeaderDashboard(null);
    expect(report.available).toBe(false);
    expect(report.observedCount).toBe(0);
    expect(report.rows).toEqual([]);
  });

  it('lists the recommended headers first, in knowledge-base order, with their values', () => {
    const report = buildHeaderDashboard(
      mainDocument([{ name: 'x-custom', value: '1' }, { name: 'content-security-policy', value: "default-src 'self'" }]),
    );
    expect(report.available).toBe(true);
    expect(report.rows[0]).toMatchObject({
      name: 'content-security-policy',
      label: 'Content Security Policy',
      value: "default-src 'self'",
      present: true,
      recommended: true,
    });
    // The non-recommended header comes after all nine recommended ones, alphabetically.
    expect(report.rows.at(-1)).toMatchObject({ name: 'x-custom', recommended: false, guidance: null });
    expect(report.rows.filter((row) => row.recommended)).toHaveLength(RECOMMENDED_HEADERS.length);
  });

  it('reports an absent recommended header with guidance, never as a value', () => {
    const report = buildHeaderDashboard(mainDocument([{ name: 'server', value: 'nginx/1.2.3' }]));
    const hsts = report.rows.find((row) => row.name === 'strict-transport-security');
    expect(hsts).toMatchObject({ present: false, value: '', recommended: true });
    expect(hsts?.guidance).toContain('31536000');
    // And the "absent" verdict only exists because the response was actually observed.
    expect(report.available).toBe(true);
  });

  it('keeps every other observed header, sorted alphabetically', () => {
    const report = buildHeaderDashboard(
      mainDocument([{ name: 'z-bucket', value: 'b' }, { name: 'a-from', value: 'a' }]),
    );
    const rest = report.rows.filter((row) => !row.recommended);
    expect(rest.map((row) => row.name)).toEqual(['a-from', 'z-bucket']);
    expect(report.observedCount).toBe(2);
  });

  it('folds duplicate header names to the first value and counts distinct headers', () => {
    const report = buildHeaderDashboard(
      mainDocument([{ name: 'set-cookie', value: 'a=1' }, { name: 'set-cookie', value: 'b=2' }]),
    );
    expect(report.observedCount).toBe(1);
    expect(report.rows.find((row) => row.name === 'set-cookie')?.value).toBe('a=1');
  });

  it('produces nothing that could enter the score: the shape is pure display data', () => {
    const report = buildHeaderDashboard(mainDocument([{ name: 'content-security-policy', value: "default-src 'self'" }]));
    for (const row of report.rows) {
      expect(Object.keys(row).sort()).toEqual(['guidance', 'label', 'name', 'present', 'recommended', 'value']);
    }
  });
});
