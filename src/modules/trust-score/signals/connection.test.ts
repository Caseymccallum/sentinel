/**
 * Connection signal tests.
 *
 * The four connection signals are the backbone of the score: encryption, TLS strength,
 * certificate trust and HSTS. Three of them depend on facts a browser may simply refuse to
 * hand an extension, so these tests check both halves of the contract - the quality values
 * for what *was* observed, and `measured: null` (no points, a caveat in the explanation) for
 * what was not.
 *
 * Every fixture is a hand-built `PageObservation`, so no browser and no network are needed.
 */

import { describe, expect, it } from 'vitest';
import { connectionAnalyzer } from './connection';
import { buildAnalysisContext } from '../../../shared/analysis';
import type { CertificateFacts, SignalAssessment } from '../../../core/types';
import type { HeaderEntry, PageObservation, RequestRecord, TlsObservation } from '../../../shared/observation';

const NOW = 1_700_000_000_000;

function certificate(overrides: Partial<CertificateFacts> = {}): CertificateFacts {
  return {
    subjectCN: 'shop.example.com',
    issuerCN: 'Example Issuing CA',
    issuerO: 'Example CA Ltd',
    issuerC: 'GB',
    serialNumber: '0a1b2c3d',
    validFrom: '2025-01-01T00:00:00Z',
    validTo: '2026-01-01T00:00:00Z',
    daysUntilExpiry: 200,
    isExpired: false,
    isSelfSigned: false,
    signatureAlgorithm: 'sha256WithRSAEncryption',
    signatureStrength: 'modern',
    publicKeyAlgorithm: 'EC',
    publicKeySizeBits: 256,
    sha256Fingerprint: 'a'.repeat(64),
    ...overrides,
  };
}

function tls(overrides: Partial<TlsObservation> = {}): TlsObservation {
  return {
    state: 'secure',
    protocol: 'TLSv1.3',
    source: 'get-security-info',
    certificate: certificate(),
    ...overrides,
  };
}

function headers(entries: Record<string, string>): HeaderEntry[] {
  return Object.entries(entries).map(([name, value]) => ({ name, value }));
}

function request(hostname = 'shop.example.com'): RequestRecord {
  return {
    requestId: `req-${hostname}`,
    url: `https://${hostname}/`,
    hostname,
    thirdParty: hostname !== 'shop.example.com',
    kind: 'main_frame',
    initiatorHostname: null,
    statusCode: 200,
    fromCache: false,
  };
}

function observation(
  options: {
    scheme?: 'https' | 'http';
    headers?: readonly HeaderEntry[];
    tls?: TlsObservation | null;
    mainDocument?: boolean;
    requests?: readonly RequestRecord[];
  } = {},
): PageObservation {
  const scheme = options.scheme ?? 'https';
  const url = `${scheme}://shop.example.com/checkout`;
  const withDocument = options.mainDocument !== false;

  return {
    observationId: 'obs-1',
    tabId: 1,
    frameId: 0,
    url,
    hostname: 'shop.example.com',
    origin: `${scheme}://shop.example.com`,
    startedAt: NOW - 1000,
    updatedAt: NOW,
    mainDocument: withDocument
      ? {
          url,
          statusCode: 200,
          statusLine: 'HTTP/1.1 200 OK',
          serverIp: '203.0.113.7',
          fromCache: false,
          headers: [...(options.headers ?? [])],
          tls: options.tls === undefined ? tls() : options.tls,
        }
      : null,
    requests: [...(options.requests ?? [])],
    requestsTruncated: false,
    dom: null,
    warnings: [],
  };
}

function analyze(options: Parameters<typeof observation>[0] = {}): SignalAssessment[] {
  return connectionAnalyzer.analyze(buildAnalysisContext(observation(options), NOW));
}

function byId(assessments: readonly SignalAssessment[], signalId: string): SignalAssessment {
  const found = assessments.find((entry) => entry.signalId === signalId);
  if (!found) throw new Error(`no assessment for ${signalId}`);
  return found;
}
describe('connectionAnalyzer', () => {
  it('reports the four connection signals in order, once each', () => {
    const assessments = analyze();

    expect(assessments.map((entry) => entry.signalId)).toEqual([
      'connection.https',
      'connection.tls-strength',
      'connection.certificate',
      'connection.hsts',
    ]);
    expect(connectionAnalyzer.id).toBe('connection');
    expect(connectionAnalyzer.moduleId).toBe('trust-score');
  });

  it('treats a page it never saw as unmeasurable rather than insecure', () => {
    const assessments = analyze({ mainDocument: false, requests: [] });

    expect(assessments.every((entry) => entry.measured === null)).toBe(true);
    expect(byId(assessments, 'connection.https').detail).toContain('did not observe this page load');
    expect(byId(assessments, 'connection.tls-strength').confidence).toBe('unavailable');
  });
});

describe('connection.https', () => {
  it('credits an encrypted page', () => {
    const secure = byId(analyze(), 'connection.https');

    expect(secure.measured).toBe(100);
    expect(secure.confidence).toBe('high');
    expect(secure.remediation).toBeUndefined();
    expect(secure.evidence).toContainEqual({ label: 'Scheme', value: 'https' });
  });

  it('drops to zero on an unencrypted page, and says why', () => {
    const insecure = byId(analyze({ scheme: 'http', tls: null }), 'connection.https');

    expect(insecure.measured).toBe(0);
    expect(insecure.confidence).toBe('high');
    expect(insecure.remediation).toBeDefined();
    expect(insecure.detail).toContain('read on the network path');
    expect(insecure.evidence).toContainEqual({ label: 'Scheme', value: 'http' });
  });
});

describe('connection.tls-strength: protocol mapping', () => {
  const cases: [string, number][] = [
    ['TLSv1.3', 100],
    ['TLSv1.2', 92],
    ['TLSv1.1', 55],
    ['TLSv1', 40],
    ['SSLv3', 10],
    ['QUIC', 100],
  ];

  it.each(cases)('scores %s at %i', (protocol, expected) => {
    const assessment = byId(analyze({ tls: tls({ protocol }) }), 'connection.tls-strength');

    expect(assessment.measured).toBe(expected);
    expect(assessment.confidence).toBe('high');
    expect(assessment.evidence).toContainEqual({ label: 'Protocol', value: protocol });
  });

  it('leaves no comparable TLS session to score on an HTTP page', () => {
    const assessment = byId(analyze({ scheme: 'http', tls: null }), 'connection.tls-strength');

    expect(assessment.measured).toBeNull();
    expect(assessment.confidence).toBe('high');
    expect(assessment.detail).toContain('no TLS session to assess');
  });

  it('flags a broken TLS session as untrustworthy', () => {
    const assessment = byId(analyze({ tls: tls({ state: 'broken' }) }), 'connection.tls-strength');

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.detail).toContain('broken');
  });

  it('reports unmeasurable rather than guessing when TLS details are withheld', () => {
    expect(byId(analyze({ tls: null }), 'connection.tls-strength').measured).toBeNull();
    expect(byId(analyze({ tls: tls({ state: 'unknown' }) }), 'connection.tls-strength').measured).toBeNull();
    expect(byId(analyze({ tls: tls({ state: 'unknown' }) }), 'connection.tls-strength').confidence).toBe(
      'unavailable',
    );
  });

  it('lowers its confidence when part of the TLS picture is missing', () => {
    expect(byId(analyze({ tls: tls({ certificate: null }) }), 'connection.tls-strength')).toMatchObject({
      measured: 100,
      confidence: 'medium',
    });
    expect(byId(analyze({ tls: tls({ protocol: null }) }), 'connection.tls-strength')).toMatchObject({
      measured: 100,
      confidence: 'medium',
    });
  });
});

describe('connection.tls-strength: signature and key size', () => {
  const cases: [string, Partial<CertificateFacts>, number][] = [
    ['a weak signature', { signatureStrength: 'weak' }, 40],
    ['a legacy signature', { signatureStrength: 'legacy' }, 75],
    ['an RSA-1024 key', { publicKeyAlgorithm: 'RSA', publicKeySizeBits: 1024 }, 50],
    ['an RSA-2048 key', { publicKeyAlgorithm: 'RSA', publicKeySizeBits: 2048 }, 90],
    ['an RSA-3072 key', { publicKeyAlgorithm: 'RSA', publicKeySizeBits: 3072 }, 100],
    ['an RSA-4096 key', { publicKeyAlgorithm: 'RSA', publicKeySizeBits: 4096 }, 100],
    ['a P-256 ECDSA key', { publicKeyAlgorithm: 'ECDSA', publicKeySizeBits: 256 }, 100],
    ['a P-128 ECDSA key', { publicKeyAlgorithm: 'ECDSA', publicKeySizeBits: 128 }, 60],
    ['a 1024-bit DSA key', { publicKeyAlgorithm: 'DSA', publicKeySizeBits: 1024 }, 70],
    ['an unknown 3072-bit key', { publicKeyAlgorithm: 'Frobnicator', publicKeySizeBits: 3072 }, 100],
    ['a certificate with no key size reported', { publicKeyAlgorithm: 'RSA', publicKeySizeBits: null }, 100],
  ];

  it.each(cases)('deducts for %s', (_label, facts, expected) => {
    const assessment = byId(
      analyze({ tls: tls({ certificate: certificate(facts) }) }),
      'connection.tls-strength',
    );

    expect(assessment.measured).toBe(expected);
  });

  it('reports a clean modern configuration with no remediation', () => {
    const assessment = byId(analyze(), 'connection.tls-strength');

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toContain('TLSv1.3');
  });

  it('never scores below zero when several weaknesses stack up', () => {
    const assessment = byId(
      analyze({
        tls: tls({
          protocol: 'SSLv3',
          certificate: certificate({ signatureStrength: 'weak', publicKeyAlgorithm: 'RSA', publicKeySizeBits: 1024 }),
        }),
      }),
      'connection.tls-strength',
    );

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
  });
});
describe('connection.certificate', () => {
  it('credits a valid certificate and shows what it proves', () => {
    const assessment = byId(analyze(), 'connection.certificate');

    expect(assessment.measured).toBe(100);
    expect(assessment.confidence).toBe('high');
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toBe('The certificate is valid for another 200 days.');
    expect(assessment.evidence).toContainEqual({ label: 'Subject', value: 'shop.example.com' });
    expect(assessment.evidence).toContainEqual({ label: 'Issuer', value: 'Example Issuing CA' });
  });

  const cases: [string, Partial<CertificateFacts>, number][] = [
    ['a self-signed certificate', { isSelfSigned: true }, 20],
    ['an expired certificate', { isExpired: true, daysUntilExpiry: -3 }, 0],
    ['an expired self-signed certificate', { isExpired: true, isSelfSigned: true, daysUntilExpiry: -10 }, 0],
    ['a certificate expiring in five days', { daysUntilExpiry: 5 }, 70],
    ['a certificate expiring in fourteen days', { daysUntilExpiry: 14 }, 85],
    ['a certificate expiring in twenty-one days', { daysUntilExpiry: 21 }, 85],
    ['a certificate expiring in twenty-two days', { daysUntilExpiry: 22 }, 100],
  ];

  it.each(cases)('deducts for %s', (_label, facts, expected) => {
    const assessment = byId(analyze({ tls: tls({ certificate: certificate(facts) }) }), 'connection.certificate');

    expect(assessment.measured).toBe(expected);
  });

  it('names the certificate problems and offers a fix', () => {
    const assessment = byId(
      analyze({ tls: tls({ certificate: certificate({ isSelfSigned: true, daysUntilExpiry: 10 }) }) }),
      'connection.certificate',
    );

    expect(assessment.detail).toContain('self-signed');
    expect(assessment.detail).toContain('expires in 10 days');
    expect(assessment.remediation).toBeDefined();
  });

  it('uses the singular when only one day is left', () => {
    const assessment = byId(
      analyze({ tls: tls({ certificate: certificate({ daysUntilExpiry: 1 }) }) }),
      'connection.certificate',
    );

    expect(assessment.detail).toContain('expires in 1 day');
  });

  it('reports unmeasurable when the browser hides the certificate', () => {
    const assessment = byId(analyze({ tls: tls({ certificate: null }) }), 'connection.certificate');

    expect(assessment.measured).toBeNull();
    expect(assessment.confidence).toBe('unavailable');
  });

  it('says there is no certificate to judge on an HTTP page', () => {
    const assessment = byId(analyze({ scheme: 'http', tls: null }), 'connection.certificate');

    expect(assessment.measured).toBeNull();
    expect(assessment.detail).toBe('No certificate was presented because the page was not served over HTTPS.');
  });
});

describe('connection.hsts', () => {
  it('credits a long-lived policy that covers subdomains', () => {
    const assessment = byId(
      analyze({ headers: headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }) }),
      'connection.hsts',
    );

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.evidence).toContainEqual({ label: 'includeSubDomains', value: 'yes' });
    expect(assessment.evidence).toContainEqual({ label: 'max-age', value: '31536000s' });
  });

  it('flags a missing policy as a real risk', () => {
    const assessment = byId(analyze({ headers: headers({ 'x-content-type-options': 'nosniff' }) }), 'connection.hsts');

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.evidence).toContainEqual({ label: 'Strict-Transport-Security', value: 'absent' });
  });

  const cases: [string, string, number][] = [
    ['a short max-age', 'max-age=3600', 55],
    ['a policy that switches HSTS off', 'max-age=0; includeSubDomains', 0],
    ['a policy without max-age', 'includeSubDomains', 60],
    ['a max-age exactly at the recommended floor', 'max-age=15552000; includeSubDomains', 100],
    ['a max-age just under the floor', 'max-age=15551999; includeSubDomains', 70],
    ['a case-insensitive policy', 'MAX-AGE=63072000; INCLUDESUBDOMAINS', 100],
  ];

  it.each(cases)('handles %s', (_label, value, expected) => {
    const assessment = byId(
      analyze({ headers: headers({ 'strict-transport-security': value }) }),
      'connection.hsts',
    );

    expect(assessment.measured).toBe(expected);
  });

  it('stays silent on an HTTP page, where HSTS cannot apply', () => {
    const assessment = byId(
      analyze({
        scheme: 'http',
        tls: null,
        headers: headers({ 'strict-transport-security': 'max-age=63072000' }),
      }),
      'connection.hsts',
    );

    expect(assessment.measured).toBeNull();
    expect(assessment.confidence).toBe('high');
    expect(assessment.detail).toContain('only applies to HTTPS pages');
  });

  it('reports unmeasurable when the response headers never arrived', () => {
    const assessments = analyze({ mainDocument: false, requests: [request()] });

    expect(byId(assessments, 'connection.hsts')).toMatchObject({ measured: null, confidence: 'unavailable' });
    // The scheme is still known from the tab, so encryption itself is scored rather than skipped.
    expect(byId(assessments, 'connection.https').measured).toBe(100);
  });
});