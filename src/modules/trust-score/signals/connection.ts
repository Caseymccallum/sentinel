/**
 * Connection signals: transport encryption, TLS strength, certificate trust, HSTS.
 *
 * These four are the backbone of the score. Three of them depend on facts the browser may
 * simply refuse to hand an extension — when that happens the signal reports
 * `measured: null`, which removes no points and shows up as a caveat instead of a verdict.
 */

import { assessment, evidence, evidenceList, quality, unavailable } from './shared';
import type { SignalAnalyzer } from '../../../shared/analysis';
import type { CertificateFacts, SignalAssessment } from '../../../core/types';

/** Protocols older than TLS 1.2 are treated as broken; 1.2 is acceptable but not ideal. */
function protocolDeduction(protocol: string | null): number {
  if (protocol === null) return 0;
  const normalised = protocol.toLowerCase();
  if (normalised.includes('tlsv1.3') || normalised.includes('tls 1.3')) return 0;
  if (normalised.includes('tlsv1.2') || normalised.includes('tls 1.2')) return 8;
  if (normalised.includes('tlsv1.1') || normalised.includes('tls 1.1')) return 45;
  if (normalised.includes('tlsv1') || normalised.includes('tls 1.0')) return 60;
  if (normalised.includes('sslv3') || normalised.includes('ssl')) return 90;
  return 0;
}

function signatureDeduction(facts: CertificateFacts | null): number {
  if (!facts) return 0;
  if (facts.signatureStrength === 'weak') return 60;
  if (facts.signatureStrength === 'legacy') return 25;
  return 0;
}

function keyDeduction(facts: CertificateFacts | null): number {
  if (!facts || facts.publicKeySizeBits === null) return 0;
  const bits = facts.publicKeySizeBits;
  const algorithm = (facts.publicKeyAlgorithm ?? '').toLowerCase();
  if (algorithm.includes('rsa')) {
    if (bits < 2048) return 50;
    if (bits < 3072) return 10;
    return 0;
  }
  if (algorithm.includes('ec') || algorithm.includes('ecdsa')) {
    return bits < 256 ? 40 : 0;
  }
  return bits < 2048 ? 30 : 0;
}

function certificateDeduction(facts: CertificateFacts | null): number {
  if (!facts) return 0;
  let deduction = 0;
  if (facts.isSelfSigned) deduction += 80;
  if (facts.isExpired) deduction += 100;
  else if (facts.daysUntilExpiry !== null) {
    if (facts.daysUntilExpiry <= 7) deduction += 30;
    else if (facts.daysUntilExpiry <= 21) deduction += 15;
  }
  return deduction;
}

function expiryPhrase(days: number): string {
  return days === 1 ? '1 day' : `${days} days`;
}

/** HSTS is only meaningful on a secure page, so an HTTP page gets `null` rather than 0. */
function hstsAssessment(
  headers: { get(name: string): string | null },
  secure: boolean,
  headersAvailable: boolean,
): SignalAssessment {
  const title = 'Transport upgrade policy (HSTS)';
  const signalId = 'connection.hsts';

  if (!secure) {
    return assessment({
      signalId,
      title,
      measured: null,
      confidence: 'high',
      detail:
        'HSTS only applies to HTTPS pages, so there is nothing to measure here — but a page served over HTTP cannot be upgraded to HTTPS at all.',
      evidence: evidenceList([evidence('Strict-Transport-Security', 'not applicable over HTTP')]),
    });
  }

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not look for a Strict-Transport-Security header.',
    );
  }

  const raw = headers.get('strict-transport-security');
  if (raw === null) {
    return assessment({
      signalId,
      title,
      measured: 0,
      confidence: 'high',
      detail:
        'No Strict-Transport-Security header was sent, so a single unencrypted request to this domain could still be intercepted.',
      evidence: evidenceList([evidence('Strict-Transport-Security', 'absent')]),
      remediation: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.',
    });
  }

  const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(raw);
  const seconds = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
  const includesSubdomains = /includeSubDomains/i.test(raw);

  const deductions: number[] = [];
  if (seconds === null) deductions.push(40);
  else if (seconds === 0) deductions.push(100);
  else if (seconds < 15_552_000) deductions.push(30);
  if (!includesSubdomains) deductions.push(15);

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      seconds === 0
        ? 'The Strict-Transport-Security header sets max-age=0, which actively switches HSTS off for this domain.'
        : `HSTS is enabled (${seconds === null ? 'no max-age' : `${seconds}s max-age`}${includesSubdomains ? ', including subdomains' : ', excluding subdomains'}).`,
    evidence: evidenceList([
      evidence('Strict-Transport-Security', raw),
      evidence('max-age', seconds === null ? null : `${seconds}s`),
      evidence('includeSubDomains', includesSubdomains ? 'yes' : 'no'),
    ]),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Use `max-age=31536000; includeSubDomains` and submit the domain to the HSTS preload list.',
  });
}

export const connectionAnalyzer: SignalAnalyzer = {
  id: 'connection',
  moduleId: 'trust-score',

  analyze(context) {
    const { observation, headers, page } = context;
    const mainDocument = observation.mainDocument;
    const secure = page.scheme === 'https';
    const headersAvailable = mainDocument !== null && headers.count > 0;
    const tls = mainDocument?.tls ?? null;
    const certificate = tls?.certificate ?? null;
    const observed = mainDocument !== null || observation.requests.length > 0;

    const assessments: SignalAssessment[] = [];

    // --------------------------------------------------------- connection.https
    if (!observed) {
      assessments.push(
        unavailable(
          'connection.https',
          'Encrypted transport',
          'Sentinel did not observe this page load, so it cannot tell how the connection was made.',
        ),
      );
    } else {
      const schemeLabel = page.scheme === 'other' ? 'a non-web scheme' : page.scheme.toUpperCase();
      assessments.push(
        assessment({
          signalId: 'connection.https',
          title: 'Encrypted transport',
          measured: secure ? 100 : 0,
          confidence: 'high',
          detail: secure
            ? 'The page was loaded over an encrypted connection.'
            : `The page was loaded over ${schemeLabel}, so anything sent or received can be read on the network path.`,
          evidence: evidenceList([
            evidence('Origin', page.origin || observation.origin),
            evidence('Scheme', page.scheme),
            evidence('Status', mainDocument?.statusLine ?? null),
          ]),
          remediation: secure ? undefined : 'Serve the site over HTTPS and redirect all HTTP requests to it.',
        }),
      );
    }

    // -------------------------------------------------- connection.tls-strength
    if (!secure) {
      assessments.push(
        assessment({
          signalId: 'connection.tls-strength',
          title: 'TLS strength',
          measured: null,
          confidence: 'high',
          detail: 'There is no TLS session to assess because the page was not served over HTTPS.',
          evidence: evidenceList([evidence('TLS', 'not in use')]),
        }),
      );
    } else if (!tls || tls.state === 'unknown') {
      assessments.push(
        unavailable(
          'connection.tls-strength',
          'TLS strength',
          'The browser did not expose the negotiated TLS details for this page, so Sentinel cannot check the protocol version or signature algorithm.',
        ),
      );
    } else if (tls.state === 'broken') {
      assessments.push(
        assessment({
          signalId: 'connection.tls-strength',
          title: 'TLS strength',
          measured: 0,
          confidence: 'high',
          detail:
            'The browser reported the TLS session as broken, which means the connection could not be trusted at all.',
          evidence: evidenceList([evidence('TLS state', tls.state)]),
          remediation:
            'Check the server certificate chain and TLS configuration; browsers only report this when validation failed.',
        }),
      );
    } else {
      const deductions = [protocolDeduction(tls.protocol), signatureDeduction(certificate), keyDeduction(certificate)];
      const clean = deductions.every((value) => value === 0);
      assessments.push(
        assessment({
          signalId: 'connection.tls-strength',
          title: 'TLS strength',
          measured: quality(deductions),
          confidence: certificate === null || tls.protocol === null ? 'medium' : 'high',
          detail: clean
            ? `The connection negotiated a modern configuration${tls.protocol ? ` (${tls.protocol})` : ''} with no legacy algorithms.`
            : 'The TLS configuration is weakened by an outdated protocol version, a legacy signature algorithm or a short key.',
          evidence: evidenceList([
            evidence('TLS state', tls.state),
            evidence('Protocol', tls.protocol),
            evidence('Protocol source', tls.source),
            evidence('Signature algorithm', certificate?.signatureAlgorithm ?? null),
            evidence('Signature strength', certificate?.signatureStrength ?? null),
            evidence(
              'Public key',
              certificate?.publicKeyAlgorithm
                ? `${certificate.publicKeyAlgorithm} ${certificate.publicKeySizeBits ?? '?'}-bit`
                : null,
            ),
          ]),
          remediation: clean
            ? undefined
            : 'Require TLS 1.2 or newer, prefer TLS 1.3, use RSA-3072+/ECDSA P-256 keys and retire SHA-1 signed certificates.',
        }),
      );
    }

    // ---------------------------------------------------- connection.certificate
    if (!secure) {
      assessments.push(
        assessment({
          signalId: 'connection.certificate',
          title: 'Certificate trust',
          measured: null,
          confidence: 'high',
          detail: 'No certificate was presented because the page was not served over HTTPS.',
          evidence: evidenceList([evidence('Certificate', 'not presented')]),
        }),
      );
    } else if (certificate === null) {
      assessments.push(
        unavailable(
          'connection.certificate',
          'Certificate trust',
          'The browser did not expose the certificate for this page, so Sentinel cannot check its issuer, validity dates or key size.',
        ),
      );
    } else {
      const problems: string[] = [];
      if (certificate.isExpired) problems.push('the certificate has expired');
      if (certificate.isSelfSigned) problems.push('the certificate is self-signed');
      const days = certificate.daysUntilExpiry;
      if (!certificate.isExpired && days !== null && days <= 21) {
        problems.push(`it expires in ${expiryPhrase(days)}`);
      }

      assessments.push(
        assessment({
          signalId: 'connection.certificate',
          title: 'Certificate trust',
          measured: quality([certificateDeduction(certificate)]),
          confidence: 'high',
          detail:
            problems.length === 0
              ? `The certificate is valid${days === null ? '' : ` for another ${expiryPhrase(days)}`}.`
              : `Certificate problems: ${problems.join('; ')}.`,
          evidence: evidenceList([
            evidence('Subject', certificate.subjectCN),
            evidence('Issuer', certificate.issuerCN ?? certificate.issuerO),
            evidence('Valid until', certificate.validTo),
            evidence('Serial', certificate.serialNumber),
            evidence(
              'Fingerprint',
              certificate.sha256Fingerprint ? `${certificate.sha256Fingerprint.slice(0, 32)}…` : null,
            ),
          ]),
          remediation:
            problems.length === 0
              ? undefined
              : 'Use a certificate from a publicly trusted authority and automate renewal before expiry.',
        }),
      );
    }

    // ----------------------------------------------------------- connection.hsts
    assessments.push(hstsAssessment(headers, secure, headersAvailable));

    return assessments;
  },
};
