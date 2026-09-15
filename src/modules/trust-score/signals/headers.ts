/**
 * Response-hardening signals: the headers a site uses to tell the browser how to protect
 * the page and its visitors.
 *
 * A missing header is only scored when Sentinel actually saw the response headers. If the
 * document was served from cache before Sentinel was listening, every signal here reports
 * `measured: null` instead of accusing the site of omitting headers it may well have sent.
 */

import { assessment, evidence, evidenceList, quality, unavailable } from './shared';
import type { HeaderIndex, SignalAnalyzer } from '../../../shared/analysis';
import { hasResponseHeaders } from '../../../shared/analysis';
import type { SignalAssessment } from '../../../core/types';

/** Headers that advertise exact technology versions. */
const VERSION_BANNERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
  'x-version',
] as const;

const VERSION_LIKE = /\d+\.\d+/;

interface Directive {
  name: string;
  values: string[];
}

/** Splits a CSP into directives: `default-src 'self'; script-src a.example` → pairs. */
function parseCsp(policy: string): Directive[] {
  return policy
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part !== '')
    .map((part) => {
      const pieces = part.split(/\s+/);
      return { name: (pieces[0] ?? '').toLowerCase(), values: pieces.slice(1) };
    });
}

function directive(policy: string, name: string): Directive | null {
  return parseCsp(policy).find((entry) => entry.name === name) ?? null;
}

function cspAssessment(headers: HeaderIndex, hasCspMeta: boolean, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.csp';
  const title = 'Content Security Policy';
  const raw = headers.get('content-security-policy');

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check for a Content Security Policy.',
    );
  }

  if (raw === null) {
    return assessment({
      signalId,
      title,
      measured: 0,
      confidence: hasCspMeta ? 'medium' : 'high',
      detail: hasCspMeta
        ? 'No Content-Security-Policy header was sent; the page only carries a `<meta>` CSP, which browsers apply late and which cannot restrict every directive.'
        : 'No Content Security Policy was sent, so the browser has no defence against injected scripts beyond its own heuristics.',
      evidence: evidenceList([
        evidence('Content-Security-Policy', 'absent'),
        evidence('Meta CSP present', hasCspMeta ? 'yes (weaker than a header)' : 'no'),
      ]),
      remediation: 'Publish a restrictive CSP header that avoids `unsafe-inline` and `unsafe-eval`.',
    });
  }

  const scriptSource = directive(raw, 'script-src') ?? directive(raw, 'default-src');
  const scriptValues = scriptSource?.values ?? [];
  const hasWildcard = scriptValues.includes('*') || scriptValues.includes('http:') || scriptValues.includes('https:');
  const allowsInline = scriptValues.includes("'unsafe-inline'");
  const allowsEval = scriptValues.includes("'unsafe-eval'");
  const hasObjectSrc = directive(raw, 'object-src')?.values.includes("'none'") === true;

  const deductions: number[] = [];
  if (allowsInline) deductions.push(35);
  if (allowsEval) deductions.push(30);
  if (!scriptSource) deductions.push(25);
  if (hasWildcard) deductions.push(20);
  if (!hasObjectSrc) deductions.push(8);

  const gaps = [
    allowsInline ? 'inline scripts are allowed' : null,
    allowsEval ? 'eval is allowed' : null,
    hasWildcard ? 'any host may serve scripts' : null,
    !scriptSource ? 'no default-src or script-src fallback' : null,
    !hasObjectSrc ? "object-src is not set to 'none'" : null,
  ].filter((entry): entry is string => entry !== null);

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      gaps.length === 0
        ? 'A Content Security Policy is in place and does not permit inline or eval-based scripts.'
        : `A Content Security Policy is in place, but it leaves gaps: ${gaps.join('; ')}.`,
    evidence: evidenceList([
      evidence('Content-Security-Policy', raw),
      evidence('Script source', scriptValues.length === 0 ? null : scriptValues.join(' ')),
      evidence('object-src', directive(raw, 'object-src')?.values.join(' ') ?? null),
      evidence('Directive count', String(parseCsp(raw).length)),
    ]),
    remediation:
      gaps.length === 0
        ? undefined
        : "Avoid `unsafe-inline` and `unsafe-eval`, restrict script sources to explicit hosts, and set `object-src 'none'`.",
  });
}

function scoreFrameAncestors(values: readonly string[]): number {
  const list = values.map((value) => value.toLowerCase());
  if (list.length === 0) return 0;
  if (list.includes("'none'")) return 100;
  if (list.length === 1 && list.includes("'self'")) return 90;
  if (list.some((value) => value === '*' || value === 'http:' || value === 'https:')) return 30;
  return 60;
}

function scoreXfo(value: string): number {
  const token = value.split(',')[0]?.trim().toLowerCase() ?? '';
  if (token === 'deny') return 100;
  if (token === 'sameorigin') return 90;
  if (token.startsWith('allow-from')) return 60;
  return 40;
}

/** `frame-ancestors` and `X-Frame-Options` are interchangeable; the stronger one wins. */
function frameAncestorsAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.frame-ancestors';
  const title = 'Clickjacking protection';

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check for clickjacking protection.',
    );
  }

  const csp = headers.get('content-security-policy');
  const frameAncestors = csp === null ? null : directive(csp, 'frame-ancestors');
  const xfo = headers.get('x-frame-options')?.trim() ?? null;

  const cspScore = frameAncestors === null ? null : scoreFrameAncestors(frameAncestors.values);
  const xfoScore = xfo === null ? null : scoreXfo(xfo);
  const best = Math.max(cspScore ?? -1, xfoScore ?? -1);

  if (best < 0) {
    return assessment({
      signalId,
      title,
      measured: 0,
      confidence: 'high',
      detail:
        'Neither `Content-Security-Policy: frame-ancestors` nor `X-Frame-Options` was sent, so another site can embed this page invisibly and overlay fake controls on it.',
      evidence: evidenceList([
        evidence('frame-ancestors', 'absent'),
        evidence('X-Frame-Options', 'absent'),
      ]),
      remediation: "Send `Content-Security-Policy: frame-ancestors 'none'` or `X-Frame-Options: DENY`.",
    });
  }

  return assessment({
    signalId,
    title,
    measured: best,
    confidence: 'high',
    detail:
      best >= 100
        ? 'The page cannot be framed by other origins.'
        : 'The page can still be framed in restricted circumstances, which is weaker than refusing embedding outright.',
    evidence: evidenceList([
      evidence('frame-ancestors', frameAncestors?.values.join(' ') ?? null),
      evidence('X-Frame-Options', xfo),
    ]),
    remediation: best >= 100 ? undefined : "Prefer `frame-ancestors 'none'` (or `X-Frame-Options: DENY`).",
  });
}

function referrerAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.referrer-policy';
  const title = 'Referrer policy';
  const raw = headers.get('referrer-policy');

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check the referrer policy.',
    );
  }

  const policy = raw?.split(',')[0]?.trim().toLowerCase() ?? null;
  const strong = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];

  let measured: number;
  let detail: string;
  if (policy !== null && strong.includes(policy)) {
    measured = 100;
    detail = `The referrer policy \`${policy}\` leaks at most the page origin to other sites.`;
  } else if (policy === 'origin' || policy === 'origin-when-cross-origin') {
    measured = 75;
    detail = `The referrer policy \`${policy}\` sends the full URL for same-origin requests and the origin elsewhere — acceptable, but looser than needed.`;
  } else if (policy === 'no-referrer-when-downgrade') {
    measured = 40;
    detail = `The referrer policy \`${policy}\` sends the full URL to every HTTPS destination, including third-party hosts.`;
  } else if (policy === 'unsafe-url') {
    measured = 0;
    detail = 'The referrer policy `unsafe-url` sends the full page URL to every destination, encrypted or not.';
  } else if (policy === null) {
    measured = 60;
    detail =
      'No Referrer-Policy header was sent, so browsers fall back to `strict-origin-when-cross-origin`: the origin leaks, the full path does not.';
  } else {
    measured = 30;
    detail = `The Referrer-Policy value \`${raw}\` is not one Sentinel recognises, so browsers may ignore it entirely.`;
  }

  return assessment({
    signalId,
    title,
    measured,
    confidence: 'high',
    detail,
    evidence: evidenceList([evidence('Referrer-Policy', raw ?? 'absent')]),
    remediation:
      measured >= 100 ? undefined : 'Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.',
  });
}

function nosniffAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.content-type-protection';
  const title = 'MIME sniffing protection';

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check for `X-Content-Type-Options`.',
    );
  }

  const raw = headers.get('x-content-type-options');
  const nosniff = raw?.toLowerCase().includes('nosniff') === true;

  return assessment({
    signalId,
    title,
    measured: nosniff ? 100 : 0,
    confidence: 'high',
    detail: nosniff
      ? '`X-Content-Type-Options: nosniff` is set, so the browser will not guess a different type for a response.'
      : '`X-Content-Type-Options: nosniff` is missing, so a browser may execute an uploaded or mislabelled file as a script.',
    evidence: evidenceList([evidence('X-Content-Type-Options', raw ?? 'absent')]),
    remediation: nosniff ? undefined : 'Send `X-Content-Type-Options: nosniff` on every response.',
  });
}

function permissionsPolicyAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.permissions-policy';
  const title = 'Feature permissions policy';

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check for a `Permissions-Policy` header.',
    );
  }

  const raw = headers.get('permissions-policy');
  const featureCount = raw === null ? 0 : raw.split(',').filter((part) => part.trim() !== '').length;
  const wildcards = raw === null ? 0 : (raw.match(/\*/g) ?? []).length;

  if (raw === null) {
    return assessment({
      signalId,
      title,
      measured: 60,
      confidence: 'high',
      detail:
        'No Permissions-Policy header was sent. Browsers apply their own defaults for features like camera, microphone and location, but the page never states which ones it actually needs.',
      evidence: evidenceList([evidence('Permissions-Policy', 'absent')]),
      remediation: 'Send a `Permissions-Policy` header listing only the features the page actually needs.',
    });
  }

  const deductions: number[] = [];
  if (featureCount === 0) deductions.push(30);
  else if (featureCount < 3) deductions.push(15);
  if (wildcards > 0) deductions.push(Math.min(40, wildcards * 20));

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      wildcards > 0
        ? 'The Permissions-Policy uses `*` wildcards, which grants features to every origin rather than restricting them.'
        : deductions.length === 0
          ? `The page restricts ${featureCount} browser features explicitly.`
          : 'The Permissions-Policy covers only a couple of features, leaving the rest to browser defaults.',
    evidence: evidenceList([
      evidence('Permissions-Policy', raw),
      evidence('Features restricted', String(featureCount)),
      evidence('Wildcards', String(wildcards)),
    ]),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Allow only the features the page needs, and prefer explicit origins over `*`.',
  });
}

/** Version banners are a targeting aid, so any exact version is treated as a real problem. */
function informationLeakageAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.information-leakage';
  const title = 'Server disclosure';

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not look for version banners.',
    );
  }

  const banners: { name: string; value: string }[] = [];
  for (const name of VERSION_BANNERS) {
    const value = headers.get(name);
    if (value !== null) banners.push({ name, value });
  }
  const versioned = banners.filter((entry) => VERSION_LIKE.test(entry.value));
  const deductions = [
    ...versioned.map(() => 40),
    ...banners.filter((entry) => !VERSION_LIKE.test(entry.value)).map(() => 15),
  ];

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      banners.length === 0
        ? 'No server or framework banner headers were sent.'
        : versioned.length > 0
          ? `Exact version numbers are advertised in ${versioned.map((entry) => entry.name).join(', ')}, which lets an attacker target exploits for that release.`
          : `Technology banners (${banners.map((entry) => entry.name).join(', ')}) reveal the stack without publishing a version.`,
    evidence: evidenceList(banners.map((entry) => evidence(entry.name, entry.value))),
    remediation:
      banners.length === 0
        ? undefined
        : 'Remove or generalise `Server`, `X-Powered-By` and similar version banners.',
  });
}

function crossOriginAssessment(headers: HeaderIndex, headersAvailable: boolean): SignalAssessment {
  const signalId = 'headers.cross-origin-policy';
  const title = 'Cross-origin isolation';

  if (!headersAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not check the cross-origin isolation headers.',
    );
  }

  const coop = headers.get('cross-origin-opener-policy')?.trim().toLowerCase() ?? null;
  const corp = headers.get('cross-origin-resource-policy')?.trim().toLowerCase() ?? null;
  const coep = headers.get('cross-origin-embedder-policy')?.trim().toLowerCase() ?? null;

  const coopScore = coop === 'same-origin' ? 50 : coop === 'same-origin-allow-popups' ? 30 : 0;
  const corpScore = corp === 'same-origin' || corp === 'same-site' ? 50 : corp === 'cross-origin' ? 20 : 0;

  return assessment({
    signalId,
    title,
    measured: quality([100 - coopScore - corpScore]),
    confidence: 'high',
    detail:
      coop === null && corp === null
        ? 'Neither Cross-Origin-Opener-Policy nor Cross-Origin-Resource-Policy was sent, so the page is not fenced off from cross-origin probing or unwanted embedding.'
        : 'Some cross-origin isolation headers are present, but the page is not fully fenced off from other origins.',
    evidence: evidenceList([
      evidence('Cross-Origin-Opener-Policy', coop ?? 'absent'),
      evidence('Cross-Origin-Resource-Policy', corp ?? 'absent'),
      evidence('Cross-Origin-Embedder-Policy', coep ?? 'absent'),
    ]),
    remediation:
      coopScore === 50 && corpScore === 50
        ? undefined
        : 'Send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`.',
  });
}

/** Every response-hardening signal, in the order they appear in the popup. */
export const headerAnalyzer: SignalAnalyzer = {
  id: 'headers',
  moduleId: 'trust-score',

  analyze(context) {
    const headersAvailable = hasResponseHeaders(context);
    const hasCspMeta = context.dom?.documentHasCspMeta === true;
    const { headers } = context;

    return [
      cspAssessment(headers, hasCspMeta, headersAvailable),
      frameAncestorsAssessment(headers, headersAvailable),
      nosniffAssessment(headers, headersAvailable),
      referrerAssessment(headers, headersAvailable),
      permissionsPolicyAssessment(headers, headersAvailable),
      informationLeakageAssessment(headers, headersAvailable),
      crossOriginAssessment(headers, headersAvailable),
    ];
  },
};
