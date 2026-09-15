/**
 * Domain and URL helpers.
 *
 * Sentinel ships no dependencies, so instead of the full Public Suffix List (~230 KB)
 * we use a compact list of the multi-label suffixes that show up in practice, falling
 * back to "last two labels". A miss only makes the third-party count slightly coarser;
 * it can never create a false security finding.
 */

/** Multi-label public suffixes ("effective TLDs") covering the overwhelming majority of real traffic. */
const MULTI_LABEL_SUFFIXES = new Set<string>([
  'ac.uk', 'co.uk', 'gov.uk', 'ltd.uk', 'me.uk', 'nhs.uk', 'org.uk', 'police.uk', 'sch.uk',
  'asn.au', 'com.au', 'edu.au', 'gov.au', 'net.au', 'org.au',
  'ac.nz', 'co.nz', 'geek.nz', 'govt.nz', 'net.nz', 'org.nz', 'school.nz',
  'ac.jp', 'co.jp', 'go.jp', 'lg.jp', 'ne.jp', 'or.jp',
  'co.kr', 'go.kr', 'ne.kr', 'or.kr',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw', 'idv.tw',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
  'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
  'com.ar', 'net.ar', 'org.ar', 'edu.ar', 'gob.ar',
  'com.co', 'net.co', 'org.co', 'edu.co', 'gov.co',
  'com.pe', 'com.ec', 'com.ve', 'com.uy', 'com.py', 'com.bo', 'com.do', 'com.gt', 'com.sv', 'com.hn',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'gov.in', 'ac.in', 'edu.in', 'res.in',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'edu.za', 'web.za',
  'co.il', 'net.il', 'org.il', 'gov.il', 'ac.il',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'gen.tr',
  'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua', 'in.ua',
  'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru', 'edu.ru', 'gov.ru',
  'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
  'com.ro', 'org.ro', 'nt.ro', 'nom.ro', 'info.ro',
  'co.th', 'in.th', 'or.th', 'ac.th', 'go.th', 'net.th',
  'com.ph', 'net.ph', 'org.ph', 'edu.ph', 'gov.ph',
  'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
  'co.id', 'net.id', 'org.id', 'web.id', 'ac.id', 'go.id', 'sch.id',
  'com.pk', 'net.pk', 'org.pk', 'edu.pk', 'gov.pk', 'gob.pk',
  'com.bd', 'net.bd', 'org.bd', 'edu.bd', 'gov.bd',
  'com.eg', 'net.eg', 'org.eg', 'edu.eg', 'gov.eg',
  'com.sa', 'net.sa', 'org.sa', 'edu.sa', 'gov.sa', 'med.sa', 'sch.sa',
  'com.ng', 'net.ng', 'org.ng', 'edu.ng', 'gov.ng',
  'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke', 'sc.ke',
  'co.zw', 'co.bw', 'co.tz', 'co.mz', 'co.ao', 'co.ma',
  'com.gh', 'com.et', 'com.ly', 'com.tn', 'com.dz', 'com.sd',
  'ac.at', 'co.at', 'or.at', 'gv.at', 'priv.at',
  'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
  'com.pt', 'edu.pt', 'gov.pt', 'org.pt', 'net.pt', 'nome.pt', 'publ.pt',
  'com.gr', 'edu.gr', 'gov.gr', 'org.gr', 'net.gr',
  'com.it', 'edu.it', 'gov.it', 'org.it', 'net.it',
  'co.hu', 'org.hu', 'gov.hu', 'edu.hu', 'net.hu',
  'com.bg', 'net.bg', 'org.bg', 'gov.bg', 'edu.bg',
  'com.hr', 'net.hr', 'org.hr', 'gov.hr', 'edu.hr',
  'com.rs', 'net.rs', 'org.rs', 'gov.rs', 'edu.rs', 'ac.rs',
  'com.sk', 'net.sk', 'org.sk', 'gov.sk', 'edu.sk',
  'com.si', 'net.si', 'org.si', 'gov.si', 'edu.si',
  'com.lv', 'net.lv', 'org.lv', 'gov.lv', 'edu.lv',
  'com.lt', 'net.lt', 'org.lt', 'gov.lt', 'edu.lt',
  'com.ee', 'net.ee', 'org.ee', 'gov.ee', 'edu.ee',
  'us.com', 'uk.com', 'eu.com', 'de.com', 'gb.com', 'gb.net', 'jp.net', 'br.com',
]);

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^[0-9a-f:]+$/i;

export interface ParsedUrl {
  url: string;
  /** Lower-case hostname without a trailing dot; empty string for opaque URLs. */
  hostname: string;
  /** Registrable domain ("example.co.uk") or the hostname when it cannot be narrowed. */
  siteDomain: string;
  origin: string;
  protocol: string;
  scheme: 'http' | 'https' | 'other';
  isSecureContext: boolean;
  isIpLiteral: boolean;
  isLocalhost: boolean;
  port: string;
}

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
}

export function isIpLiteralHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  if (IPV4_PATTERN.test(host)) {
    return host.split('.').every((part) => {
      const value = Number(part);
      return value >= 0 && value <= 255 && part === String(value);
    });
  }
  return host.includes(':') && IPV6_PATTERN.test(host);
}

export function isLocalhostHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host.endsWith('.local')
  );
}

/**
 * Registrable domain (effective TLD + 1) without the full Public Suffix List.
 * Handles multi-label suffixes such as `co.uk` plus IPv4/IPv6 literals.
 */
export function getSiteDomain(hostname: string): string {
  const host = normalizeHostname(hostname);
  if (host === '') return '';
  if (isIpLiteralHostname(host)) return host;

  const labels = host.split('.');
  if (labels.length <= 2) return host;

  if (MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join('.'))) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
}

/** True when both hostnames belong to the same registrable domain. */
export function isSameSite(a: string, b: string): boolean {
  const left = getSiteDomain(a);
  const right = getSiteDomain(b);
  return left !== '' && left === right;
}

/** First-party = same registrable domain as the page; third-party = anything else. */
export function isThirdPartyTo(pageHostname: string, requestHostname: string): boolean {
  const page = normalizeHostname(pageHostname);
  const request = normalizeHostname(requestHostname);
  if (page === '' || request === '') return false;
  if (page === request) return false;
  if (isIpLiteralHostname(page) || isIpLiteralHostname(request)) return page !== request;
  return !isSameSite(page, request);
}

export function parseUrl(input: string | URL): ParsedUrl {
  let parsed: URL;
  try {
    parsed = input instanceof URL ? input : new URL(input);
  } catch {
    return {
      url: typeof input === 'string' ? input : String(input),
      hostname: '',
      siteDomain: '',
      origin: '',
      protocol: '',
      scheme: 'other',
      isSecureContext: false,
      isIpLiteral: false,
      isLocalhost: false,
      port: '',
    };
  }

  const protocol = parsed.protocol.replace(/:$/, '').toLowerCase();
  const scheme: ParsedUrl['scheme'] = protocol === 'https' ? 'https' : protocol === 'http' ? 'http' : 'other';
  const hostname = normalizeHostname(parsed.hostname);

  return {
    url: parsed.href,
    hostname,
    siteDomain: getSiteDomain(hostname),
    origin: parsed.origin === 'null' ? '' : parsed.origin,
    protocol,
    scheme,
    isSecureContext: scheme === 'https' || isLocalhostHostname(hostname),
    isIpLiteral: isIpLiteralHostname(hostname),
    isLocalhost: isLocalhostHostname(hostname),
    port: parsed.port,
  };
}

export function domainFromUrl(url: string): string {
  return parseUrl(url).hostname;
}

/**
 * URL form safe to persist in local history: no credentials, query string or fragment.
 * Query strings routinely carry session tokens, so they never touch disk.
 */
export function toStoredUrl(url: string): string {
  const parsed = parseUrl(url);
  if (parsed.origin === '') return '';
  return `${parsed.origin}${safePathname(url)}`;
}

function safePathname(url: string): string {
  try {
    const pathname = new URL(url).pathname;
    return pathname === '' ? '/' : pathname;
  } catch {
    return '/';
  }
}

/** Matches a hostname against a user-supplied pattern (`example.com`, `*.example.com`). */
export function hostnameMatchesPattern(hostname: string, pattern: string): boolean {
  const host = normalizeHostname(hostname);
  const raw = normalizeHostname(pattern);
  if (host === '' || raw === '') return false;

  const normalized = raw.startsWith('*.') ? raw.slice(2) : raw;

  if (normalized.includes('*')) {
    const escaped = normalized.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^.]*');
    return new RegExp(`^${escaped}$`).test(host);
  }

  return host === normalized || host.endsWith(`.${normalized}`);
}
