/**
 * DOM observation: everything the `DomReport` carries except the forms.
 *
 * Same safety contract as `form-observer.ts`: attributes and structure only, never a field's
 * value, never a mutation, never an event listener.
 *
 * A few fields here are deliberately *static* reads rather than live measurements:
 * `sensitiveFieldNames` is a list of `name`/`id` attributes that look like they hold personal
 * data (nothing is read), and `inlineEvalSignals` is a count of `eval`-shaped text in inline
 * scripts. Both are evidence for the user, not verdicts.
 */

import { hostnameOf, isSecureUrl, originOf, resolveAgainst } from '../shared/urls';
import { isThirdPartyTo } from '../core/domain';
import type { DomReport, IframeReport, ScriptReport } from '../shared/observation';
import { countPasswordFields, observeForms, type FormObserverOptions } from './form-observer';

/** Caps, so a hostile page cannot make the report arbitrarily large. */
export const MAX_IFRAMES = 100;
export const MAX_SCRIPTS = 200;
export const MAX_URLS = 200;
export const MAX_SENSITIVE_NAMES = 50;

/**
 * `name`/`id` values that commonly hold data a user would not want broadcast. Matching these is
 * a *label* match: Sentinel counts the fields, it never looks inside one.
 */
const SENSITIVE_FIELD_HINTS = [
  'password', 'passwd', 'pass', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'auth',
  'ssn', 'socialsecurity', 'nationalid', 'passport', 'licence', 'license', 'dob', 'birth',
  'creditcard', 'cardnumber', 'ccnum', 'cvv', 'cvc', 'iban', 'accountnumber', 'routingnumber',
  'email', 'phone', 'mobile', 'address', 'postcode', 'zip', 'iban',
];

const MAX_SPECULATIVE_HINT = /^prefetch|preload|preconnect|dns-prefetch|prerender$/i;

function relTokens(element: Element): string[] {
  return (element.getAttribute('rel') ?? '')
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token !== '');
}

/** `sandbox` tokens: an absent attribute is not the same as an empty one (empty = fully locked). */
function sandboxTokens(element: Element): string[] {
  const raw = element.getAttribute('sandbox');
  if (raw === null) return [];
  return raw
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token !== '');
}

function observeIframe(element: Element, pageHostname: string, pageScheme: string): IframeReport {
  const rawSrc = element.getAttribute('src');
  const src = rawSrc === null || rawSrc.trim() === '' ? null : rawSrc.trim();
  const absolute = src === null ? null : resolveAgainst(element.ownerDocument?.baseURI ?? '', src);
  const hostname = absolute === null ? null : hostnameOf(absolute) || null;
  const tokens = sandboxTokens(element);
  const allow = (element.getAttribute('allow') ?? '')
    .toLowerCase()
    .split(/[;\s]+/)
    .filter((token) => token !== '')
    .map((token) => token.split('=')[0] ?? token);

  return {
    src: absolute,
    hostname,
    isThirdParty: hostname !== null && isThirdPartyTo(pageHostname, hostname),
    isInsecure: pageScheme === 'https' && absolute !== null && !isSecureUrl(absolute),
    hasSandbox: element.hasAttribute('sandbox'),
    sandboxTokens: tokens,
    allowTokens: allow,
    allowsSameOrigin: tokens.includes('allow-same-origin'),
    allowsTopNavigation: tokens.some((token) => token.startsWith('allow-top-navigation')),
    allowsPopups: tokens.includes('allow-popups') || tokens.includes('allow-popups-to-escape-sandbox'),
    allowsForms: tokens.includes('allow-forms'),
    title: element.getAttribute('title'),
    visible: !element.hasAttribute('hidden') && !/display\s*:\s*none/i.test(element.getAttribute('style') ?? ''),
  };
}

function observeScript(element: Element, pageHostname: string, pageScheme: string): ScriptReport {
  const rawSrc = element.getAttribute('src');
  const src = rawSrc === null || rawSrc.trim() === '' ? null : rawSrc.trim();
  const absolute = src === null ? null : resolveAgainst(element.ownerDocument?.baseURI ?? '', src);
  const type = (element.getAttribute('type') ?? '').toLowerCase();
  const text = src === null ? (element.textContent ?? '') : '';

  return {
    src: absolute,
    hostname: absolute === null ? null : hostnameOf(absolute) || null,
    isThirdParty: absolute !== null && isThirdPartyTo(pageHostname, hostnameOf(absolute)),
    isInsecure: pageScheme === 'https' && absolute !== null && !isSecureUrl(absolute),
    hasIntegrity: element.hasAttribute('integrity'),
    isAsync: element.hasAttribute('async'),
    isDefer: element.hasAttribute('defer'),
    isModule: type === 'module',
    // A static count of `eval`-shaped calls in inline script text. It is a hint for a human, not
    // a verdict: minified third-party code contains these without anyone intending them.
    inlineEvalSignals: src === null ? (text.match(/\b(?:eval|new\s+Function)\s*\(/g) ?? []).length : 0,
  };
}
export interface DomObserverOptions extends FormObserverOptions {
  /** Lower-case hostname of the page. */
  pageHostname: string;
  /** `https` or `http`; used to decide what counts as mixed content. */
  pageScheme: string;
  /** `true` when the extension could read `window.top.location`, i.e. the frame is same-origin. */
  isFramed?: boolean;
  /** Optional extra insecure URLs the caller already knows about (from resource timings). */
  insecureUrls?: readonly string[];
  collectedAt: number;
}

/**
 * Walks the document once and produces the analysable `DomReport`.
 *
 * One pass, capped lists, no mutation. The report is plain data so it survives
 * `chrome.runtime.sendMessage`'s structured clone unchanged.
 */
export function observeDom(doc: Document, options: DomObserverOptions): DomReport {
  // The caller's URL wins when it provides one: the content script knows the page it was injected
  // into, whereas `document.location` is empty for documents built by tests.
  const url = options.baseUrl || doc.location?.href || '';
  const iframes: IframeReport[] = [];
  for (const element of Array.from(doc.querySelectorAll('iframe, frame'))) {
    if (iframes.length >= MAX_IFRAMES) break;
    iframes.push(observeIframe(element, options.pageHostname, options.pageScheme));
  }

  const scripts: ScriptReport[] = [];
  for (const element of Array.from(doc.querySelectorAll('script'))) {
    if (scripts.length >= MAX_SCRIPTS) break;
    scripts.push(observeScript(element, options.pageHostname, options.pageScheme));
  }

  const mixedContent = options.pageScheme === 'https' ? new Set<string>() : null;
  if (mixedContent) {
    for (const frames of iframes) if (frames.isInsecure && frames.src) mixedContent.add(frames.src);
    for (const script of scripts) if (script.isInsecure && script.src) mixedContent.add(script.src);
    for (const element of Array.from(doc.querySelectorAll('link[href], img[src], source[src], video[src], audio[src]'))) {
      const raw = element.getAttribute('href') ?? element.getAttribute('src');
      if (raw === null) continue;
      const absolute = resolveAgainst(doc.baseURI, raw);
      if (absolute.startsWith('http://')) mixedContent.add(absolute);
    }
    for (const extra of options.insecureUrls ?? []) {
      if (extra.startsWith('http://')) mixedContent.add(extra);
    }
  }

  const speculativeUrls = new Set<string>();
  const dnsPrefetchHosts = new Set<string>();
  for (const element of Array.from(doc.querySelectorAll('link[rel]'))) {
    const tokens = relTokens(element);
    if (!tokens.some((token) => MAX_SPECULATIVE_HINT.test(token))) continue;
    const href = element.getAttribute('href');
    if (href === null || href.trim() === '') continue;
    const absolute = resolveAgainst(doc.baseURI, href);
    speculativeUrls.add(absolute);
    if (tokens.includes('dns-prefetch')) {
      const host = hostnameOf(absolute);
      if (host !== '') dnsPrefetchHosts.add(host);
    }
    if (speculativeUrls.size >= MAX_URLS && dnsPrefetchHosts.size >= MAX_URLS) break;
  }

  const sensitiveFieldNames = new Set<string>();
  let inlineEventHandlerCount = 0;
  for (const element of Array.from(doc.querySelectorAll('*'))) {
    for (const name of element.getAttributeNames()) {
      if (name.startsWith('on')) inlineEventHandlerCount += 1;
    }
    if (sensitiveFieldNames.size >= MAX_SENSITIVE_NAMES) continue;
    const label = `${element.getAttribute('name') ?? ''} ${element.getAttribute('id') ?? ''}`.toLowerCase();
    if (label.trim() === '') continue;
    if (SENSITIVE_FIELD_HINTS.some((hint) => label.includes(hint))) {
      const trimmed = label.trim().split(/\s+/)[0];
      if (trimmed) sensitiveFieldNames.add(trimmed);
    }
  }

  let inlineScriptCount = 0;
  for (const script of scripts) {
    if (script.src === null) inlineScriptCount += 1;
  }

  let targetBlankWithoutNoopener = 0;
  for (const element of Array.from(doc.querySelectorAll('a[target]'))) {
    if ((element.getAttribute('target') ?? '').toLowerCase() !== '_blank') continue;
    const rel = relTokens(element);
    if (!rel.includes('noopener') && !rel.includes('noreferrer')) targetBlankWithoutNoopener += 1;
  }

  const notes: string[] = [];
  if (mixedContent && mixedContent.size > 0) {
    notes.push(`${mixedContent.size} subresource(s) were referenced over HTTP from an HTTPS page.`);
  }

  return {
    url,
    collectedAt: options.collectedAt,
    documentHasCspMeta: hasMetaCsp(doc),
    forms: observeForms(doc, options),
    iframes,
    scripts,
    mixedContentUrls: Array.from(mixedContent ?? []).slice(0, MAX_URLS),
    speculativeUrls: Array.from(speculativeUrls).slice(0, MAX_URLS),
    dnsPrefetchHosts: Array.from(dnsPrefetchHosts).slice(0, MAX_URLS),
    pingAttributeCount: doc.querySelectorAll('a[ping]').length,
    inlineEventHandlerCount,
    inlineScriptCount,
    sensitiveFieldNames: Array.from(sensitiveFieldNames),
    passwordFieldCount: countPasswordFields(doc),
    isFramed: options.isFramed === true,
    targetBlankWithoutNoopener,
    notes,
  };
}

/** True when the document carries a `<meta http-equiv="Content-Security-Policy">` tag. */
function hasMetaCsp(doc: Document): boolean {
  for (const meta of Array.from(doc.querySelectorAll('meta[http-equiv]'))) {
    const value = (meta.getAttribute('http-equiv') ?? '').trim().toLowerCase();
    if (value === 'content-security-policy') return true;
  }
  return false;
}

/**
 * True when this document sits inside a frame it cannot read out of - the case Sentinel reports
 * as "framed by another origin".
 *
 * Reaching for `window.top` never throws; reading `window.top.location.href` does, and only for a
 * cross-origin parent. So the question is answered by trying, and the throw is information rather
 * than an error: it means the embedding page belongs to somebody else.
 */
export function isInCrossOriginFrame(win: Window): boolean {
  try {
    const top = win.top;
    if (!top || top === win.self) return false;
    // Same-origin ancestor: readable, so this frame is not cross-origin.
    void top.location.href;
    return false;
  } catch {
    return true;
  }
}

/** Origin of the embedding page when it is readable, or `null`. */
export function frameOrigin(win: Window): string | null {
  try {
    const top = win.top;
    if (!top || top === win.self) return null;
    return originOf(top.location.href) || null;
  } catch {
    return null;
  }
}