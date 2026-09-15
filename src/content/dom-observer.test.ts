// @vitest-environment jsdom
/**
 * DOM observer tests.
 *
 * The DOM observer feeds the `hygiene` analysers, so these tests check the facts those signals
 * read: frames and their sandbox tokens, insecure subresources on an HTTPS page, ping attributes,
 * speculative hints and password counts. The same safety contract as `form-observer.test.ts`
 * applies here and is asserted again: attributes only, no mutation.
 */

import { describe, expect, it, vi } from 'vitest';
import { observeDom, type DomObserverOptions } from './dom-observer';

const PAGE = 'https://shop.example.com/checkout';
const NOW = 1_700_000_000_000;

function documentWith(html: string): Document {
  const doc = document.implementation.createHTMLDocument('fixture');
  doc.body.innerHTML = html;
  Object.defineProperty(doc, 'baseURI', { value: PAGE, configurable: true });
  return doc;
}

function options(overrides: Partial<DomObserverOptions> = {}): DomObserverOptions {
  return {
    pageHostname: 'shop.example.com',
    pageScheme: 'https',
    baseUrl: PAGE,
    collectedAt: NOW,
    ...overrides,
  };
}

describe('observeDom', () => {
  it('describes an ordinary page without inventing problems', () => {
    const doc = documentWith(`
      <link rel="stylesheet" href="/style.css" />
      <script src="/app.js" defer integrity="sha384-abc"></script>
      <a href="https://shop.example.com/help" target="_blank" rel="noopener">Help</a>
      <img src="/logo.png" alt="" />
    `);
    const report = observeDom(doc, options());

    expect(report.url).toBe(PAGE);
    expect(report.collectedAt).toBe(NOW);
    expect(report.mixedContentUrls).toEqual([]);
    expect(report.pingAttributeCount).toBe(0);
    expect(report.targetBlankWithoutNoopener).toBe(0);
    expect(report.scripts[0]).toMatchObject({
      src: 'https://shop.example.com/app.js',
      isDefer: true,
      hasIntegrity: true,
    });
    expect(report.documentHasCspMeta).toBe(false);
  });

  it('records a frame with its sandbox and allow tokens', () => {
    const doc = documentWith(`
      <iframe src="https://ads.example.net/embed" sandbox="allow-scripts allow-same-origin" allow="camera; geolocation" title="Advert"></iframe>
      <iframe src="/local.html"></iframe>
    `);
    const report = observeDom(doc, options());

    expect(report.iframes).toHaveLength(2);
    expect(report.iframes[0]).toMatchObject({
      hostname: 'ads.example.net',
      isThirdParty: true,
      hasSandbox: true,
      allowsSameOrigin: true,
      allowsForms: false,
      allowsTopNavigation: false,
      title: 'Advert',
    });
    expect(report.iframes[1]).toMatchObject({ isThirdParty: false, hasSandbox: false });
  });

  it('counts ping attributes on links, which report clicks to a third party', () => {
    const doc = documentWith(`
      <a href="https://shop.example.com/next" ping="https://collect.example.net/ping">Next</a>
      <a href="https://shop.example.com/other" ping="https://collect.example.net/ping">Other</a>
    `);
    expect(observeDom(doc, options()).pingAttributeCount).toBe(2);
  });

  it('collects speculative connections and DNS prefetch hosts separately', () => {
    const doc = documentWith(`
      <link rel="preconnect" href="https://cdn.example.net" />
      <link rel="dns-prefetch" href="https://tracker.example.org" />
      <link rel="preload" href="/font.woff2" as="font" />
      <link rel="prefetch" href="https://next.example.net/page" />
    `);
    const report = observeDom(doc, options());

    expect(report.speculativeUrls).toHaveLength(4);
    expect(report.dnsPrefetchHosts).toEqual(['tracker.example.org']);
  });

  it('counts inline scripts, inline handlers and sensitive field labels without reading values', () => {
    const doc = documentWith(`
      <script>var a = eval('1+1');</script>
      <script src="/app.js"></script>
      <button onclick="doThing()">Go</button>
      <input type="password" name="password" value="SECRET" />
      <input type="text" name="creditCardNumber" />
      <p id="emailHelp">Help</p>
    `);
    const report = observeDom(doc, options());

    expect(report.inlineScriptCount).toBe(1);
    expect(report.inlineEventHandlerCount).toBe(1);
    expect(report.scripts[0]?.inlineEvalSignals).toBe(1);
    expect(report.scripts[1]?.inlineEvalSignals).toBe(0);
    expect(report.sensitiveFieldNames).toContain('password');
    expect(report.sensitiveFieldNames).toContain('creditcardnumber');
    expect(report.passwordFieldCount).toBe(1);
    expect(JSON.stringify(report)).not.toContain('SECRET');
  });

  it('counts target=_blank links that omit noopener', () => {
    const doc = documentWith(`
      <a href="https://other.example.net" target="_blank">One</a>
      <a href="https://other.example.net" target="_blank" rel="noopener">Two</a>
      <a href="https://other.example.net" target="_blank" rel="noreferrer">Three</a>
    `);
    expect(observeDom(doc, options()).targetBlankWithoutNoopener).toBe(1);
  });

  it('detects a meta CSP and reports it, since browsers apply it late', () => {
    const doc = documentWith('<meta http-equiv="content-security-policy" content="default-src self" />');
    expect(observeDom(doc, options()).documentHasCspMeta).toBe(true);
  });

  it('carries the forms it observed, with the caller options applied', () => {
    const doc = documentWith('<form action="/login" method="post"><input type="password" name="pass" /></form>');
    const report = observeDom(doc, options({ inCrossOriginFrame: true }));

    expect(report.forms).toHaveLength(1);
    expect(report.forms[0]?.hasPasswordField).toBe(true);
    expect(report.forms[0]?.inCrossOriginFrame).toBe(true);
  });

  it('never mutates the document it observes', () => {
    const doc = documentWith('<form action="/login"><input type="password" name="pass" /></form>');
    const before = doc.body.innerHTML;
    const submit = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => undefined);

    observeDom(doc, options());

    expect(doc.body.innerHTML).toBe(before);
    expect(submit).not.toHaveBeenCalled();
    submit.mockRestore();
  });
});