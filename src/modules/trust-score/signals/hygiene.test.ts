/**
 * Page-hygiene signal tests.
 *
 * Two contracts matter more than any individual number here:
 *
 *   1. A check that ran and found nothing wrong measures 100, while a check Sentinel could not
 *      run at all measures `null`. D-006 in `docs/ARCHITECTURE.md` exists because the popup has
 *      to be able to tell the user which of those two just happened.
 *   2. The same fact is never charged twice: a password form posting to an unencrypted endpoint
 *      is `hygiene.password-forms`'s finding, and `hygiene.form-targets` deliberately ignores
 *      forms that have a password field.
 */

import { describe, expect, it } from 'vitest';
import { hygieneAnalyzer } from './hygiene';
import { buildAnalysisContext } from '../../../shared/analysis';
import type { SignalAssessment } from '../../../core/types';
import type {
  DomReport,
  FormReport,
  HeaderEntry,
  IframeReport,
  PageObservation,
  RequestRecord,
  ResourceTimingRecord,
} from '../../../shared/observation';

const NOW = 1_700_000_000_000;
const URL = 'https://shop.example.com/checkout';

function baseDom(overrides: Partial<DomReport> = {}): DomReport {
  return {
    url: URL,
    collectedAt: NOW - 500,
    documentHasCspMeta: false,
    forms: [],
    iframes: [],
    scripts: [],
    mixedContentUrls: [],
    speculativeUrls: [],
    dnsPrefetchHosts: [],
    pingAttributeCount: 0,
    inlineEventHandlerCount: 0,
    inlineScriptCount: 0,
    sensitiveFieldNames: [],
    passwordFieldCount: 0,
    isFramed: false,
    targetBlankWithoutNoopener: 0,
    notes: [],
    ...overrides,
  };
}

function form(overrides: Partial<FormReport> = {}): FormReport {
  return {
    actionUrl: 'https://shop.example.com/login',
    actionHostname: 'shop.example.com',
    method: 'post',
    inCrossOriginFrame: false,
    isNested: false,
    isThirdPartyAction: false,
    isInsecureAction: false,
    hasPasswordField: false,
    hasHiddenPasswordField: false,
    hasFileInput: false,
    hasAutocompleteDisabled: false,
    autocompleteOffCount: 0,
    inputCount: 0,
    inputs: [],
    ...overrides,
  };
}

function passwordForm(overrides: Partial<FormReport> = {}): FormReport {
  return form({
    hasPasswordField: true,
    inputs: [{ type: 'password', name: 'pass', hasAutocomplete: true, autocomplete: 'current-password' }],
    inputCount: 1,
    ...overrides,
  });
}

function iframe(overrides: Partial<IframeReport> = {}): IframeReport {
  return {
    src: 'https://ads.example.net/embed',
    hostname: 'ads.example.net',
    isThirdParty: true,
    isInsecure: false,
    hasSandbox: true,
    sandboxTokens: ['allow-scripts'],
    allowTokens: [],
    allowsSameOrigin: false,
    allowsTopNavigation: false,
    allowsPopups: false,
    allowsForms: false,
    title: 'Advert',
    visible: true,
    ...overrides,
  };
}
function timing(hostname: string, initiatorType = 'script', path = '/app.js'): ResourceTimingRecord {
  return {
    url: `https://${hostname}${path}`,
    hostname,
    origin: `https://${hostname}`,
    initiatorType,
    transferSize: 900,
    durationMs: 20,
    thirdParty: hostname !== 'shop.example.com',
  };
}

function request(hostname: string, kind: RequestRecord['kind'], url: string): RequestRecord {
  return {
    requestId: `req-${hostname}-${kind}`,
    url,
    hostname,
    thirdParty: hostname !== 'shop.example.com',
    kind,
    initiatorHostname: 'shop.example.com',
    statusCode: 200,
    fromCache: false,
  };
}

interface AnalyzeOptions {
  dom?: DomReport | null;
  requests?: RequestRecord[];
  timings?: ResourceTimingRecord[];
  headers?: Record<string, string>;
  url?: string;
  observed?: boolean;
  resourcesCollected?: boolean;
}

function analyze(options: AnalyzeOptions = {}): Record<string, SignalAssessment> {
  const url = options.url ?? URL;
  const observed = options.observed !== false;
  const hostname = (url.replace(/^[a-z]+:\/\//, '').split('/')[0] ?? 'shop.example.com').split(':')[0] ?? '';
  const headers: HeaderEntry[] = Object.entries(
    options.headers ?? { 'content-security-policy': "default-src 'self'" },
  ).map(([name, value]) => ({ name, value }));

  const observation: PageObservation = {
    observationId: 'obs-1',
    tabId: 1,
    frameId: 0,
    url,
    hostname,
    origin: `${url.replace(/^([a-z]+):\/\/.*/, '$1')}://${hostname}`,
    startedAt: NOW - 1000,
    updatedAt: NOW,
    mainDocument: observed
      ? {
          url,
          statusCode: 200,
          statusLine: 'HTTP/1.1 200 OK',
          serverIp: '203.0.113.7',
          fromCache: false,
          headers,
          tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
        }
      : null,
    requests: options.requests ?? [],
    requestsTruncated: false,
    resourceTimings: options.timings ?? [],
    resourcesCollected: options.resourcesCollected ?? observed,
    dom: options.dom === undefined ? baseDom() : options.dom,
    warnings: [],
  };

  const assessments = hygieneAnalyzer.analyze(buildAnalysisContext(observation, NOW));
  return Object.fromEntries(assessments.map((assessment) => [assessment.signalId, assessment]));
}

describe('hygieneAnalyzer', () => {
  it('reports the four declared hygiene signals and nothing else', () => {
    expect(Object.keys(analyze()).sort()).toEqual([
      'hygiene.embedded-content',
      'hygiene.form-targets',
      'hygiene.mixed-content',
      'hygiene.password-forms',
    ]);
  });

  it('measures a clean page as clean', () => {
    const results = analyze({ headers: { 'content-security-policy': "default-src 'self'" } });

    expect(results['hygiene.mixed-content']?.measured).toBe(100);
    expect(results['hygiene.password-forms']?.measured).toBe(100);
    expect(results['hygiene.form-targets']?.measured).toBe(100);
    expect(results['hygiene.embedded-content']?.measured).toBe(100);
  });

  it('reports every signal as unmeasured when no page report arrived', () => {
    const results = analyze({ dom: null, observed: false });

    for (const signalId of Object.keys(results)) {
      expect(results[signalId]?.measured, signalId).toBeNull();
    }
  });

  describe('hygiene.mixed-content', () => {
    it('charges hard for insecure active content and less for a passive resource', () => {
      const active = analyze({
        requests: [request('cdn.example.net', 'script', 'http://cdn.example.net/app.js')],
      });
      const passive = analyze({
        requests: [request('img.example.net', 'image', 'http://img.example.net/logo.png')],
      });

      // 45 for one insecure script, versus 15 for a passive image.
      expect(active['hygiene.mixed-content']?.measured).toBe(55);
      expect(active['hygiene.mixed-content']?.detail).toContain('insecure active resource');
      expect(passive['hygiene.mixed-content']?.measured).toBe(85);
      expect(passive['hygiene.mixed-content']?.detail).toContain('insecure subresource');
    });

    it('counts insecure URLs the DOM reported even when no timing was recorded for them', () => {
      const results = analyze({
        dom: baseDom({ mixedContentUrls: ['http://legacy.example.net/widget.js'] }),
      });

      expect(results['hygiene.mixed-content']?.measured).toBe(85);
      expect(results['hygiene.mixed-content']?.evidence).toContainEqual({
        label: 'Insecure URLs',
        value: 'http://legacy.example.net/widget.js',
      });
    });

    it('does not apply to a page that is itself served over HTTP', () => {
      const results = analyze({ url: 'http://shop.example.com/checkout', observed: true });

      // The connection signals own that finding; charging it here as well would double-count it.
      expect(results['hygiene.mixed-content']?.measured).toBeNull();
      expect(results['hygiene.mixed-content']?.detail).toContain('mixed content does not apply');
    });

    it('is unmeasured while the content script is still running', () => {
      const results = analyze({ timings: [], dom: null, resourcesCollected: false });
      expect(results['hygiene.mixed-content']?.measured).toBeNull();
    });
  });

  describe('hygiene.password-forms', () => {
    it('sees nothing to worry about when the page has no password field', () => {
      const results = analyze({ dom: baseDom({ forms: [form()] }) });
      expect(results['hygiene.password-forms']?.measured).toBe(100);
      expect(results['hygiene.password-forms']?.detail).toContain('no password field');
    });

    it('charges a password posted over an unencrypted connection the hardest', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [
            passwordForm({
              actionUrl: 'http://shop.example.com/login',
              isInsecureAction: true,
            }),
          ],
        }),
      });

      expect(results['hygiene.password-forms']?.measured).toBe(40);
      expect(results['hygiene.password-forms']?.detail).toContain('unencrypted connection');
    });

    it('charges a password sent to another domain, and says which', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [
            passwordForm({
              actionUrl: 'https://collect.example.net/login',
              actionHostname: 'collect.example.net',
              isThirdPartyAction: true,
            }),
          ],
        }),
      });

      expect(results['hygiene.password-forms']?.measured).toBe(55);
      expect(results['hygiene.password-forms']?.detail).toContain('another domain');
    });

    it('charges a password form inside a cross-origin frame and one that is nested', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [passwordForm({ inCrossOriginFrame: true, isNested: true })],
        }),
      });

      // 40 (cross-origin frame) + 15 (nested)
      expect(results['hygiene.password-forms']?.measured).toBe(45);
      expect(results['hygiene.password-forms']?.detail).toContain('cross-origin frame');
    });

    it('flags autocomplete=off on a password field without treating it as a serious finding', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [
            passwordForm({
              inputs: [{ type: 'password', name: 'pass', hasAutocomplete: true, autocomplete: 'off' }],
            }),
          ],
        }),
      });

      expect(results['hygiene.password-forms']?.measured).toBe(95);
      expect(results['hygiene.password-forms']?.detail).toContain('Autocomplete is switched off');
    });

    it('accepts new-password as good practice and reports the safe path positively', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [
            passwordForm({
              inputs: [{ type: 'password', name: 'pass', hasAutocomplete: true, autocomplete: 'new-password' }],
            }),
          ],
        }),
      });

      expect(results['hygiene.password-forms']?.measured).toBe(100);
      expect(results['hygiene.password-forms']?.detail).toContain('same-origin, over HTTPS');
    });

    it('notices a login and a registration form on the same page', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 2,
          forms: [passwordForm(), passwordForm({ actionUrl: 'https://shop.example.com/register' })],
        }),
      });

      expect(results['hygiene.password-forms']?.evidence).toContainEqual({
        label: 'Login and registration on one page',
        value: 'yes (more than one password field)',
      });
    });
  });

  describe('hygiene.form-targets', () => {
    it('ignores password forms, which the password-handling signal owns', () => {
      const results = analyze({
        dom: baseDom({
          passwordFieldCount: 1,
          forms: [passwordForm({ isInsecureAction: true, actionUrl: 'http://shop.example.com/login' })],
        }),
      });

      // Charging the same fact to two signals would spend the category budget twice on it.
      expect(results['hygiene.form-targets']?.measured).toBe(100);
      expect(results['hygiene.form-targets']?.detail).toContain('covered by the password-handling check');
    });

    it('charges a form that submits to a different domain', () => {
      const results = analyze({
        dom: baseDom({
          forms: [
            form({
              actionUrl: 'https://collect.example.net/subscribe',
              actionHostname: 'collect.example.net',
              isThirdPartyAction: true,
            }),
          ],
        }),
      });

      expect(results['hygiene.form-targets']?.measured).toBe(50);
      expect(results['hygiene.form-targets']?.detail).toContain('submits to a different domain');
    });

    it('charges a form that submits over HTTP', () => {
      const results = analyze({
        dom: baseDom({
          forms: [form({ actionUrl: 'http://shop.example.com/subscribe', isInsecureAction: true })],
        }),
      });

      expect(results['hygiene.form-targets']?.measured).toBe(70);
      expect(results['hygiene.form-targets']?.detail).toContain('unencrypted connection');
    });

    it('reports no forms as a measured fact rather than a gap', () => {
      const results = analyze({ dom: baseDom({ forms: [] }) });
      expect(results['hygiene.form-targets']?.measured).toBe(100);
      expect(results['hygiene.form-targets']?.detail).toContain('no forms');
    });
  });

  describe('hygiene.embedded-content', () => {
    it('measures no frames as clean', () => {
      const results = analyze({ dom: baseDom({ iframes: [] }) });
      expect(results['hygiene.embedded-content']?.measured).toBe(100);
    });

    it('charges an unsandboxed third-party frame the hardest', () => {
      const results = analyze({ dom: baseDom({ iframes: [iframe({ hasSandbox: false, sandboxTokens: [] })] }) });

      expect(results['hygiene.embedded-content']?.measured).toBe(40);
      expect(results['hygiene.embedded-content']?.detail).toContain('no sandbox attribute');
    });

    it('treats allow-same-origin plus allow-forms as the sandbox being undone', () => {
      const results = analyze({
        dom: baseDom({
          iframes: [
            iframe({ allowsSameOrigin: true, allowsForms: true, sandboxTokens: ['allow-scripts', 'allow-same-origin'] }),
          ],
        }),
      });

      expect(results['hygiene.embedded-content']?.measured).toBe(50);
      expect(results['hygiene.embedded-content']?.detail).toContain('both same-origin and form submission');
    });

    it('charges a frame that may navigate the top window, and one loaded over HTTP', () => {
      const navigates = analyze({ dom: baseDom({ iframes: [iframe({ allowsTopNavigation: true })] }) });
      const insecure = analyze({
        dom: baseDom({
          iframes: [iframe({ isInsecure: true, src: 'http://ads.example.net/embed', allowsPopups: true })],
        }),
      });

      expect(navigates['hygiene.embedded-content']?.measured).toBe(60);
      expect(insecure['hygiene.embedded-content']?.measured).toBe(60);
      expect(insecure['hygiene.embedded-content']?.detail).toContain('loaded over HTTP');
    });

    it('treats a same-origin unsandboxed frame as a lesser problem than a third-party one', () => {
      const results = analyze({
        dom: baseDom({
          iframes: [iframe({ isThirdParty: false, hostname: 'shop.example.com', hasSandbox: false, sandboxTokens: [] })],
        }),
      });

      expect(results['hygiene.embedded-content']?.measured).toBe(75);
    });
  });
});