/**
 * Page-hygiene signals: the page's own structural weaknesses.
 *
 * Everything here needs the DOM report from the content script, and nothing here reads a value
 * a user typed - the form observer only ever inspects attributes (see `src/content/form-observer.ts`).
 * When the DOM report is missing, every signal reports `measured: null`: a page Sentinel could
 * not look at must not be described as well behaved.
 *
 * A check that *did* run and found nothing wrong measures 100, not `null`. `null` is reserved for
 * "Sentinel could not look", which is a different fact and a different thing to tell the user
 * (see D-006 in `docs/ARCHITECTURE.md`).
 */

import { assessment, countLabel, evidence, evidenceList, quality, sampleList, unavailable } from './shared';
import { pageObserved, resourcesCollected, type AnalysisContext, type SignalAnalyzer } from '../../../shared/analysis';
import type { FormReport } from '../../../shared/observation';
import type { SignalAssessment } from '../../../core/types';

/** Kinds whose insecure load is *active* mixed content: the browser may already block them. */
const ACTIVE_KINDS = new Set(['script', 'stylesheet', 'sub_frame', 'xmlhttprequest', 'media', 'other']);

function passwordForms(forms: readonly FormReport[]): FormReport[] {
  return forms.filter((form) => form.hasPasswordField);
}

/** Forms with no password field: destinations are scored for these only (see below). */
function nonPasswordForms(forms: readonly FormReport[]): FormReport[] {
  return forms.filter((form) => !form.hasPasswordField);
}

function describeForm(form: FormReport, index: number): string {
  const target = form.actionUrl ?? 'the page itself';
  return `form ${index + 1} (${form.method.toUpperCase()} ${target})`;
}

function mixedContentAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'hygiene.mixed-content';
  const title = 'Mixed content';
  const securePage = context.page.scheme === 'https';

  // Mixed content is a property of a secure page: on an HTTP page every subresource is already
  // insecure, which is the connection signals' finding, not this one's.
  if (!securePage) {
    return assessment({
      signalId,
      title,
      measured: null,
      confidence: 'high',
      detail:
        'This page is not served over HTTPS, so mixed content does not apply - the whole page is already unencrypted.',
      evidence: evidenceList([evidence('Scheme', context.page.scheme)]),
    });
  }

  const fromRequests = context.requests.insecureSubresources;
  if (!pageObserved(context)) {
    return unavailable(
      signalId,
      title,
      'Sentinel did not observe this page load at all, so it cannot tell which subresources were loaded insecurely.',
    );
  }

  if (!resourcesCollected(context) && context.dom === null) {
    return unavailable(
      signalId,
      title,
      'Sentinel has neither the page report nor its resource timings yet, so it cannot tell which subresources were loaded insecurely.',
    );
  }

  const domUrls = context.dom?.mixedContentUrls ?? [];
  const known = new Set(fromRequests.map((request) => request.url));
  const extraFromDom = domUrls.filter((url) => !known.has(url));

  if (fromRequests.length === 0 && extraFromDom.length === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: resourcesCollected(context) ? 'high' : 'medium',
      detail: 'Every subresource this page loaded came over HTTPS.',
      evidence: evidenceList([evidence('Insecure subresources', 'none')]),
    });
  }

  // Active content (a script, a stylesheet, a frame) is materially worse than a passive one.
  const active = fromRequests.filter((request) => ACTIVE_KINDS.has(request.kind));
  const passive = fromRequests.filter((request) => !ACTIVE_KINDS.has(request.kind));
  const deductions: number[] = [];
  if (active.length > 0) deductions.push(Math.min(70, active.length * 45));
  if (passive.length > 0) deductions.push(Math.min(40, passive.length * 15));
  if (extraFromDom.length > 0) deductions.push(Math.min(40, extraFromDom.length * 15));

  const examples = sampleList(
    [...active, ...passive].map((request) => `${request.hostname} (${request.kind})`).concat(extraFromDom),
    4,
  );

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      active.length > 0
        ? `This HTTPS page loads ${countLabel(active.length, 'insecure active resource')}, which can be rewritten in transit even though the padlock still shows: ${examples}.`
        : `This HTTPS page loads ${countLabel(passive.length + extraFromDom.length, 'insecure subresource')} that can be altered in transit: ${examples}.`,
    evidence: evidenceList([
      evidence('Insecure active resources', String(active.length)),
      evidence('Insecure passive resources', String(passive.length)),
      evidence('Insecure URLs', sampleList([...fromRequests.map((r) => r.url), ...extraFromDom], 6)),
    ]),
    remediation: 'Serve every subresource over HTTPS and redirect HTTP requests to it.',
  });
}
/**
 * Password handling.
 *
 * The scoring model's rationale for this signal is about *capture in transit*: an insecure
 * action, a third-party action, or a frame that can wrap the page. Autocomplete is recorded and
 * flagged separately - `autocomplete="off"` on a password field is a red flag (it removes the
 * password manager's protection without adding any), but it is not the same class of problem as
 * posting a password to an HTTP endpoint, so it costs far less.
 */
function passwordFormsAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'hygiene.password-forms';
  const title = 'Password handling';

  if (context.dom === null) {
    return unavailable(
      signalId,
      title,
      'No page report arrived from the content script, so Sentinel could not check whether this page has a password field.',
    );
  }

  const forms = passwordForms(context.dom.forms);
  if (context.dom.passwordFieldCount === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail: 'This page has no password field, so there is no credential here to intercept.',
      evidence: evidenceList([evidence('Password fields', 'none')]),
    });
  }

  const problems: string[] = [];
  const deductions: number[] = [];
  const autocompleteOff: string[] = [];

  for (const [index, form] of forms.entries()) {
    const where = describeForm(form, index);
    if (form.isInsecureAction) {
      deductions.push(60);
      problems.push(`${where} posts the password over an unencrypted connection`);
    } else if (form.isThirdPartyAction) {
      deductions.push(45);
      problems.push(`${where} sends the password to another domain`);
    }
    if (form.inCrossOriginFrame) {
      deductions.push(40);
      problems.push(`${where} sits inside a cross-origin frame`);
    }
    if (form.isNested) {
      deductions.push(15);
      problems.push(`${where} is nested inside another form`);
    }
    if (form.hasHiddenPasswordField) {
      deductions.push(25);
      problems.push(`${where} has a hidden password field`);
    }

    for (const input of form.inputs) {
      if (input.type !== 'password') continue;
      // `off` looks like security but only prevents the password manager from helping.
      if (input.autocomplete === 'off') autocompleteOff.push(input.name || '(unnamed field)');
      if (input.autocomplete === null && form.isInsecureAction) {
        deductions.push(10);
      }
    }
  }

  if (autocompleteOff.length > 0) deductions.push(Math.min(10, autocompleteOff.length * 5));

  const multipleFields = context.dom.passwordFieldCount > 1;
  const evidenceRows = [
    evidence('Password fields', String(context.dom.passwordFieldCount)),
    evidence('Forms with a password field', String(forms.length)),
    evidence(
      'Login and registration on one page',
      multipleFields ? 'yes (more than one password field)' : 'no',
    ),
    evidence('Autocomplete off', autocompleteOff.length > 0 ? sampleList(autocompleteOff, 4) : 'none'),
  ];
  for (const [index, form] of forms.slice(0, 4).entries()) {
    evidenceRows.push(
      evidence(
        `Form ${index + 1}`,
        `${form.method.toUpperCase()} ${form.actionUrl ?? 'the page itself'} - ` +
          `${form.isInsecureAction ? 'insecure' : form.isThirdPartyAction ? 'third-party' : 'same-origin'} action`,
      ),
    );
  }

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      problems.length > 0
        ? `Password handling problems: ${problems.join('; ')}.` +
          (autocompleteOff.length > 0
            ? ` Autocomplete is switched off on ${countLabel(autocompleteOff.length, 'password field')}, which weakens the password manager without protecting anything.`
            : '')
        : `This page has ${countLabel(context.dom.passwordFieldCount, 'password field')} and submits ${forms.length === 1 ? 'it' : 'them'} safely: same-origin, over HTTPS.` +
          (autocompleteOff.length > 0
            ? ` Autocomplete is switched off on ${countLabel(autocompleteOff.length, 'field')}, which prevents a password manager from protecting the credential.`
            : ''),
    evidence: evidenceList(evidenceRows),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Post credentials to your own origin over HTTPS, never from inside a frame, and leave password autocomplete enabled.',
  });
}
/**
 * Form destinations.
 *
 * Deliberately scoped to forms *without* a password field. A password form that posts to an
 * unencrypted third-party endpoint is already charged to `hygiene.password-forms`, and charging
 * the same fact twice is exactly what D-003 exists to prevent: two signals would each believe
 * they own the finding, and the category budget would be spent twice on one mistake.
 */
function formTargetsAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'hygiene.form-targets';
  const title = 'Form destinations';

  if (context.dom === null) {
    return unavailable(
      signalId,
      title,
      "No page report arrived from the content script, so Sentinel could not read this page's form actions.",
    );
  }

  const forms = nonPasswordForms(context.dom.forms);
  if (forms.length === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail:
        context.dom.forms.length === 0
          ? 'This page has no forms, so nothing is submitted anywhere.'
          : 'This page has no form without a password field, so every destination is covered by the password-handling check instead.',
      evidence: evidenceList([
        evidence('Forms', String(context.dom.forms.length)),
        evidence('Forms without a password field', 'none'),
      ]),
    });
  }

  const problems: string[] = [];
  const dangerous: FormReport[] = [];
  const deductions: number[] = [];

  for (const [index, form] of forms.entries()) {
    const where = describeForm(form, index);
    if (form.isThirdPartyAction) {
      deductions.push(50);
      dangerous.push(form);
      problems.push(`${where} submits to a different domain`);
    } else if (form.isInsecureAction) {
      deductions.push(30);
      dangerous.push(form);
      problems.push(`${where} submits over an unencrypted connection`);
    }
    if (form.inCrossOriginFrame && !form.isThirdPartyAction) {
      deductions.push(20);
      problems.push(`${where} submits from inside a cross-origin frame`);
    }
  }

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      problems.length === 0
        ? `All ${countLabel(forms.length, 'form')} without a password field submit to this site over HTTPS.`
        : `Form destination problems: ${problems.join('; ')}.`,
    evidence: evidenceList([
      evidence('Forms without a password field', String(forms.length)),
      evidence('Cross-origin actions', String(dangerous.filter((form) => form.isThirdPartyAction).length)),
      evidence('Insecure actions', String(dangerous.filter((form) => form.isInsecureAction).length)),
      evidence('Destinations', sampleList(forms.map((form) => form.actionHostname ?? '(this page)'), 5)),
    ]),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Submit to your own origin over HTTPS, and keep third-party forms in a sandboxed frame.',
  });
}
/**
 * Embedded content safety.
 *
 * An unsandboxed third-party frame is the dangerous case: it can run scripts, navigate the top
 * window and open popups on the page's behalf. A sandboxed frame that still grants
 * `allow-scripts allow-same-origin` is nearly as bad, because together those two tokens undo the
 * sandbox - so the tokens are scored, not just the presence of the attribute.
 */
function embeddedContentAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'hygiene.embedded-content';
  const title = 'Embedded content safety';

  if (context.dom === null) {
    return unavailable(
      signalId,
      title,
      'No page report arrived from the content script, so Sentinel could not inspect the frames embedded in this page.',
    );
  }

  const iframes = context.dom.iframes;
  if (iframes.length === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail: "This page embeds no frames, so nothing is loaded with the page's privileges.",
      evidence: evidenceList([evidence('Frames', 'none')]),
    });
  }

  const problems: string[] = [];
  const deductions: number[] = [];

  for (const [index, frame] of iframes.entries()) {
    const where = `frame ${index + 1} (${frame.hostname ?? frame.src ?? 'inline'})`;
    const thirdParty = frame.isThirdParty;
    if (!frame.hasSandbox) {
      deductions.push(thirdParty ? 60 : 25);
      problems.push(`${where} has no sandbox attribute${thirdParty ? ' and is third-party' : ''}`);
      continue;
    }
    if (thirdParty && frame.allowsSameOrigin && frame.allowsForms) {
      deductions.push(50);
      problems.push(`${where} is third-party and its sandbox grants both same-origin and form submission`);
    } else if (thirdParty && frame.allowsSameOrigin) {
      deductions.push(40);
      problems.push(`${where} is third-party and its sandbox grants same-origin access`);
    } else if (frame.allowsTopNavigation) {
      deductions.push(40);
      problems.push(`${where} may navigate the top window`);
    } else if (frame.allowsPopups) {
      deductions.push(20);
      problems.push(`${where} may open popups`);
    } else if (thirdParty) {
      deductions.push(15);
      problems.push(`${where} is a sandboxed third-party frame`);
    }
    if (frame.isInsecure) {
      deductions.push(20);
      problems.push(`${where} is loaded over HTTP`);
    }
  }

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: 'high',
    detail:
      problems.length === 0
        ? `All ${countLabel(iframes.length, 'frame')} on this page are same-origin or properly sandboxed.`
        : `Embedded content problems: ${problems.join('; ')}.`,
    evidence: evidenceList([
      evidence('Frames', String(iframes.length)),
      evidence('Third-party frames', String(iframes.filter((frame) => frame.isThirdParty).length)),
      evidence('Unsandboxed frames', String(iframes.filter((frame) => !frame.hasSandbox).length)),
      evidence(
        'Frames that may navigate the top window',
        String(iframes.filter((frame) => frame.allowsTopNavigation).length),
      ),
    ]),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Sandbox third-party frames, avoid granting `allow-same-origin` and `allow-forms` together, and drop `allow-top-navigation`.',
  });
}

export const hygieneAnalyzer: SignalAnalyzer = {
  id: 'hygiene',
  moduleId: 'trust-score',

  analyze(context) {
    return [
      mixedContentAssessment(context),
      passwordFormsAssessment(context),
      formTargetsAssessment(context),
      embeddedContentAssessment(context),
    ];
  },
};