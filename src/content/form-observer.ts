/**
 * Form observation from the DOM.
 *
 * SAFETY CONTRACT - this module and everything it calls:
 *
 *   1. Never reads an input's `value` (or `checked`, or a field's text content). Only attributes
 *      are inspected: `type`, `name`, `autocomplete`, `action`, `method`, `hidden`, `style`.
 *   2. Never calls `submit()`, `requestSubmit()`, `focus()`, `click()` or `preventDefault()`.
 *   3. Never registers a submit/input/change listener, so it cannot intercept, delay or observe
 *      a submission the user started.
 *   4. Never writes to the page: no attribute is set, no node is created or removed.
 *
 * Sentinel is an observer, and a password field is the one place in a page where being a
 * participant would be indefensible. `src/content/form-observer.test.ts` pins this contract by
 * planting a known secret in a field and proving it never reaches the report.
 *
 * A form with no `action` submits to the document URL, so every action is resolved against
 * `document.baseURI` (which honours `<base href>`) rather than guessed.
 */

import { hostnameOf, resolveAgainst, schemeOf } from '../shared/urls';
import { isThirdPartyTo } from '../core/domain';
import type { FormInputReport, FormReport } from '../shared/observation';

export interface FormObserverOptions {
  /** Hostname of the top-level page, used to decide whether an action is third-party. */
  pageHostname: string;
  /** True when the document this observer walks sits inside a cross-origin frame. */
  inCrossOriginFrame?: boolean;
  /** Base URL for resolving relative actions; defaults to `document.baseURI`. */
  baseUrl?: string;
}

/** Caps, so a hostile page cannot bloat a report with thousands of inputs. */
export const MAX_FORMS = 200;
export const MAX_INPUTS_PER_FORM = 60;

function attribute(element: Element, name: string): string | null {
  const value = element.getAttribute(name);
  return value === null ? null : value.trim();
}

function inputType(element: Element): string {
  // `getAttribute` rather than `.type`: this keeps the observer working for elements a page has
  // built in ways browsers disagree about, and never invokes a property getter.
  return (attribute(element, 'type') ?? 'text').toLowerCase();
}

function isHiddenByAncestor(element: Element): boolean {
  let node: Element | null = element.parentElement;
  while (node && node.tagName.toLowerCase() !== 'form') {
    if (node.hasAttribute('hidden')) return true;
    const style = attribute(node, 'style');
    if (style !== null && /display\s*:\s*none/i.test(style)) return true;
    node = node.parentElement;
  }
  return false;
}

/** True when the form is nested inside another `<form>` (only possible via injected HTML). */
function isNestedForm(form: Element): boolean {
  const outer = form.parentElement?.closest('form') ?? null;
  return outer !== null && outer !== form;
}

function describeInputs(form: Element): FormInputReport[] {
  const inputs: FormInputReport[] = [];

  for (const element of Array.from(form.querySelectorAll('input, select, textarea'))) {
    if (inputs.length >= MAX_INPUTS_PER_FORM) break;
    const autocomplete = attribute(element, 'autocomplete');
    inputs.push({
      type: inputType(element),
      name: attribute(element, 'name') ?? '',
      hasAutocomplete: autocomplete !== null,
      // Kept verbatim (lower-cased) rather than reduced to a boolean, so the analyser can tell
      // `off` from `new-password` and `current-password`.
      autocomplete: autocomplete === null ? null : autocomplete.toLowerCase(),
    });
  }

  return inputs;
}
/** Observes one `<form>`. Reads attributes only - see the safety contract above. */
export function observeForm(form: Element, options: FormObserverOptions): FormReport {
  const baseUrl = options.baseUrl ?? form.ownerDocument?.baseURI ?? '';
  const rawAction = attribute(form, 'action');
  // A missing action submits to the document URL; so does an empty one. Both resolve the same way.
  const actionUrl = resolveAgainst(baseUrl, rawAction ?? '');
  const actionHostname = hostnameOf(actionUrl) || null;

  const inputs = describeInputs(form);
  const passwordInputs = inputs.filter((input) => input.type === 'password');
  const autocompleteOffCount = inputs.filter((input) => input.autocomplete === 'off').length;

  const hasHiddenPasswordField = Array.from(form.querySelectorAll('input'))
    .filter((element) => inputType(element) === 'password')
    .some((element) => element.hasAttribute('hidden') || isHiddenByAncestor(element));

  const isThirdPartyAction =
    actionHostname !== null && isThirdPartyTo(options.pageHostname, actionHostname);

  // Not "insecure relative to the page" but "not HTTPS": a password sent over HTTP is
  // interceptable whether the page around it was HTTP or HTTPS.
  const isInsecureAction = schemeOf(actionUrl) !== 'https';

  return {
    actionUrl,
    actionHostname,
    method: (attribute(form, 'method') ?? 'get').toLowerCase(),
    inCrossOriginFrame: options.inCrossOriginFrame === true,
    isNested: isNestedForm(form),
    isThirdPartyAction,
    isInsecureAction,
    hasPasswordField: passwordInputs.length > 0,
    hasHiddenPasswordField,
    hasFileInput: inputs.some((input) => input.type === 'file'),
    hasAutocompleteDisabled: autocompleteOffCount > 0,
    autocompleteOffCount,
    inputCount: inputs.length,
    inputs,
  };
}

/** Every form in the document, in document order, capped at `MAX_FORMS`. */
export function observeForms(doc: Document, options: FormObserverOptions): FormReport[] {
  const forms: FormReport[] = [];
  for (const form of Array.from(doc.querySelectorAll('form'))) {
    if (forms.length >= MAX_FORMS) break;
    forms.push(observeForm(form, options));
  }
  return forms;
}

/**
 * Number of password fields in the document.
 *
 * Counted separately from `observeForms` because a password field outside a `<form>` is still a
 * password field, and "how many credentials does this page collect" is a question about the
 * page, not about its markup being well-formed.
 */
export function countPasswordFields(doc: Document): number {
  let count = 0;
  for (const element of Array.from(doc.querySelectorAll('input'))) {
    if (inputType(element) === 'password') count += 1;
  }
  return count;
}