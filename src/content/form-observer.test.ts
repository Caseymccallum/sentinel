// @vitest-environment jsdom
/**
 * Form observer tests.
 *
 * The safety contract in `form-observer.ts` is the point of this file. Two of these tests exist
 * purely to enforce it: one plants a secret in a password field and proves the string never
 * appears anywhere in the report, the other replaces `submit`/`requestSubmit` with spies and
 * proves the observer never touches them. Everything else checks the attributes that reach the
 * `hygiene` analysers: action resolution, autocomplete, cross-origin targets and password counts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { countPasswordFields, observeForm, observeForms } from './form-observer';

const PAGE = 'https://shop.example.com/checkout';

function documentWith(html: string): Document {
  const doc = document.implementation.createHTMLDocument('fixture');
  doc.body.innerHTML = html;
  // `createHTMLDocument` gives an opaque base URL, so it is set explicitly to model a real page.
  Object.defineProperty(doc, 'baseURI', { value: PAGE, configurable: true });
  return doc;
}

function options(overrides: Partial<Parameters<typeof observeForms>[1]> = {}) {
  return { pageHostname: 'shop.example.com', ...overrides };
}

describe('form observer safety contract', () => {
  const SECRET = 'hunter2-THIS-MUST-NEVER-BE-REPORTED';

  beforeEach(() => {
    vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => undefined);
    vi.spyOn(HTMLFormElement.prototype, 'requestSubmit').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('never lets an input value reach the report', () => {
    const doc = documentWith(`
      <form action="/login" method="post">
        <input type="text" name="user" value="${SECRET}" />
        <input type="password" name="pass" value="${SECRET}" />
        <textarea name="notes">${SECRET}</textarea>
        <input type="checkbox" name="remember" checked />
      </form>
    `);

    const form = observeForm(doc.querySelector('form') as Element, options());
    const serialised = JSON.stringify(form);

    expect(serialised).not.toContain(SECRET);
    expect(serialised).not.toContain('hunter2');
    // The field itself is still described: it is the *value* that must never travel.
    expect(form.inputs.map((input) => input.name)).toEqual(['user', 'pass', 'notes', 'remember']);
    expect(form.inputs.every((input) => !Object.hasOwn(input, 'value'))).toBe(true);
  });

  it('never submits a form, and never registers a submit listener', () => {
    const doc = documentWith(`
      <form action="/login" method="post">
        <input type="password" name="pass" value="secret" />
        <button type="submit">Sign in</button>
      </form>
    `);
    const formElement = doc.querySelector('form') as HTMLFormElement;
    const addEventListener = vi.spyOn(formElement, 'addEventListener');

    observeForms(doc, options());

    expect(HTMLFormElement.prototype.submit).not.toHaveBeenCalled();
    expect(HTMLFormElement.prototype.requestSubmit).not.toHaveBeenCalled();
    for (const call of addEventListener.mock.calls) {
      expect(['submit', 'input', 'change']).not.toContain(call[0]);
    }
  });

  it('does not modify the page it observes', () => {
    const doc = documentWith('<form action="/login" method="post"><input type="password" name="pass" /></form>');
    const before = doc.body.innerHTML;

    observeForms(doc, options());

    expect(doc.body.innerHTML).toBe(before);
  });
});
describe('form observation', () => {
  it('resolves a relative action against the document base URL', () => {
    const doc = documentWith('<form action="/login" method="post"><input type="password" name="pass" /></form>');
    const form = observeForm(doc.querySelector('form') as Element, options());

    expect(form.actionUrl).toBe('https://shop.example.com/login');
    expect(form.actionHostname).toBe('shop.example.com');
    expect(form.method).toBe('post');
    expect(form.isThirdPartyAction).toBe(false);
    expect(form.isInsecureAction).toBe(false);
  });

  it('treats a form with no action as submitting to the page itself', () => {
    const doc = documentWith('<form><input type="email" name="email" /></form>');
    const form = observeForm(doc.querySelector('form') as Element, options());

    expect(form.actionUrl).toBe(PAGE);
    expect(form.actionHostname).toBe('shop.example.com');
    expect(form.method).toBe('get');
  });

  it('honours <base href> when resolving an action', () => {
    const doc = documentWith('<form action="submit"></form>');
    const base = doc.createElement('base');
    base.href = 'https://forms.example.net/collect/';
    doc.head.appendChild(base);
    Object.defineProperty(doc, 'baseURI', { value: 'https://forms.example.net/collect/', configurable: true });

    const form = observeForm(doc.querySelector('form') as Element, options());
    expect(form.actionUrl).toBe('https://forms.example.net/collect/submit');
    expect(form.isThirdPartyAction).toBe(true);
  });

  it('flags a third-party action and an insecure action separately', () => {
    const doc = documentWith(`
      <form action="https://collect.example.net/login" method="post"><input type="password" name="pass" /></form>
      <form action="http://shop.example.com/login" method="post"><input type="password" name="pass" /></form>
    `);
    const [thirdParty, insecure] = observeForms(doc, options());

    expect(thirdParty?.isThirdPartyAction).toBe(true);
    expect(thirdParty?.isInsecureAction).toBe(false);
    expect(insecure?.isThirdPartyAction).toBe(false);
    expect(insecure?.isInsecureAction).toBe(true);
  });

  it('records autocomplete verbatim, including the value that removes password-manager help', () => {
    const doc = documentWith(`
      <form action="/login">
        <input type="text" name="user" autocomplete="username" />
        <input type="password" name="old" autocomplete="off" />
        <input type="password" name="new" autocomplete="NEW-PASSWORD" />
        <input type="password" name="none" />
      </form>
    `);
    const form = observeForm(doc.querySelector('form') as Element, options());

    expect(form.inputs.map((input) => input.autocomplete)).toEqual(['username', 'off', 'new-password', null]);
    expect(form.inputs.map((input) => input.hasAutocomplete)).toEqual([true, true, true, false]);
    expect(form.autocompleteOffCount).toBe(1);
    expect(form.hasAutocompleteDisabled).toBe(true);
    expect(form.hasPasswordField).toBe(true);
    // Multiple password fields on one page: login and registration together.
    expect(countPasswordFields(doc)).toBe(3);
  });

  it('finds a hidden password field, which is how a credential gets collected invisibly', () => {
    const hiddenAttribute = documentWith(
      '<form action="/login"><input type="password" name="trap" hidden /></form>',
    );
    const inlineStyle = documentWith(
      '<form action="/login"><div style="display: none"><input type="password" name="trap" /></div></form>',
    );
    const visible = documentWith('<form action="/login"><input type="password" name="pass" /></form>');

    expect(observeForms(hiddenAttribute, options())[0]?.hasHiddenPasswordField).toBe(true);
    expect(observeForms(inlineStyle, options())[0]?.hasHiddenPasswordField).toBe(true);
    expect(observeForms(visible, options())[0]?.hasHiddenPasswordField).toBe(false);
  });

  it('detects a file input and a nested form', () => {
    const doc = documentWith(`
      <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="contract" />
      </form>
    `);
    const form = observeForm(doc.querySelector('form') as Element, options());
    expect(form.hasFileInput).toBe(true);

    // A nested `<form>` written in HTML is dropped by the parser (it is invalid markup), so the
    // only way one exists in a document is by script - which is exactly how a page would graft a
    // second, invisible form into a real one.
    const nestedDoc = documentWith('<form id="outer" action="/a"></form>');
    const outerForm = nestedDoc.querySelector('#outer') as HTMLFormElement;
    const wrapper = nestedDoc.createElement('div');
    const innerForm = nestedDoc.createElement('form');
    innerForm.setAttribute('action', '/b');
    wrapper.appendChild(innerForm);
    outerForm.appendChild(wrapper);

    const [outer, inner] = observeForms(nestedDoc, options());
    expect(outer?.isNested).toBe(false);
    expect(inner?.isNested).toBe(true);
    expect(inner?.actionUrl).toBe('https://shop.example.com/b');
  });

  it('reports the cross-origin frame flag only when the caller knows it is true', () => {
    const doc = documentWith('<form action="/login"><input type="password" name="pass" /></form>');

    expect(observeForms(doc, options())[0]?.inCrossOriginFrame).toBe(false);
    expect(observeForms(doc, options({ inCrossOriginFrame: true }))[0]?.inCrossOriginFrame).toBe(true);
  });

  it('returns nothing for a page with no forms, and counts no password fields', () => {
    const doc = documentWith('<main><p>No forms here.</p></main>');
    expect(observeForms(doc, options())).toEqual([]);
    expect(countPasswordFields(doc)).toBe(0);
  });
});