#!/usr/bin/env node
/**
 * check-local-only - keeps Sentinel's central promise mechanically true.
 *
 * Sentinel claims that nothing ever leaves the browser. A claim like that is worth nothing
 * unless something checks it, so this script scans three things and fails if any of them
 * looks like it could talk to a server:
 *
 *   1. every source file under `src/`, so a network primitive cannot be merged in;
 *   2. every built file under `.output/`, so a dependency cannot smuggle one in either;
 *   3. each built `manifest.json`, so permissions cannot quietly widen.
 *
 * A source line may opt out with a `sentinel-allow-local-only` marker, which lets
 * documentation and tests *mention* a primitive without tripping the scan.
 *
 * Usage: node scripts/check-local-only.mjs
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ALLOW_MARKER = 'sentinel-allow-local-only';

/** Extensions we treat as text worth scanning. */
const SCANNED_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.html',
  '.css',
  '.json',
  '.txt',
]);

/** Directory names never worth scanning, even inside a built extension. */
const SKIP_DIRECTORIES = new Set(['node_modules', '.git']);

/**
 * Network primitives. `pattern` is matched against raw file text; `why` is printed with
 * every hit so a failure explains itself rather than just pointing at an offset.
 */
const NETWORK_PRIMITIVES = [
  { name: 'fetch()', pattern: /\bfetch\s*\(/g, why: 'Sentinel never makes requests of its own.' },
  { name: 'XMLHttpRequest', pattern: /\bXMLHttpRequest\b/g, why: 'Sentinel never makes requests of its own.' },
  { name: 'WebSocket', pattern: /\bnew\s+WebSocket\b/g, why: 'No sockets, no remote control channel.' },
  { name: 'EventSource', pattern: /\bnew\s+EventSource\b/g, why: 'No server-pushed configuration.' },
  { name: 'sendBeacon()', pattern: /\bsendBeacon\s*\(/g, why: 'Telemetry by another name.' },
  { name: 'WebTransport', pattern: /\bnew\s+WebTransport\b/g, why: 'Sentinel never makes requests of its own.' },
  { name: 'RTCPeerConnection', pattern: /\bnew\s+RTCPeerConnection\b/g, why: 'No peer connections.' },
  { name: 'importScripts()', pattern: /\bimportScripts\s*\(/g, why: 'Remote code execution path.' },
  { name: 'remote dynamic import', pattern: /\bimport\s*\(\s*['"]https?:/g, why: 'Remote code execution path.' },
  { name: 'remote <script src>', pattern: /<script[^>]+src\s*=\s*["']https?:/gi, why: 'Remote code execution path.' },
  { name: 'navigator.onLine', pattern: /\bnavigator\.onLine\b/g, why: 'Nothing to report home, either way.' },
  { name: 'chrome.identity', pattern: /\b(?:chrome|browser)\.identity\b/g, why: 'No accounts, by design.' },
  {
    name: 'management control call',
    pattern: /\b(?:chrome|browser)\.management\.(?:setEnabled|uninstall|uninstallSelf)\b/g,
    why: 'D-010: the Extension Auditor lists other extensions, it never controls them.',
  },
  { name: 'externally_connectable', pattern: /externally_connectable/g, why: 'Only Sentinel may talk to Sentinel.' },
  { name: 'update_url', pattern: /\bupdate_url\b/g, why: 'Self-updating would phone home.' },
];

/** Permissions Sentinel is allowed to ask for, with the reason each one earns its place. */
const ALLOWED_PERMISSIONS = new Map([
  ['storage', 'Settings, history and session-scoped page observations.'],
  ['webRequest', 'Read response headers of requests the page already made. Observational only.'],
  [
    'cookies',
    'D-007: required by chrome.cookies.getAll() to enumerate cookies for the active tab. ' +
      'Justified because: (1) the Cookie Transparency module\'s entire function is reading cookies; ' +
      '(2) no cookie value leaves the browser - the observer keeps metadata only, never the value; ' +
      '(3) chrome.cookies.set() and chrome.cookies.remove() are only called in response to an ' +
      'explicit user action in the popup, never automatically.',
  ],
  [
    'management',
    'D-010: required by browser.management.getAll() to list the other installed extensions and ' +
      'the permissions they hold, for the Extension Auditor. Justified because: (1) the audit is ' +
      'read-only - Sentinel never calls setEnabled, uninstall or uninstallSelf, which this script ' +
      'enforces as a network-primitive-style rule; (2) the report is computed on demand from a ' +
      'popup action, never persisted, and never enters the page Trust Score; (3) Sentinel excludes ' +
      'itself from its own audit.',
  ],
  ['tabs', 'Know which tab a report belongs to.'],
  ['scripting', 'Inject the DOM collector on demand.'],
  ['activeTab', 'Act only on the tab the user invoked Sentinel from.'],
]);

/** Permissions that would break the promise outright if they ever appeared. */
const FORBIDDEN_PERMISSIONS = new Map([
  ['webRequestBlocking', 'Sentinel observes traffic; it never blocks, redirects or rewrites it.'],
  ['declarativeNetRequest', 'Blocking rules are not analysis.'],
  ['identity', 'No accounts, no sign-in, no profile.'],
  ['proxy', 'Sentinel must not sit between the user and the network.'],
  ['management', 'Other extensions are listed, never controlled (see ALLOWED_PERMISSIONS: D-010 moved listing here; control calls stay forbidden).'],
  ['debugger', 'Far more access than analysis needs.'],
  ['nativeMessaging', 'A native host is an escape hatch off the device.'],
  ['downloads', 'Sentinel reports; it does not fetch files.'],
]);

/** Host access Sentinel may declare: the pages it analyses, and nothing narrower or wider. */
const ALLOWED_HOST_PERMISSIONS = ['<all_urls>'];

/** Dev builds legitimately contain an HMR socket, so they are skipped by name. */
const DEV_OUTPUT_SUFFIX = '-dev';

function walk(directory) {
  const found = [];
  if (!existsSync(directory)) return found;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (SKIP_DIRECTORIES.has(entry.name)) continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...walk(full));
    else if (SCANNED_EXTENSIONS.has(extname(entry.name).toLowerCase())) found.push(full);
  }
  return found;
}

/** Source lines carrying a network primitive, each with the rule that fired. */
function scanFile(file) {
  const text = readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  const lines = text.split('\n');
  const hits = [];

  for (const rule of NETWORK_PRIMITIVES) {
    const pattern = new RegExp(rule.pattern.source, 'g');
    let match = pattern.exec(text);
    while (match !== null) {
      const lineNumber = text.slice(0, match.index).split('\n').length;
      const line = lines[lineNumber - 1] ?? '';
      // Documentation and tests may name a primitive; call sites may not.
      if (!line.includes(ALLOW_MARKER)) {
        hits.push({
          file: relative(ROOT, file).replace(/\\/g, '/'),
          lineNumber,
          snippet: line.trim().slice(0, 100),
          name: rule.name,
          why: rule.why,
        });
      }
      if (pattern.lastIndex === match.index) pattern.lastIndex += 1;
      match = pattern.exec(text);
    }
  }

  return hits;
}

/** Checks a built `manifest.json`: permissions and connectability, not file contents. */
function checkManifest(file) {
  const problems = [];
  const label = relative(ROOT, file).replace(/\\/g, '/');
  const add = (message) => problems.push(`${label}: ${message}`);

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    add(`is not valid JSON (${error instanceof Error ? error.message : String(error)}).`);
    return problems;
  }

  if (manifest.externally_connectable) {
    add('declares externally_connectable, which would let web pages talk to Sentinel.');
  }
  if (manifest.update_url) {
    add('declares update_url, which would poll a server for updates.');
  }

  const permissions = [...(manifest.permissions ?? []), ...(manifest.optional_permissions ?? [])];
  for (const permission of permissions) {
    if (ALLOWED_PERMISSIONS.has(permission)) continue;
    const reason = FORBIDDEN_PERMISSIONS.get(permission);
    add(
      reason
        ? `asks for "${permission}": ${reason}`
        : `asks for "${permission}", which is not on the allow-list in this script.`,
    );
  }

  const hosts = [...(manifest.host_permissions ?? []), ...(manifest.optional_host_permissions ?? [])];
  for (const host of hosts) {
    if (!ALLOWED_HOST_PERMISSIONS.includes(host)) add(`requests host access to "${host}".`);
  }

  const csp = manifest.content_security_policy?.extension_pages;
  if (typeof csp === 'string' && /https?:|unsafe-eval|unsafe-inline/.test(csp)) {
    add(`has a page CSP that allows remote or inline code ("${csp}").`);
  }

  return problems;
}

function main() {
  const failures = [];
  const notes = [];
  const report = (files, label) => {
    for (const file of files) {
      for (const hit of scanFile(file)) {
        failures.push(
          `  ${hit.file}:${hit.lineNumber}\n      ${hit.name} - ${hit.why}\n      ${hit.snippet}`,
        );
      }
    }
    if (files.length === 0) notes.push(`nothing to scan in ${label}.`);
  };

  const sourceFiles = walk(join(ROOT, 'src'));
  if (sourceFiles.length === 0) failures.push('  src/ contains no source files - is this the right project?');
  report(sourceFiles, 'src/');

  const outputDir = join(ROOT, '.output');
  const outputFiles = [];
  if (!existsSync(outputDir)) {
    notes.push('no .output/ directory yet; checking source only (run `npm run build` for the full check).');
  } else {
    for (const entry of readdirSync(outputDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      if (entry.name.endsWith(DEV_OUTPUT_SUFFIX)) {
        notes.push(`skipped .output/${entry.name}/ (dev build, which contains an HMR socket).`);
        continue;
      }
      outputFiles.push(...walk(join(outputDir, entry.name)));
    }
    report(outputFiles, '.output/');

    const manifests = outputFiles.filter((file) => file.endsWith('manifest.json'));
    if (manifests.length === 0) notes.push('no built manifest.json found; permissions were not checked.');
    for (const manifest of manifests) {
      failures.push(...checkManifest(manifest).map((problem) => `  ${problem}`));
    }
  }

  console.log('check-local-only - Sentinel promises that nothing leaves the browser.');
  console.log(`Scanned ${sourceFiles.length} source file(s) and ${outputFiles.length} built file(s).`);
  for (const note of notes) console.log(`  note  ${note}`);

  if (failures.length > 0) {
    console.log(`\nFAIL  ${failures.length} problem(s) found:\n`);
    for (const failure of failures) console.log(failure);
    console.log(
      '\nFix the call site, or - for prose and tests that only mention a primitive - add a' +
        ` "${ALLOW_MARKER}" marker to that line.`,
    );
    process.exitCode = 1;
    return;
  }

  console.log('\nOK  No network primitives, no widened permissions.');
}

main();


