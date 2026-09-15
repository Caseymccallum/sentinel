#!/usr/bin/env node
/**
 * Local fixture server for the Playwright "money test" (Phase 1, Task 1.6).
 *
 * Sentinel is forbidden from making network calls of its own, so the money test needs pages served
 * from this machine. This module starts three servers, all bound to 127.0.0.1:
 *
 *   1. **HTTPS, page port** - the fixture pages in `tests/e2e/fixtures`, with the security headers
 *      each page is meant to stand for. The self-signed fixture certificate lives in
 *      `tests/fixtures/certs`; Chromium is launched with `--ignore-certificate-errors`, and every
 *      hostname is mapped to 127.0.0.1 by `HOST_RESOLVER_RULES`.
 *   2. **HTTPS, tracker port (8788)** - empty-bodied stub scripts for the well-known tracker hosts
 *      in `TRACKER_HOSTS`, so a fixture can load `https://www.google-analytics.com:8788/analytics.js`
 *      and have the request land here. The body is deliberately empty: the tracker signal is built
 *      from the request *origin*, never from the script's contents. This port also answers the
 *      cross-origin form action target used by `forms.html`.
 *   3. **HTTP, no headers** - the strong-negative page: plain HTTP, no security headers, three
 *      trackers and a password form posting over HTTP. It is the only way to exercise
 *      `connection.https` measuring zero (and therefore the score cap) and the insecure-action
 *      findings.
 *
 * A 404 for anything else, so a typo in a test URL is loud rather than silent.
 *
 * Usage:
 *   node scripts/e2e-server.mjs            # start and log the URLs
 *   import { startFixtureServers } from .../e2e-server.mjs   # from the Playwright test
 */

import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const repoRoot = resolve(here, '..');
const fixtureDir = join(repoRoot, 'tests', 'e2e', 'fixtures');
const certDir = join(repoRoot, 'tests', 'fixtures', 'certs');

export const HTTPS_PORT = Number(process.env.SENTINEL_E2E_HTTPS_PORT ?? 4173);
export const HTTP_PORT = Number(process.env.SENTINEL_E2E_HTTP_PORT ?? 4174);
/** Must match the `:8788` literals in `tests/e2e/fixtures/trackers.html` and `forms.html`. */
export const TRACKER_PORT = Number(process.env.SENTINEL_E2E_TRACKER_PORT ?? 8788);

export const SECURE_HOST = 'secure.test';
export const INSECURE_HOST = 'insecure.test';
export const CROSS_ORIGIN_HOST = 'other.test';

/** Hosts the fixture certificate is used for, and that tracker stubs are served for. */
export const TRACKER_HOSTS = Object.freeze([
  'www.google-analytics.com',
  'connect.facebook.net',
  'static.hotjar.com',
  'cdn.segment.com',
]);

/** Chromium arguments that keep every fixture hostname pointing at this machine. */
export const HOST_RESOLVER_RULES = Object.freeze(
  [SECURE_HOST, INSECURE_HOST, CROSS_ORIGIN_HOST, ...TRACKER_HOSTS]
    .map((host) => `MAP ${host} 127.0.0.1`)
    .join(','),
);

export const SECURE_PAGE_URL = `https://${SECURE_HOST}:${HTTPS_PORT}/clean.html`;
export const INSECURE_PAGE_URL = `http://${INSECURE_HOST}:${HTTP_PORT}/insecure.html`;
export const TRACKER_PAGE_URL = `https://${SECURE_HOST}:${HTTPS_PORT}/trackers.html`;
export const FORMS_PAGE_URL = `https://${SECURE_HOST}:${HTTPS_PORT}/forms.html`;
export const WEAK_PAGE_URL = `https://${SECURE_HOST}:${HTTPS_PORT}/weak.html`;
export const NO_HEADERS_PAGE_URL = `https://${SECURE_HOST}:${HTTPS_PORT}/headers-missing.html`;

const MIME = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
});
/**
 * Security headers per fixture page.
 *
 * These are the *inputs* of the headers signal, so each page represents one posture:
 *
 *   - `clean.html` is exemplary: every header Sentinel knows how to check, all of them strict.
 *   - `weak.html` sends a policy no reviewer would accept: `unsafe-inline` + `unsafe-eval`,
 *     `ALLOWALL` framing, `unsafe-url` referrers, `max-age=0` HSTS.
 *   - `trackers.html` and `forms.html` are honest but not perfect: they exist to exercise other
 *     signals, so they carry the security headers a real site would have.
 *   - `headers-missing.html` sends nothing at all.
 */
export const PAGE_HEADERS = Object.freeze({
  'clean.html': Object.freeze({
    'content-security-policy':
      "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'geolocation=(), camera=(), microphone=()',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  }),
  'weak.html': Object.freeze({
    'content-security-policy': "default-src * 'unsafe-inline' 'unsafe-eval'",
    'x-frame-options': 'ALLOWALL',
    'referrer-policy': 'unsafe-url',
    'permissions-policy': 'geolocation=*',
    'strict-transport-security': 'max-age=0',
  }),
  'headers-missing.html': Object.freeze({}),
  'trackers.html': Object.freeze({
    'content-security-policy':
      "default-src 'self'; script-src 'self' https://www.google-analytics.com:8788 https://connect.facebook.net:8788 https://static.hotjar.com:8788 https://cdn.segment.com:8788; object-src 'none'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'geolocation=()',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  }),
  'forms.html': Object.freeze({
    'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  }),
});

function hostnameOf(hostHeader) {
  if (!hostHeader) return '';
  const withoutPort = hostHeader.startsWith('[')
    ? hostHeader.slice(0, hostHeader.indexOf(']') + 1)
    : hostHeader.split(':')[0];
  return (withoutPort ?? '').toLowerCase();
}

function isTrackerHost(hostname) {
  return TRACKER_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`));
}

async function readFileOrNull(path) {
  try {
    return await readFile(path);
  } catch {
    return null;
  }
}

/** Serves one file from the fixture directory, with the headers that file is meant to carry. */
async function serveFixture(pathname, res, headers) {
  const name = pathname === '/' ? 'clean.html' : pathname.slice(1);
  // No path traversal: only a bare file name in the fixtures directory is ever opened.
  if (name.includes('/') || name.includes('\\') || name.includes('..')) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('404');
    return;
  }

  const body = await readFileOrNull(join(fixtureDir, name));
  if (body === null) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end(`404 ${name}`);
    return;
  }

  res.writeHead(200, {
    'content-type': MIME[extname(name).toLowerCase()] ?? 'application/octet-stream',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

/** Handles a request on the page servers (HTTPS and HTTP). */
export function handlePageRequest(req, res, options) {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? SECURE_HOST}`);
  void (async () => {
    try {
      const headers = options.securityHeaders ? (PAGE_HEADERS[url.pathname.slice(1)] ?? {}) : {};
      await serveFixture(url.pathname, res, headers);
    } catch (error) {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(`500 ${error instanceof Error ? error.message : String(error)}`);
    }
  })();
}

/**
 * Cookies the tracker stubs stand for (Phase 2, Task 2.6.6).
 *
 * The stubs do send these as `Set-Cookie` headers, but modern Chromium blocks third-party
 * cookie *storage* by default (the money test must not depend on a browser policy that keeps
 * moving), so the money test seeds the cookie store directly from this list with
 * `context.addCookies()`. What the test asserts is Sentinel's pipeline, not Chromium's
 * Set-Cookie policy: the page contacts these hosts, the hosts' cookies exist in the store, and
 * the only way they can appear in the popup is the full third-party path (tracker observer ->
 * cookie observer -> classifier -> TrustEngine -> popup).
 *
 * Lifetimes are chosen to exercise the persistence signal: `_ga` outlives two years
 * (COOKIES_LONG_PERSISTENCE), `_gid` lasts a day.
 */
export const TRACKER_COOKIE_SEEDS = Object.freeze([
  { name: '_ga', value: 'GA1.1.1000000000.1700000000', domain: '.google-analytics.com', maxAge: 63_072_000 },
  { name: '_gid', value: 'GA1.1.2000000000.1700000000', domain: '.google-analytics.com', maxAge: 86_400 },
  // NOTE: the fixture's Meta stub is served from `connect.facebook.net`, so the seed domain is
  // `facebook.net` — the observer queries the registrable domains the page actually contacted.
  { name: '_fbp', value: 'fb.1.1700000000.1001', domain: '.facebook.net', maxAge: 7_776_000 },
  { name: 'fr', value: '1AbCdEfGh', domain: '.facebook.net', maxAge: 7_776_000 },
  { name: '_hjSessionUser', value: 'hj-user', domain: '.hotjar.com', maxAge: 31_536_000 },
  { name: 'ajs_anonymous_id', value: 'segment-anon', domain: '.segment.com', maxAge: 31_536_000 },
]);

function cookieHeader(seed) {
  return `${seed.name}=${seed.value}; Path=/; Domain=${seed.domain}; Secure; SameSite=Lax; Max-Age=${seed.maxAge}`;
}

const TRACKER_COOKIES = Object.freeze(
  Object.fromEntries(
    Object.entries(
      TRACKER_COOKIE_SEEDS.reduce((byHost, seed) => {
        const host = seed.domain.replace(/^\./, '');
        (byHost[host] ??= []).push(cookieHeader(seed));
        return byHost;
      }, {}),
    ),
  ),
);

/**
 * Handles a request on the tracker port: an empty script for a known tracker host (planting its
 * documented cookies), or a 204 for the cross-origin form target. The script body is empty on
 * purpose - the signal is the origin.
 */
export function handleTrackerRequest(req, res) {
  const hostname = hostnameOf(req.headers.host);
  const url = new URL(req.url ?? '/', `http://${hostname}`);

  if (isTrackerHost(hostname)) {
    const cookies = TRACKER_COOKIES[hostname];
    res.writeHead(200, {
      'content-type': MIME['.js'],
      'cache-control': 'no-store',
      ...(cookies ? { 'set-cookie': cookies } : {}),
    });
    res.end('/* sentinel fixture tracker stub: intentionally empty */\n');
    return;
  }

  if (hostname === CROSS_ORIGIN_HOST && url.pathname === '/collect') {
    res.writeHead(204);
    res.end();
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end(`404 ${hostname}${url.pathname}`);
}
/**
 * Starts all three servers and resolves once each is listening.
 *
 * Resolves with a `stop()` that closes them, because a test suite that leaks a listening socket
 * hangs the run (and the next one's port bind).
 */
export async function startFixtureServers() {
  const key = await readFile(join(certDir, 'fixture-key.pem'));
  const cert = await readFile(join(certDir, 'fixture-cert.pem'));

  const httpsServer = createHttpsServer({ key, cert }, (req, res) =>
    handlePageRequest(req, res, { securityHeaders: true }),
  );
  const trackerServer = createHttpsServer({ key, cert }, handleTrackerRequest);
  const httpServer = createHttpServer((req, res) =>
    handlePageRequest(req, res, { securityHeaders: false }),
  );

  /**
   * Binds with patience: `--repeat-each` makes Playwright recycle workers, so a second
   * `beforeAll` can race the first worker's teardown for these fixed ports. An EADDRINUSE
   * from a dying predecessor is transient — the old server releases the port as its process
   * exits — so retry for up to ten seconds before giving up.
   */
  const listen = (server, port) =>
    new Promise((resolvePort, reject) => {
      const started = Date.now();
      const attempt = () => {
        server.once('error', (error) => {
          if (/** @type {NodeJS.ErrnoException} */ (error).code === 'EADDRINUSE' && Date.now() - started < 10_000) {
            setTimeout(attempt, 250);
            return;
          }
          reject(error);
        });
        server.listen(port, '127.0.0.1', () => resolvePort(undefined));
      };
      attempt();
    });

  await Promise.all([
    listen(httpsServer, HTTPS_PORT),
    listen(trackerServer, TRACKER_PORT),
    listen(httpServer, HTTP_PORT),
  ]);

  return {
    httpsPort: HTTPS_PORT,
    httpPort: HTTP_PORT,
    trackerPort: TRACKER_PORT,
    async stop() {
      await Promise.all(
        [httpsServer, trackerServer, httpServer].map(
          (server) => new Promise((resolveClose) => server.close(() => resolveClose(undefined))),
        ),
      );
    },
  };
}

/**
 * Running the file directly starts the servers and logs how to reach each page.
 *
 * `pathToFileURL` rather than string concatenation: on Windows an `argv[1]` such as
 * `C:\...\e2e-server.mjs` does not survive being pasted into a `file://` URL, and the check would
 * silently never match - the script would exit immediately after starting nothing.
 */
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  const servers = await startFixtureServers();
  console.log('sentinel fixture server running (127.0.0.1 only):');
  console.log(`  secure page    ${SECURE_PAGE_URL}`);
  console.log(`  tracker page   ${TRACKER_PAGE_URL}`);
  console.log(`  forms page     ${FORMS_PAGE_URL}`);
  console.log(`  weak headers   ${WEAK_PAGE_URL}`);
  console.log(`  no headers     ${NO_HEADERS_PAGE_URL}`);
  console.log(`  insecure page  ${INSECURE_PAGE_URL}`);
  console.log(`  tracker stubs  https://${TRACKER_HOSTS[0]}:${servers.trackerPort}/`);
  console.log('\nCtrl-C to stop.');
}