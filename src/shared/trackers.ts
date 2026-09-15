/**
 * Local tracker classification.
 *
 * A curated, offline list of hosts whose business is measurement rather than content.
 * There is no remote blocklist fetch and no crowdsourced database: Sentinel must work
 * identically offline, in a fresh profile, with zero network requests. The list is
 * deliberately conservative - a host appears here only when its documented purpose is
 * analytics, advertising, session recording, device fingerprinting or error/behaviour
 * monitoring - so a match is a fact about the host, not a guess about the individual site.
 *
 * Matching is on DNS-label boundaries: `sub.doubleclick.net` matches `doubleclick.net`,
 * while `notdoubleclick.net` does not.
 *
 * Every entry carries `{ domain, name, category }`; the plain-language `description` a match
 * reports is the category's unless the entry overrides it. Writing one paragraph per domain
 * would be 150 near-identical strings, and the sentence a user needs is about *what kind of
 * host this is* ("advertising network that builds a profile of your browsing"), which is a
 * fact about the category rather than about the individual domain.
 */

export type TrackerCategory =
  | 'analytics'
  | 'advertising'
  | 'social'
  | 'session-replay'
  | 'fingerprinting'
  | 'monitoring';

export interface TrackerCategoryMeta {
  id: TrackerCategory;
  /** Short label for the popup, e.g. "Analytics". */
  label: string;
  /** One sentence, written for the user, describing what hosts in this category do. */
  description: string;
  /**
   * Optimisation and support tags usually serve a first-party purpose, so a match there is
   * reported with lower confidence than an ad network or an analytics pixel.
   */
  confidence: 'high' | 'medium';
}

/** Domains grouped by what the operator does with the data. */
export const TRACKER_CATEGORIES: readonly TrackerCategoryMeta[] = [
  {
    id: 'analytics',
    label: 'Analytics',
    description: 'Measures the pages and events you visit and reports them back to the vendor.',
    confidence: 'high',
  },
  {
    id: 'advertising',
    label: 'Advertising',
    description: 'Builds and bids on an advertising profile of your browsing across sites.',
    confidence: 'high',
  },
  {
    id: 'social',
    label: 'Social',
    description: 'Reports your activity to a social platform so it can attribute it to your account.',
    confidence: 'high',
  },
  {
    id: 'session-replay',
    label: 'Session recording',
    description: 'Records how you move, click and scroll through the page and can capture what you type.',
    confidence: 'high',
  },
  {
    id: 'fingerprinting',
    label: 'Fingerprinting',
    description: 'Combines device and browser traits into a stable identifier that survives clearing cookies.',
    confidence: 'high',
  },
  {
    id: 'monitoring',
    label: 'Monitoring and optimisation',
    description: 'Watches errors and behaviour, or runs experiments and support chat on the page.',
    confidence: 'medium',
  },
];

export interface TrackerEntry {
  /** Registrable domain, matched on DNS-label boundaries. */
  domain: string;
  /** Vendor name as a user would recognise it. */
  name: string;
  category: TrackerCategory;
  /** Optional per-domain override of the category description. */
  description?: string;
}

/** The knowledge base: ~150 hand-curated domains, each from vendor product documentation. */
export const TRACKER_ENTRIES: readonly TrackerEntry[] = [
  // ------------------------------------------------------------------- analytics (32)
  { domain: 'google-analytics.com', name: 'Google Analytics', category: 'analytics' },
  { domain: 'analytics.google.com', name: 'Google Analytics', category: 'analytics' },
  { domain: 'googletagmanager.com', name: 'Google Tag Manager', category: 'analytics' },
  { domain: 'scorecardresearch.com', name: 'Comscore ScorecardResearch', category: 'analytics' },
  { domain: 'quantserve.com', name: 'Quantcast Measure', category: 'analytics' },
  { domain: 'quantcast.com', name: 'Quantcast', category: 'analytics' },
  { domain: 'comscore.com', name: 'Comscore', category: 'analytics' },
  { domain: 'nielsen.com', name: 'Nielsen', category: 'analytics' },
  { domain: 'matomo.cloud', name: 'Matomo Cloud', category: 'analytics' },
  { domain: 'statcounter.com', name: 'StatCounter', category: 'analytics' },
  { domain: 'histats.com', name: 'Histats', category: 'analytics' },
  { domain: 'chartbeat.com', name: 'Chartbeat', category: 'analytics' },
  { domain: 'chartbeat.net', name: 'Chartbeat', category: 'analytics' },
  { domain: 'parsely.com', name: 'Parse.ly', category: 'analytics' },
  { domain: 'segment.io', name: 'Segment', category: 'analytics' },
  { domain: 'segment.com', name: 'Segment', category: 'analytics' },
  { domain: 'mixpanel.com', name: 'Mixpanel', category: 'analytics' },
  { domain: 'amplitude.com', name: 'Amplitude', category: 'analytics' },
  { domain: 'heap.io', name: 'Heap', category: 'analytics' },
  { domain: 'heapanalytics.com', name: 'Heap', category: 'analytics' },
  { domain: 'kissmetrics.com', name: 'Kissmetrics', category: 'analytics' },
  { domain: 'crazyegg.com', name: 'Crazy Egg', category: 'analytics' },
  { domain: 'clicky.com', name: 'Clicky', category: 'analytics' },
  { domain: 'mousestats.com', name: 'MouseStats', category: 'analytics' },
  { domain: 'mc.yandex.ru', name: 'Yandex Metrica', category: 'analytics' },
  { domain: 'metrika.yandex.ru', name: 'Yandex Metrica', category: 'analytics' },
  { domain: 'cnzz.com', name: 'CNZZ (Umeng)', category: 'analytics' },
  {
    domain: 'clarity.ms',
    name: 'Microsoft Clarity',
    category: 'analytics',
    description: 'Builds heatmaps and recordings of real visits to show site owners how the page was used.',
  },
  {
    domain: 'newrelic.com',
    name: 'New Relic Browser',
    category: 'analytics',
    description: 'Collects runtime performance and error data from the page as it loads.',
  },
  {
    domain: 'nr-data.net',
    name: 'New Relic Browser',
    category: 'analytics',
    description: 'Collects runtime performance and error data from the page as it loads.',
  },
  {
    domain: 'bugsnag.com',
    name: 'Bugsnag',
    category: 'analytics',
    description: 'Captures JavaScript errors and stack traces from real visitors.',
  },
  {
    domain: 'raygun.io',
    name: 'Raygun',
    category: 'analytics',
    description: 'Captures JavaScript errors and stack traces from real visitors.',
  },
  // ---------------------------------------------------------------- advertising (62)
  {
    domain: 'doubleclick.net',
    name: 'Google DoubleClick',
    category: 'advertising',
    description: "Google's advertising exchange: matches the pages you visit to bids from ad buyers.",
  },
  { domain: 'googleadservices.com', name: 'Google Ads', category: 'advertising' },
  { domain: 'googlesyndication.com', name: 'Google AdSense', category: 'advertising' },
  { domain: 'adservice.google.com', name: 'Google Ads', category: 'advertising' },
  { domain: 'adsrvr.org', name: 'The Trade Desk', category: 'advertising' },
  { domain: 'adnxs.com', name: 'Xandr (AppNexus)', category: 'advertising' },
  { domain: 'appnexus.com', name: 'Xandr (AppNexus)', category: 'advertising' },
  { domain: 'criteo.com', name: 'Criteo', category: 'advertising' },
  { domain: 'criteo.net', name: 'Criteo', category: 'advertising' },
  { domain: 'taboola.com', name: 'Taboola', category: 'advertising' },
  { domain: 'outbrain.com', name: 'Outbrain', category: 'advertising' },
  { domain: 'pubmatic.com', name: 'PubMatic', category: 'advertising' },
  { domain: 'rubiconproject.com', name: 'Magnite (Rubicon)', category: 'advertising' },
  { domain: 'magnite.com', name: 'Magnite', category: 'advertising' },
  { domain: 'openx.net', name: 'OpenX', category: 'advertising' },
  { domain: 'casalemedia.com', name: 'Index Exchange', category: 'advertising' },
  { domain: 'smartadserver.com', name: 'Equativ (Smart)', category: 'advertising' },
  { domain: 'adsafeprotected.com', name: 'Integral Ad Science', category: 'advertising' },
  { domain: 'moatads.com', name: 'Oracle Moat', category: 'advertising' },
  { domain: 'doubleverify.com', name: 'DoubleVerify', category: 'advertising' },
  { domain: 'iasds01.com', name: 'Integral Ad Science', category: 'advertising' },
  { domain: 'teads.tv', name: 'Teads', category: 'advertising' },
  { domain: 'sharethrough.com', name: 'Sharethrough', category: 'advertising' },
  { domain: 'yieldmo.com', name: 'Yieldmo', category: 'advertising' },
  { domain: 'amazon-adsystem.com', name: 'Amazon Advertising', category: 'advertising' },
  { domain: 'media.net', name: 'Media.net', category: 'advertising' },
  { domain: 'bidswitch.net', name: 'BidSwitch', category: 'advertising' },
  { domain: 'turn.com', name: 'Amobee (Turn)', category: 'advertising' },
  { domain: 'mathtag.com', name: 'MediaMath', category: 'advertising' },
  { domain: 'simpli.fi', name: 'Simpli.fi', category: 'advertising' },
  { domain: 'tapad.com', name: 'Tapad', category: 'advertising' },
  { domain: 'exelator.com', name: 'Epsilon (Exelate)', category: 'advertising' },
  { domain: 'bluekai.com', name: 'Oracle BlueKai', category: 'advertising' },
  { domain: 'demdex.net', name: 'Adobe Audience Manager', category: 'advertising' },
  { domain: 'omtrdc.net', name: 'Adobe Experience Cloud', category: 'advertising' },
  { domain: '2o7.net', name: 'Adobe Analytics', category: 'advertising' },
  { domain: 'everesttech.net', name: 'Adobe Advertising Cloud', category: 'advertising' },
  { domain: 'adobedtm.com', name: 'Adobe Dynamic Tag Manager', category: 'advertising' },
  {
    domain: 'liadm.com',
    name: 'LiveIntent',
    category: 'advertising',
    description: 'Links the email address you used to sign up to later ad impressions across sites.',
  },
  { domain: 'agkn.com', name: 'Neustar (Aggregate Knowledge)', category: 'advertising' },
  { domain: 'rlcdn.com', name: 'LiveRamp', category: 'advertising' },
  { domain: 'crwdcntrl.net', name: 'Lotame', category: 'advertising' },
  { domain: 'advertising.com', name: 'Yahoo Advertising', category: 'advertising' },
  { domain: 'indexww.com', name: 'Index Exchange', category: 'advertising' },
  { domain: 'gumgum.com', name: 'GumGum', category: 'advertising' },
  { domain: 'spotxchange.com', name: 'SpotX (Magnite)', category: 'advertising' },
  { domain: 'adform.net', name: 'Adform', category: 'advertising' },
  { domain: 'yieldlab.net', name: 'Yieldlab', category: 'advertising' },
  { domain: '3lift.com', name: 'TripleLift', category: 'advertising' },
  { domain: 'sitescout.com', name: 'SiteScout (Centro)', category: 'advertising' },
  { domain: 'zemanta.com', name: 'Zemanta', category: 'advertising' },
  { domain: 'adjust.com', name: 'Adjust', category: 'advertising' },
  { domain: 'branch.io', name: 'Branch', category: 'advertising' },
  { domain: 'kochava.com', name: 'Kochava', category: 'advertising' },
  { domain: 'sizmek.com', name: 'Sizmek (Amazon)', category: 'advertising' },
  { domain: 'flashtalking.com', name: 'Flashtalking', category: 'advertising' },
  { domain: 'tremorhub.com', name: 'Tremor (Magnite)', category: 'advertising' },
  // ---------------------------------------------------------------------- social (15)
  {
    domain: 'connect.facebook.net',
    name: 'Meta Pixel',
    category: 'social',
    description: 'Reports the pages and purchases you make to Meta so ads can be attributed to them.',
  },
  {
    domain: 'pixel.facebook.com',
    name: 'Meta Pixel',
    category: 'social',
    description: 'Reports the pages and purchases you make to Meta so ads can be attributed to them.',
  },
  { domain: 'static.ads-twitter.com', name: 'X (Twitter) Ads', category: 'social' },
  { domain: 'platform.twitter.com', name: 'X (Twitter) Embeds', category: 'social' },
  { domain: 'analytics.twitter.com', name: 'X (Twitter) Analytics', category: 'social' },
  { domain: 'ads.linkedin.com', name: 'LinkedIn Ads', category: 'social' },
  {
    domain: 'px.ads.linkedin.com',
    name: 'LinkedIn Insight Tag',
    category: 'social',
    description: 'Reports your visit to LinkedIn, which can match it to your account there.',
  },
  { domain: 'snap.licdn.com', name: 'LinkedIn', category: 'social' },
  { domain: 'sc-static.net', name: 'Snapchat Ads', category: 'social' },
  { domain: 'tr.snapchat.com', name: 'Snapchat Pixel', category: 'social' },
  { domain: 'ct.pinterest.com', name: 'Pinterest Tag', category: 'social' },
  { domain: 'analytics.tiktok.com', name: 'TikTok Pixel', category: 'social' },
  { domain: 'business-api.tiktok.com', name: 'TikTok Events API', category: 'social' },
  { domain: 'vk.com', name: 'VKontakte', category: 'social' },
  { domain: 'top-fwz1.mail.ru', name: 'VK (Mail.ru) Ads', category: 'social' },
  // -------------------------------------------------------------- session-replay (10)
  {
    domain: 'hotjar.com',
    name: 'Hotjar',
    category: 'session-replay',
    description: 'Records your session as heatmaps and replays, including clicks and scroll position.',
  },
  {
    domain: 'hotjar.io',
    name: 'Hotjar',
    category: 'session-replay',
    description: 'Records your session as heatmaps and replays, including clicks and scroll position.',
  },
  {
    domain: 'fullstory.com',
    name: 'FullStory',
    category: 'session-replay',
    description: 'Records a replayable copy of your session on the page.',
  },
  { domain: 'smartlook.com', name: 'Smartlook', category: 'session-replay' },
  { domain: 'mouseflow.com', name: 'Mouseflow', category: 'session-replay' },
  { domain: 'luckyorange.com', name: 'Lucky Orange', category: 'session-replay' },
  { domain: 'inspectlet.com', name: 'Inspectlet', category: 'session-replay' },
  { domain: 'logrocket.com', name: 'LogRocket', category: 'session-replay' },
  { domain: 'logrocket.io', name: 'LogRocket', category: 'session-replay' },
  { domain: 'sessioncam.com', name: 'SessionCam', category: 'session-replay' },
  // -------------------------------------------------------------- fingerprinting (13)
  { domain: 'fpjs.io', name: 'Fingerprint', category: 'fingerprinting' },
  { domain: 'fpapi.io', name: 'Fingerprint', category: 'fingerprinting' },
  { domain: 'fingerprint.com', name: 'Fingerprint', category: 'fingerprinting' },
  { domain: 'fingerprintjs.com', name: 'FingerprintJS', category: 'fingerprinting' },
  { domain: 'deviceatlas.com', name: 'DeviceAtlas', category: 'fingerprinting' },
  { domain: 'bluecava.com', name: 'BlueCava', category: 'fingerprinting' },
  { domain: 'iovation.com', name: 'Iovation (TransUnion)', category: 'fingerprinting' },
  { domain: 'threatmetrix.com', name: 'ThreatMetrix (LexisNexis)', category: 'fingerprinting' },
  { domain: 'sift.com', name: 'Sift', category: 'fingerprinting' },
  { domain: 'siftscience.com', name: 'Sift Science', category: 'fingerprinting' },
  { domain: 'perimeterx.net', name: 'HUMAN (PerimeterX)', category: 'fingerprinting' },
  { domain: 'px-cdn.net', name: 'HUMAN (PerimeterX)', category: 'fingerprinting' },
  { domain: 'datadome.co', name: 'DataDome', category: 'fingerprinting' },
  // ------------------------------------------------------------------ monitoring (27)
  { domain: 'optimizely.com', name: 'Optimizely', category: 'monitoring' },
  { domain: 'vwo.com', name: 'VWO', category: 'monitoring' },
  { domain: 'visualwebsiteoptimizer.com', name: 'VWO', category: 'monitoring' },
  { domain: 'abtasty.com', name: 'AB Tasty', category: 'monitoring' },
  { domain: 'dynamicyield.com', name: 'Dynamic Yield', category: 'monitoring' },
  { domain: 'monetate.net', name: 'Monetate', category: 'monitoring' },
  { domain: 'liveperson.net', name: 'LivePerson', category: 'monitoring' },
  { domain: 'livechatinc.com', name: 'LiveChat', category: 'monitoring' },
  { domain: 'intercom.io', name: 'Intercom', category: 'monitoring' },
  { domain: 'intercomcdn.com', name: 'Intercom', category: 'monitoring' },
  { domain: 'zdassets.com', name: 'Zendesk', category: 'monitoring' },
  { domain: 'drift.com', name: 'Drift', category: 'monitoring' },
  { domain: 'hs-analytics.net', name: 'HubSpot', category: 'monitoring' },
  { domain: 'hs-scripts.com', name: 'HubSpot', category: 'monitoring' },
  { domain: 'hsforms.net', name: 'HubSpot', category: 'monitoring' },
  { domain: 'munchkin.marketo.net', name: 'Marketo', category: 'monitoring' },
  { domain: 'pardot.com', name: 'Pardot (Salesforce)', category: 'monitoring' },
  { domain: 'olark.com', name: 'Olark', category: 'monitoring' },
  { domain: 'tawk.to', name: 'Tawk.to', category: 'monitoring' },
  { domain: 'crisp.chat', name: 'Crisp', category: 'monitoring' },
  // --- Error reporting: a different shape of monitoring, so it gets its own sentence ---
  {
    domain: 'sentry.io',
    name: 'Sentry',
    category: 'monitoring',
    description: 'Captures JavaScript errors, stack traces and performance data from real visitors.',
  },
  {
    domain: 'sentry-cdn.com',
    name: 'Sentry',
    category: 'monitoring',
    description: 'Captures JavaScript errors, stack traces and performance data from real visitors.',
  },
  { domain: 'rollbar.com', name: 'Rollbar', category: 'monitoring' },
  { domain: 'trackjs.com', name: 'TrackJS', category: 'monitoring' },
  { domain: 'datadoghq-browser-agent.com', name: 'Datadog RUM', category: 'monitoring' },
  { domain: 'loggly.com', name: 'Loggly', category: 'monitoring' },
  { domain: 'splunkcloud.com', name: 'Splunk Observability', category: 'monitoring' },
];

export interface TrackerMatch {
  /** The hostname Sentinel recognised, e.g. `www.google-analytics.com`. */
  hostname: string;
  /** The list entry that matched, e.g. `google-analytics.com`. */
  matchedDomain: string;
  /** Vendor name, e.g. "Google Analytics". */
  name: string;
  category: TrackerCategory;
  /** Human label for the category, e.g. "Analytics". */
  categoryLabel: string;
  confidence: 'high' | 'medium';
  /** One sentence describing what this host does with the data. */
  description: string;
}

/** Flattened index: domain -> entry. Built once at module load. */
const ENTRY_INDEX = new Map<string, TrackerEntry>();
for (const entry of TRACKER_ENTRIES) ENTRY_INDEX.set(entry.domain, entry);

const CATEGORY_META = new Map<string, TrackerCategoryMeta>(
  TRACKER_CATEGORIES.map((meta) => [meta.id, meta]),
);

export const TRACKER_DOMAIN_COUNT = ENTRY_INDEX.size;

/** Every domain in the knowledge base, sorted. Used by tests and the options page. */
export function trackerDomains(): string[] {
  return TRACKER_ENTRIES.map((entry) => entry.domain).sort();
}

export function trackerCategoryMeta(category: TrackerCategory): TrackerCategoryMeta {
  const meta = CATEGORY_META.get(category);
  if (!meta) throw new Error(`Unknown tracker category "${category}"`);
  return meta;
}

function toMatch(host: string, entry: TrackerEntry): TrackerMatch {
  const meta = trackerCategoryMeta(entry.category);
  return {
    hostname: host,
    matchedDomain: entry.domain,
    name: entry.name,
    category: entry.category,
    categoryLabel: meta.label,
    confidence: meta.confidence,
    description: entry.description ?? meta.description,
  };
}

/**
 * Returns the tracker match for a hostname, or `null` when the host is not on the list.
 *
 * A trailing dot (the fully-qualified form) is stripped, then the host is walked label by
 * label, so `sub.doubleclick.net` matches `doubleclick.net` while `notdoubleclick.net` does
 * not: the comparison is always made on a dot boundary.
 */
export function classifyTracker(hostname: string): TrackerMatch | null {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (host === '') return null;

  const exact = ENTRY_INDEX.get(host);
  if (exact) return toMatch(host, exact);

  let candidate = host;
  while (candidate.includes('.')) {
    candidate = candidate.slice(candidate.indexOf('.') + 1);
    const entry = ENTRY_INDEX.get(candidate);
    if (entry) return toMatch(host, entry);
  }
  return null;
}

/** Category of a hostname, for callers that only need the bucket. */
export function trackerCategoryOf(hostname: string): TrackerCategory | null {
  return classifyTracker(hostname)?.category ?? null;
}