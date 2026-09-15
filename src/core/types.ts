/**
 * Core data contracts for Sentinel's scoring engine.
 *
 * Everything in here is plain, structured-clone-safe data: these objects travel
 * between the background service worker, the popup and `chrome.storage.session`,
 * so no classes, functions or DOM references are allowed.
 */

/** Sentinel ships five modules; each one can be enabled or disabled on its own. */
export type ModuleId =
  | 'trust-score'
  | 'cookie-transparency'
  | 'change-monitor'
  | 'extension-auditor'
  | 'header-dashboard';

/** `active` modules contribute findings today; `planned` ones are toggleable placeholders. */
export type ModuleState = 'active' | 'planned';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** How sure the analyser is about a finding. `unavailable` = could not be measured. */
export type Confidence = 'unavailable' | 'low' | 'medium' | 'high';

export type Grade =
  | 'A+'
  | 'A'
  | 'A-'
  | 'B+'
  | 'B'
  | 'B-'
  | 'C+'
  | 'C'
  | 'C-'
  | 'D+'
  | 'D'
  | 'D-'
  | 'F';

/** A single labelled fact shown in the "technical detail" disclosure. */
export interface Evidence {
  label: string;
  value: string;
}

/**
 * One measurement produced by a signal analyser.
 *
 * `measured` is expressed as a 0-100 *quality* value (100 = nothing wrong) so that
 * every analyser speaks the same language and `ScoringModel` alone decides how many
 * points a problem is worth.
 */
export interface SignalAssessment {
  /** Stable, namespaced id matching a key in `SCORING_MODEL`, e.g. `connection.https`. */
  signalId: string;
  /** Short human title, e.g. "Encrypted connection". */
  title: string;
  /** 0-100 quality, or `null` when the signal could not be measured at all. */
  measured: number | null;
  confidence: Confidence;
  /** One sentence of technical detail. */
  detail: string;
  evidence: Evidence[];
  /** Plain-language advice, when there is something the site owner could fix. */
  remediation?: string;
}

/** A `SignalAssessment` after the engine has attached scoring metadata. */
export interface Finding extends SignalAssessment {
  categoryId: string;
  moduleId: ModuleId;
  severity: Severity;
  /** Points this signal can remove from its category (from the scoring model). */
  maxImpact: number;
  /** Points actually removed; `0` when `measured === null`. */
  impact: number;
}

export interface CategoryScore {
  categoryId: string;
  moduleId: ModuleId;
  label: string;
  description: string;
  /** Weight declared by the scoring model, 0-1. */
  weight: number;
  /** Weight after redistribution across categories that could be measured, 0-1. */
  effectiveWeight: number;
  /** 0-100, or `null` when no signal in the category could be measured. */
  score: number | null;
  status: Severity;
  findings: Finding[];
}

/**
 * A hard ceiling on the composite score, triggered by one signal measuring its worst value.
 *
 * Weights average, so a single catastrophic fact can be outvoted by everything else looking
 * fine. A cap says the opposite: this fact invalidates the rest of the report, so the number
 * is not allowed above a ceiling. Caps are declared in the scoring model (data), applied in
 * `ScoringModel.score()` (arithmetic) and reported back to the UI as `cappedBy`, so the user
 * always sees that a ceiling was applied and why.
 */
export interface ScoreCapDefinition {
  /** Only `zero` is supported: `measured === 0`, the worst possible value for the signal. */
  when: 'zero';
  /** Ceiling applied to the composite score, 0-100. */
  cap: number;
  /** One sentence shown next to the score, so the cap is never a silent adjustment. */
  reason: string;
}

/** The cap that actually lowered a score, with the signal that triggered it. */
export interface AppliedScoreCap {
  signalId: string;
  title: string;
  cap: number;
  reason: string;
}

export interface TrustScore {
  /** 0-100, rounded, after any hard cap. */
  value: number;
  grade: Grade;
  categories: CategoryScore[];
  modelVersion: string;
  /** True when at least one category could not be fully measured. */
  partial: boolean;
  /** Share of the model's total weight that produced a real measurement, 0-1. */
  coverage: number;
  /** Present only when a hard cap lowered the raw weighted total (see `ScoreCapDefinition`). */
  cappedBy?: AppliedScoreCap;
}

/** Certificate facts derived locally from the DER bytes the browser hands us. */
export interface CertificateFacts {
  subjectCN: string | null;
  issuerCN: string | null;
  issuerO: string | null;
  issuerC: string | null;
  serialNumber: string | null;
  validFrom: string | null;
  validTo: string | null;
  /** Negative when already expired. */
  daysUntilExpiry: number | null;
  isExpired: boolean;
  isSelfSigned: boolean;
  signatureAlgorithm: string | null;
  /** `weak` for MD5/SHA-1 based signatures, `legacy` for SHA-1 keys, `modern` otherwise. */
  signatureStrength: 'weak' | 'legacy' | 'modern' | null;
  publicKeyAlgorithm: string | null;
  publicKeySizeBits: number | null;
  sha256Fingerprint: string | null;
}

/** Everything the UI needs to describe *what Sentinel actually looked at*. */
export interface ObservationSummary {
  /** False when Sentinel did not observe the page load (e.g. it was installed after). */
  observed: boolean;
  scheme: 'http' | 'https' | 'other';
  statusCode: number | null;
  statusLine: string | null;
  serverIp: string | null;
  fromCache: boolean;
  /** TLS facts, or `null` when the browser did not expose any. */
  tls: {
    state: 'secure' | 'insecure' | 'broken' | 'unknown';
    /** Real negotiated protocol when the browser exposes it, else `null`. */
    protocol: string | null;
    source: 'event-security-info' | 'get-security-info' | 'none';
    certificate: CertificateFacts | null;
  } | null;
  headerCount: number;
  requestCount: number;
  thirdPartyHostCount: number;
  trackerCount: number;
  domReportAvailable: boolean;
  /**
   * True when the page's own resource timings were collected. `false` means the content script
   * had not answered yet, so "this page contacted nobody" is not yet a fact - the popup shows
   * the tracker checks as still running rather than as clean.
   */
  resourcesCollected: boolean;
  frameCount: number;
  /** Human-readable notes about gaps in the observation. */
  notes: string[];
}

/**
 * Cookie contracts (Phase 2).
 *
 * A `CookieRecord` is the *metadata only* shape the cookie observer produces.
 *
 * SAFETY CONTRACT (D-007): a cookie's `value` is never read, never stored, never
 * transmitted. The observer replaces it with `valueLength` before anything else sees the
 * record, and `src/background/cookie-observer.test.ts` proves with a canary value that the
 * secret appears nowhere in the output. Every type below is metadata.
 */

export type CookieCategory = 'essential' | 'analytics' | 'advertising' | 'social' | 'preference' | 'unknown';

/** What the cookie is *for*, as distinct from which bucket the classifier puts it in. */
export type CookiePurpose =
  | 'tracking'
  | 'session'
  | 'security'
  | 'personalization'
  | 'consent'
  | 'ab-testing'
  | 'unknown';

/**
 * Whether deleting the cookie is safe, phrased for the delete button.
 *
 * Conservative by design: only cookies the knowledge base *explicitly* knows are tracking
 * cookies are ever `'yes'`. Anything else is `'no'` (deleting breaks something), `'will-log-out'`
 * (deleting is harmless but ends the session) or `'unknown'` (we do not know, so we do not say yes).
 */
export type CookieSafeToDelete = 'yes' | 'no' | 'will-log-out' | 'unknown';

export type CookieSameSite = 'no_restriction' | 'lax' | 'strict' | 'unspecified';

/** Raw cookie metadata as the observer reports it. Never contains the cookie's value. */
export interface CookieRecord {
  name: string;
  domain: string;
  hostOnly: boolean;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: CookieSameSite;
  /** True for a session cookie (no expiry); `false` for a persistent one. */
  session: boolean;
  /** Unix seconds, present only when `session` is `false`. */
  expirationDate?: number;
  storeId: string;
  /** Character count of the cookie's value. The value itself is never kept (D-007). */
  valueLength: number;
  /** Computed: the cookie's domain belongs to the page's registrable domain. */
  firstParty: boolean;
  /**
   * The page-observed origin (tracker observer output) the cookie was enumerated for, when it
   * came from the third-party query. Third-party cookies set on origins the page contacted are
   * the reason this field exists: it is how a `_fbp` set by `connect.facebook.net` shows up in
   * the report for a page that never mentions Facebook in its own URL.
   */
  observedOrigin?: string;
}

/** A cookie after classification against the knowledge base. Still metadata only. */
export interface ClassifiedCookie extends CookieRecord {
  known: boolean;
  category: CookieCategory;
  /** Plain-language description, from the knowledge base or the generic inference rules. */
  description: string;
  purpose: CookiePurpose;
  safeToDelete: CookieSafeToDelete;
  /** Who set it: a user-facing vendor name (`Meta`, `Google Analytics`) or the cookie's own domain. */
  setBy: string;
  /** Stable id for the popup's rows and delete buttons: `storeId|domain|path|name`. */
  id: string;
}

/** Category counts and aggregates the TrustEngine and the popup summary header read. */
export interface CookieSummary {
  total: number;
  essential: number;
  analytics: number;
  advertising: number;
  social: number;
  unknown: number;
  thirdPartyCount: number;
  /** Persistent cookies (`session === false`). */
  persistentCount: number;
  /** Longest remaining lifetime in whole days, `0` when every cookie is a session cookie. */
  longestExpirationDays: number;
  /** Name of the longest-lasting cookie, `null` when none expires. */
  longestExpirationName: string | null;
}

/** The cookie half of a `ScanResult`: classified cookies plus their summary. */
export interface CookieReport {
  /** True once the observer actually enumerated cookies for this tab. */
  collected: boolean;
  cookies: ClassifiedCookie[];
  summary: CookieSummary;
}

/**
 * The cookie verdicts the brief names. They are outcome labels the cookie analyser maps its
 * measurements onto (one measured value per signal can only express one verdict), and the
 * explanation and popup use the same vocabulary.
 */
export type CookieVerdict =
  | 'COOKIES_TRACKING_HEAVY'
  | 'COOKIES_TRACKING_PRESENT'
  | 'COOKIES_NONE_OR_ESSENTIAL'
  | 'COOKIES_THIRD_PARTY_PRESENT'
  | 'COOKIES_LONG_PERSISTENCE';

export interface ModuleRunStatus {
}

export interface ModuleRunStatus {
  id: ModuleId;
  enabled: boolean;
  state: ModuleState;
  ran: boolean;
  error?: string;
}

/**
 * Change Monitor contracts (Phase 3, D-008).
 *
 * A `ProfileChange` is one plain-language difference between two consecutive recorded scans of
 * the same registrable domain. These findings are *informational and weightless*: they never
 * enter the Trust Score or its categories (see D-008) — they carry severity only for colour and
 * ordering in the popup's Changes panel.
 */
export type ProfileChangeKind =
  | 'score'
  | 'trackers'
  | 'third-party'
  | 'headers'
  | 'signals'
  | 'certificate';

export interface ProfileChange {
  kind: ProfileChangeKind;
  /** One plain-language sentence, safe to show the user as-is. */
  detail: string;
  severity: Severity;
  /** True when something got worse since the previous scan. */
  worsened: boolean;
}

/**
 * The per-domain history line the popup's Changes panel shows (D-008). Attached by the
 * background alongside `changes` when a scan is recorded; metadata only, keyed by registrable
 * domain — never paths, queries or page titles.
 */
export interface ProfileHistorySummary {
  domain: string;
  scanCount: number;
  lastScore: number | null;
  averageScore: number | null;
  /** Relative time of the previous visit, e.g. "2 hours ago". */
  lastSeenLabel: string;
}

/**
 * Header Dashboard contracts (Phase 4, D-009).
 *
 * Informational and weightless: the trust-score module already *scores* the security-relevant
 * response headers (the `headers` category); the dashboard's job is *transparency* — every
 * header the site sent, next to the value good practice recommends. Nothing here touches the
 * Trust Score, and a recommended header is only reported absent when the response was
 * actually observed (D-006: "missing" is never allowed to mean "clean" — or "guilty").
 */
export interface HeaderDashboardRow {
  name: string;
  /** Display name: the knowledge base's label for recommended headers, else the raw name. */
  label: string;
  /** The value the site sent; `''` for a recommended header that was absent. */
  value: string;
  present: boolean;
  /** True for the security headers Sentinel knows recommended practice for. */
  recommended: boolean;
  /** Plain-language recommended practice; set for recommended headers only. */
  guidance: string | null;
}

export interface HeaderDashboardReport {
  /** False when the page load was never observed; the UI must say so, not show gaps as guilt. */
  available: boolean;
  /** How many distinct response headers were observed (0 when unavailable). */
  observedCount: number;
  /** Recommended headers first (present or absent, in knowledge-base order), then the rest. */
  rows: HeaderDashboardRow[];
}

/**
 * Extension Auditor contracts (Phase 4, D-010).
 *
 * Informational, browser-scoped and weightless: the audit reviews *other installed
 * extensions* for over-broad permissions. It is not part of any page scan, it never enters
 * the Trust Score, and the result is computed on demand and never persisted.
 */
export interface PermissionFinding {
  /** The permission string as the extension declared it, or `host-access`. */
  name: string;
  /** Human label from the knowledge base, or the raw name when unknown. */
  label: string;
  severity: Severity;
  /** What the permission would let an extension do, in plain language. */
  why: string;
}

/** How much of the web an extension has been granted access to. */
export type HostAccess = 'none' | 'site-specific' | 'broad';

export interface ExtensionAuditEntry {
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  hostAccess: HostAccess;
  /** Worst severity across the findings; drives ordering and colour. */
  risk: Severity;
  /** Notable permissions plus host access, worst first. */
  findings: PermissionFinding[];
}

export interface ExtensionAuditReport {
  auditedAt: number;
  /** Every other installed extension, worst risk first. Sentinel excludes itself (D-010). */
  extensions: ExtensionAuditEntry[];
}

/** The complete, serialisable result of one scan. */
export interface ScanResult {
  scanId: string;
  url: string;
  domain: string;
  origin: string;
  isSecureContext: boolean;
  scannedAt: number;
  durationMs: number;
  modules: ModuleRunStatus[];
  score: TrustScore | null;
  /** Plain-language reading of the same scan; never null, even when `score` is. */
  explanation: Explanation;
  findings: Finding[];
  observation: ObservationSummary;
  /** Classified cookie metadata for the popup's Cookies tab; `null` when cookies were not collected. */
  cookies: CookieReport | null;
  /**
   * Every response header the site sent, beside recommended practice (Phase 4, D-009).
   * Informational and weightless — never part of the score. `null` when the module is off.
   */
  headers: HeaderDashboardReport | null;
  /**
   * Differences versus the domain's previously recorded scan, attached by the background after
   * the scan is recorded (D-008). Absent when the change module is off, the scan was only
   * partially observed, or this observation was already recorded.
   */
  changes?: ProfileChange[];
  /** The site's history line for the Changes panel, present once a scan has been recorded. */
  history?: ProfileHistorySummary;
  warnings: string[];
}

/** Compact, persistent record kept by the history store and (later) Change Monitor. */
export interface ScanSummary {
  scanId: string;
  url: string;
  domain: string;
  scannedAt: number;
  score: number | null;
  grade: Grade | null;
  trackerCount: number;
  thirdPartyHostCount: number;
  headerCount: number;
  signalIds: string[];
  /** Fingerprint of the security-relevant shape of the page, for change detection. */
  signature: string;
}

/** A finding rendered for the drill-down UI. */
export interface FindingView {
  signalId: string;
  categoryId: string;
  categoryLabel: string;
  title: string;
  severity: Severity;
  severityLabel: string;
  confidence: Confidence;
  confidenceLabel: string;
  detail: string;
  evidence: Evidence[];
  remediation: string | null;
  measured: number | null;
  measuredLabel: string;
  impact: number;
  maxImpact: number;
  /** e.g. "−12 of 25 possible points from Response hardening". */
  scoreEffect: string;
}

/**
 * The plain-language reading of a scan, produced by `ExplanationBuilder` and rendered
 * directly by the popup. Kept as data so the UI layer needs no analysis logic at all.
 */
export interface Explanation {
  headline: string;
  summary: string;
  severityCounts: Record<Severity, number>;
  /** One line per category: "Connection security — 92/100 (model weight 35%)". */
  breakdown: string[];
  /** Highest-impact problems, worst first. */
  highlights: string[];
  /** Signals that measured perfectly. */
  strengths: string[];
  /** What could not be measured, and why that matters. */
  caveats: string[];
  /** How much of the model actually produced a measurement (null when complete). */
  coverageNote: string | null;
  /** True when there is no score at all (typically nothing observed yet). */
  insufficientData: boolean;
}
