/**
 * The trust-score module's analysers, in the order the engine runs them.
 *
 * Order only affects diagnostics: two analysers may never report the same signal id, and
 * when they do `TrustEngine` keeps the first measurement and records a warning.
 */

import type { SignalAnalyzer } from '../../../shared/analysis';
import { connectionAnalyzer } from './connection';
import { cookieAnalyzer } from './cookies';
import { headerAnalyzer } from './headers';
import { hygieneAnalyzer } from './hygiene';
import { privacyAnalyzer } from './privacy';

/**
 * Order matters only for diagnostics, but it does follow the weight table: connection and
 * headers (20% each) first, then the signals fed by the content script (privacy 25%, hygiene
 * 15%), then the cookie store signals (cookies 20%, Phase 2).
 */
export const TRUST_SCORE_ANALYZERS: readonly SignalAnalyzer[] = [
  connectionAnalyzer,
  headerAnalyzer,
  privacyAnalyzer,
  hygieneAnalyzer,
  cookieAnalyzer,
];

export { connectionAnalyzer, headerAnalyzer, hygieneAnalyzer, privacyAnalyzer, cookieAnalyzer };
