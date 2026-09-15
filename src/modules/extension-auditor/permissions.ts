/**
 * The Extension Auditor's permission knowledge base (Phase 4, D-010).
 *
 * Sentinel reads what the browser already knows: `browser.management.getAll()` reports, for
 * every installed extension, which API permissions and host patterns it holds. This file is
 * the local, hand-written translation of those strings into what they would let an extension
 * do — the same pattern as the cookie knowledge base (Phase 2), and deliberately opinionated:
 * the severity grades *capability*, and a capability you cannot see is the dangerous kind.
 *
 * A permission missing from this table is reported as `low` with an honest "not in Sentinel's
 * knowledge base" note — an unknown permission is a reason to look, not a verdict.
 */

import type { HostAccess, PermissionFinding, Severity } from '../../core/types';

export interface PermissionInfo {
  label: string;
  severity: Severity;
  /** What the permission would let an extension do, in plain language. */
  why: string;
}

export const PERMISSION_KB: Readonly<Record<string, PermissionInfo>> = {
  debugger: {
    label: 'Remote debugging',
    severity: 'critical',
    why: 'Can take control of the browser through the debugging protocol: read and change anything any page does.',
  },
  nativeMessaging: {
    label: 'Native messaging',
    severity: 'critical',
    why: 'Can exchange messages with programs on your computer, escaping the browser sandbox.',
  },
  webRequestBlocking: {
    label: 'Blocking web requests',
    severity: 'critical',
    why: 'Can intercept and modify every request a page makes (legacy Manifest V2 capability).',
  },
  proxy: {
    label: 'Proxy control',
    severity: 'high',
    why: 'Can route all of your traffic through servers of its choosing.',
  },
  history: {
    label: 'Browsing history',
    severity: 'high',
    why: 'Can read your entire browsing history.',
  },
  tabs: {
    label: 'Tab access',
    severity: 'high',
    why: 'Can read the address and title of every tab you open.',
  },
  cookies: {
    label: 'Cookies',
    severity: 'high',
    why: 'Can read cookie metadata for every site you visit.',
  },
  clipboardRead: {
    label: 'Clipboard reading',
    severity: 'high',
    why: 'Can read anything you copy.',
  },
  management: {
    label: 'Extension management',
    severity: 'high',
    why: 'Can list the extensions you have installed, and enable or disable them.',
  },
  webRequest: {
    label: 'Web request visibility',
    severity: 'medium',
    why: 'Can see the network requests pages make.',
  },
  webNavigation: {
    label: 'Navigation monitoring',
    severity: 'medium',
    why: 'Can see every navigation event, including addresses and frames.',
  },
  scripting: {
    label: 'Script injection',
    severity: 'medium',
    why: 'Can inject scripts into pages; combined with broad host access this is code execution on those sites.',
  },
  downloads: {
    label: 'Downloads',
    severity: 'medium',
    why: 'Can open, cancel and change your downloads.',
  },
  bookmarks: {
    label: 'Bookmarks',
    severity: 'medium',
    why: 'Can read and change your bookmarks.',
  },
  privacy: {
    label: 'Privacy settings',
    severity: 'medium',
    why: 'Can change browser privacy features such as tracking protection.',
  },
  geolocation: {
    label: 'Location',
    severity: 'medium',
    why: 'Can ask for your physical location.',
  },
  notifications: {
    label: 'Notifications',
    severity: 'low',
    why: 'Can show desktop notifications.',
  },
  activeTab: {
    label: 'Active tab (on click)',
    severity: 'low',
    why: 'Access to the current tab only after you click the extension.',
  },
  storage: {
    label: 'Local storage',
    severity: 'info',
    why: 'Local storage only; no access to your browsing.',
  },
  unlimitedStorage: {
    label: 'Unlimited storage',
    severity: 'info',
    why: 'Can store large amounts of data locally.',
  },
  contextMenus: {
    label: 'Context menus',
    severity: 'info',
    why: 'Can add items to the right-click menu.',
  },
  alarms: {
    label: 'Alarms',
    severity: 'info',
    why: 'Can schedule its own work.',
  },
  idle: {
    label: 'Idle detection',
    severity: 'info',
    why: 'Can detect when you stop using the computer.',
  },
};

/** Not in the table: honest uncertainty, not a clean bill of health. */
export const UNKNOWN_PERMISSION: PermissionInfo = {
  label: '',
  severity: 'low',
  why: "Not in Sentinel's knowledge base. Review what this permission does before trusting the extension.",
};

/**
 * True for a match pattern whose host part is `*` — the whole web under one scheme — and for
 * Chrome's `<all_urls>`. Scheme-scoped wildcards are still "every site", so they count.
 */
export function isBroadHostPattern(pattern: string): boolean {
  if (pattern === '<all_urls>') return true;
  const schemeSplit = pattern.split('://');
  const rest = schemeSplit.length === 2 ? schemeSplit[1] : undefined;
  if (rest === undefined) return false;
  const host = rest.split('/')[0] ?? '';
  return host === '*';
}

/** Classifies the host patterns an extension has been granted. */
export function classifyHostAccess(hostPermissions: readonly string[]): HostAccess {
  let any = false;
  for (const pattern of hostPermissions) {
    if (isBroadHostPattern(pattern)) return 'broad';
    if (pattern.trim() !== '') any = true;
  }
  return any ? 'site-specific' : 'none';
}

/** The synthetic finding an audit attaches for host access, if any. */
export function hostAccessFinding(hostPermissions: readonly string[]): PermissionFinding | null {
  const access = classifyHostAccess(hostPermissions);
  if (access === 'broad') {
    return {
      name: 'host-access',
      label: 'Broad host access',
      severity: 'high',
      why: 'Can read and change every site you visit, on every page.',
    };
  }
  if (access === 'site-specific') {
    return {
      name: 'host-access',
      label: 'Host access',
      severity: 'low',
      why: `Can read and change pages on the ${hostPermissions.length} ${hostPermissions.length === 1 ? 'site' : 'sites'} it names.`,
    };
  }
  return null;
}
