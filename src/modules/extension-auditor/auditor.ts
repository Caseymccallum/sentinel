/**
 * The Extension Auditor's pure classifier (Phase 4, D-010).
 *
 * Input: what `browser.management.getAll()` reported about the installed extensions, mapped
 * onto plain data. Output: one `ExtensionAuditEntry` per extension, worst risk first, with
 * every notable permission translated into what it would let the extension do.
 *
 * This file knows nothing about the browser. The caller filters `type === 'extension'` and
 * excludes Sentinel itself (D-010: the auditor does not audit itself); the audit result is
 * computed on demand, never persisted, and never touches the Trust Score.
 */

import type {
  ExtensionAuditEntry,
  ExtensionAuditReport,
  PermissionFinding,
  Severity,
} from '../../core/types';
import { SEVERITY_ORDER } from '../../core/scoring-model';
import { PERMISSION_KB, UNKNOWN_PERMISSION, classifyHostAccess, hostAccessFinding } from './permissions';

/** The shape of one installed extension, as the caller maps it from `management.ExtensionInfo`. */
export interface AuditableExtension {
  id: string;
  name: string;
  version: string;
  enabled: boolean;
  permissions: readonly string[];
  hostPermissions: readonly string[];
}

export interface AuditOptions {
  /** Ids to leave out of the report (Sentinel excludes itself before calling). */
  excludeIds?: readonly string[];
  /** Injected clock, so `auditedAt` stays predictable under test. */
  now?: number;
}

function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/** Audits one extension: every declared permission plus host access, findings worst first. */
export function auditOneExtension(extension: AuditableExtension): ExtensionAuditEntry {
  const findings: PermissionFinding[] = extension.permissions.map((name) => {
    const info = PERMISSION_KB[name] ?? { ...UNKNOWN_PERMISSION, label: name };
    return { name, label: info.label, severity: info.severity, why: info.why };
  });

  const hostFinding = hostAccessFinding(extension.hostPermissions);
  if (hostFinding) findings.push(hostFinding);

  findings.sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    return a.label.localeCompare(b.label);
  });

  const worst = findings.reduce<Severity>((risk, finding) => {
    return severityRank(finding.severity) > severityRank(risk) ? finding.severity : risk;
  }, 'info');

  const hostAccess = classifyHostAccess(extension.hostPermissions);

  return {
    id: extension.id,
    name: extension.name,
    version: extension.version,
    enabled: extension.enabled,
    hostAccess,
    risk: worst,
    findings,
  };
}

/** Audits a list of installed extensions, worst risk first, then alphabetically. */
export function auditExtensions(
  installed: readonly AuditableExtension[],
  options: AuditOptions = {},
): ExtensionAuditReport {
  const excluded = new Set(options.excludeIds ?? []);
  const extensions = installed
    .filter((extension) => !excluded.has(extension.id))
    .map(auditOneExtension)
    .sort((a, b) => {
      const byRisk = severityRank(b.risk) - severityRank(a.risk);
      if (byRisk !== 0) return byRisk;
      return a.name.localeCompare(b.name);
    });
  return { auditedAt: options.now ?? 0, extensions };
}
