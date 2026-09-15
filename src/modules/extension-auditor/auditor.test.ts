import { describe, expect, it } from 'vitest';
import { auditExtensions, auditOneExtension, type AuditableExtension } from './auditor';
import { PERMISSION_KB, classifyHostAccess, hostAccessFinding, isBroadHostPattern } from './permissions';

function extension(overrides: Partial<AuditableExtension> = {}): AuditableExtension {
  return {
    id: 'ext-1',
    name: 'Test Extension',
    version: '1.2.3',
    enabled: true,
    permissions: [],
    hostPermissions: [],
    ...overrides,
  };
}

describe('permission knowledge base', () => {
  it('grades the capabilities a user cannot see as the most serious', () => {
    expect(PERMISSION_KB.debugger?.severity).toBe('critical');
    expect(PERMISSION_KB.nativeMessaging?.severity).toBe('critical');
    expect(PERMISSION_KB.history?.severity).toBe('high');
    expect(PERMISSION_KB.tabs?.severity).toBe('high');
  });

  it('never grades a permission above what it can do: storage stays informational', () => {
    expect(PERMISSION_KB.storage?.severity).toBe('info');
    expect(PERMISSION_KB.alarms?.severity).toBe('info');
  });

  it('treats every whole-web match pattern as broad host access', () => {
    expect(isBroadHostPattern('<all_urls>')).toBe(true);
    expect(isBroadHostPattern('*://*/*')).toBe(true);
    expect(isBroadHostPattern('https://*/*')).toBe(true);
    expect(isBroadHostPattern('https://example.com/*')).toBe(false);
  });

  it('classifies host access in three honest grades', () => {
    expect(classifyHostAccess([])).toBe('none');
    expect(classifyHostAccess(['https://example.com/*'])).toBe('site-specific');
    expect(classifyHostAccess(['https://example.com/*', '*://*/*'])).toBe('broad');
  });

  it('attaches a synthetic finding for broad host access, and none for no access', () => {
    const broad = hostAccessFinding(['<all_urls>']);
    expect(broad).toMatchObject({ name: 'host-access', severity: 'high' });
    expect(hostAccessFinding([])).toBeNull();
    expect(hostAccessFinding(['https://example.com/*'])?.severity).toBe('low');
  });
});

describe('auditOneExtension', () => {
  it('translates every declared permission, worst first', () => {
    const entry = auditOneExtension(
      extension({ permissions: ['storage', 'history', 'tabs'] }),
    );
    expect(entry.risk).toBe('high');
    expect(entry.findings[0]?.name).toBe('history');
    expect(entry.findings.at(-1)?.name).toBe('storage');
    expect(entry.hostAccess).toBe('none');
  });

  it('reports an unknown permission honestly instead of calling it safe', () => {
    const entry = auditOneExtension(extension({ permissions: ['someBrandNewPermission'] }));
    const finding = entry.findings[0];
    expect(finding?.severity).toBe('low');
    expect(finding?.why).toContain("Not in Sentinel's knowledge base");
    expect(finding?.label).toBe('someBrandNewPermission');
  });

  it('adds the broad-host-access finding to the risk, not just to the list', () => {
    const entry = auditOneExtension(extension({ permissions: ['storage'], hostPermissions: ['<all_urls>'] }));
    expect(entry.hostAccess).toBe('broad');
    expect(entry.risk).toBe('high');
    expect(entry.findings[0]).toMatchObject({ name: 'host-access', severity: 'high' });
  });

  it('produces a clean audit for a permission-free extension, not a warning', () => {
    const entry = auditOneExtension(extension());
    expect(entry.risk).toBe('info');
    expect(entry.findings).toEqual([]);
  });
});

describe('auditExtensions', () => {
  it('sorts worst risk first, then alphabetically within a risk band', () => {
    const report = auditExtensions([
      extension({ id: 'a', name: 'Alpha', permissions: ['storage'] }),
      extension({ id: 'c', name: 'Charlie', permissions: ['debugger'] }),
      extension({ id: 'b', name: 'Beta', permissions: ['history'] }),
    ]);
    expect(report.extensions.map((entry) => entry.name)).toEqual(['Charlie', 'Beta', 'Alpha']);
  });

  it('excludes the ids the caller names (D-010: Sentinel excludes itself)', () => {
    const report = auditExtensions(
      [extension({ id: 'self', name: 'Sentinel' }), extension({ id: 'other', name: 'Other' })],
      { excludeIds: ['self'] },
    );
    expect(report.extensions.map((entry) => entry.id)).toEqual(['other']);
  });

  it('records when the audit ran, from the injected clock', () => {
    const report = auditExtensions([], { now: 1234 });
    expect(report.auditedAt).toBe(1234);
    expect(report.extensions).toEqual([]);
  });
});
