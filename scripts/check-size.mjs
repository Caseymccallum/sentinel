#!/usr/bin/env node
/**
 * check-size - Sentinel has to stay small enough to read.
 *
 * A reviewer should be able to open a built extension and understand it, so this script
 * measures what `wxt build` produced and fails when it grows past a budget. The budgets are
 * deliberately generous for Phase 1 and exist to catch accidents (a bundled dependency, a
 * stray source map, an inlined font), not to force premature optimisation.
 *
 * Usage: node scripts/check-size.mjs [--verbose]
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUTPUT_DIR = join(ROOT, '.output');
const VERBOSE = process.argv.includes('--verbose');

/** Total budget per built target (Chrome and Firefox are measured separately). */
const TOTAL_BUDGET_KB = 400;

/** No single file may exceed this - a large file usually means something got inlined. */
const FILE_BUDGET_KB = 200;

/** Extensions whose bytes do not affect what runs. */
const IGNORED_EXTENSIONS = new Set(['.map']);

function walk(directory) {
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const full = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...walk(full));
    else if (!IGNORED_EXTENSIONS.has(extname(entry.name).toLowerCase())) found.push(full);
  }
  return found;
}

function formatKb(bytes) {
  return `${(bytes / 1024).toFixed(1)} kB`;
}

function main() {
  if (!existsSync(OUTPUT_DIR)) {
    console.log('check-size - no .output/ directory yet; run `npm run build` first.');
    process.exitCode = 1;
    return;
  }

  const targets = readdirSync(OUTPUT_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => !name.endsWith('-dev'))
    // A target counts as built only if it actually has a manifest to ship.
    .filter((name) => existsSync(join(OUTPUT_DIR, name, 'manifest.json')))
    .sort();

  if (targets.length === 0) {
    console.log('check-size - no built targets under .output/; run `npm run build` first.');
    process.exitCode = 1;
    return;
  }

  const problems = [];
  console.log('check-size - keeping the extension small enough to audit.');

  for (const target of targets) {
    const files = walk(join(OUTPUT_DIR, target)).map((file) => ({
      path: relative(OUTPUT_DIR, file).replace(/\\/g, '/'),
      bytes: statSync(file).size,
    }));
    const total = files.reduce((sum, file) => sum + file.bytes, 0);
    const largest = [...files].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
    const over = total / 1024 > TOTAL_BUDGET_KB;

    console.log(
      `\n${over ? 'FAIL' : ' ok '}  ${target}: ${files.length} file(s), ${formatKb(total)}` +
        ` (budget ${TOTAL_BUDGET_KB} kB)`,
    );
    for (const file of largest) {
      console.log(`         ${formatKb(file.bytes).padStart(9)}  ${file.path}`);
    }
    if (VERBOSE) {
      for (const file of files) console.log(`        ${formatKb(file.bytes).padStart(9)}  ${file.path}`);
    }

    if (over) {
      problems.push(
        `${target} is ${formatKb(total)}, over its ${TOTAL_BUDGET_KB} kB budget ` +
          `(${formatKb(total - TOTAL_BUDGET_KB * 1024)} too large). Trim it, or raise TOTAL_BUDGET_KB deliberately.`,
      );
    }

    for (const file of files) {
      if (file.bytes / 1024 > FILE_BUDGET_KB) {
        problems.push(
          `${file.path} is ${formatKb(file.bytes)}, over the ${FILE_BUDGET_KB} kB per-file budget. ` +
            'Something was probably inlined; check the bundle for a bundled dependency.',
        );
      }
    }

    const manifestPath = join(OUTPUT_DIR, target, 'manifest.json');
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      const shipped = manifest.permissions?.length ?? 0;
      console.log(`         ${shipped} permission(s) declared, ${files.length} file(s) shipped`);
    } catch {
      // The local-only check is the authority on manifest contents; size is not its job.
    }
  }

  if (problems.length > 0) {
    console.log(`\nFAIL  ${problems.length} size problem(s):`);
    for (const problem of problems) console.log(`  - ${problem}`);
    process.exitCode = 1;
    return;
  }

  console.log('\nOK  Every built target is within budget.');
}

main();
