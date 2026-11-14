// The `security-scans / funds-safety` check. Reads Semgrep's JSON (tao rules, run with
// --baseline-commit so only what the change introduces is reported) and adds the checks that work on
// the diff itself: address literals (JSON included), sensitive files, lifecycle scripts, minified or
// binary code, and new LavaMoat powers. Every blocking finding can be accepted for one exact head
// commit by an approver's review (see common.mjs findApproval).
//
// env: BASE (base commit; empty = report-only full run), SEMGREP_JSON, GITHUB_TOKEN,
//      GITHUB_REPOSITORY, GITHUB_EVENT_PATH, GITHUB_STEP_SUMMARY
import { existsSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { CONFIG_PATH, TEST_GLOBS, findApproval, git, hostAllowed, ignored, loadConfig, matchAny, prNumber, report, show, versionOnlyChange } from './common.mjs';
import { LOCKFILE_RE } from './lockfiles.mjs';
import { mergePolicies, policyFindings } from './lavamoat.mjs';

// Files that decide what gets installed, scanned or reviewed. A change to one blocks until approved
// (Fable red-team #4): a PR that widens them would make the next PR pass.
export const DEFAULT_SENSITIVE = [
  CONFIG_PATH,
  '.semgrepignore',
  '{,.github/,docs/}CODEOWNERS',
  '**/.npmrc',
  '**/.yarnrc',
  '**/.yarnrc.yml',
  '**/bunfig.toml',
  '.yarn/plugins/**',
  '.yarn/releases/**',
  '.yarn/patches/**',
  '**/patches/*.patch',
  '.pnpmfile.cjs',
  '**/.cargo/config{,.toml}',
  '**/pip.conf',
];
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish', 'prepack', 'postpack', 'dependencies'];
const PM_FIELDS = ['packageManager', 'trustedDependencies', 'patchedDependencies', 'lavamoat'];
const CODE_EXT = /\.(jsx?|tsx?|mjs|cjs|rs)$/;
const ADDRESS = /(?<![0-9A-Za-z])(0x[0-9a-fA-F]{40}|5[1-9A-HJ-NP-Za-km-z]{47})(?![0-9A-Za-z])/g;

/** {path: [{line, text}]} of lines added between base and head (renames followed as edits). */
export function addedLines(base, head = 'HEAD') {
  const out = {};
  let file = null;
  let line = 0;
  for (const l of git('diff', '-U0', '--no-color', '--no-ext-diff', '--find-renames', base, head).split('\n')) {
    if (l.startsWith('+++ ')) {
      file = l === '+++ /dev/null' ? null : l.slice(6);
      if (file) out[file] ??= [];
    } else if (l.startsWith('@@')) line = Number(/\+(\d+)/.exec(l)[1]);
    else if (file && l.startsWith('+')) out[file].push({ line: line++, text: l.slice(1) });
    else if (file && l.startsWith(' ')) line++;
  }
  return out;
}

export function addressFindings(added, cfg) {
  const out = [];
  for (const [file, lines] of Object.entries(added)) {
    if (LOCKFILE_RE.test(file) || matchAny(file, TEST_GLOBS) || /\.(snap|svg|lock|md|mdx)$/.test(file)) continue;
    for (const { line, text } of lines) {
      for (const m of text.matchAll(ADDRESS)) {
        const addr = `${m[1].slice(0, 8)}…${m[1].slice(-4)}`;
        if (matchAny(file, cfg.address_report_only)) {
          out.push({ rule: 'address-changed', severity: 'report', file, line, message: `address ${addr} added in a report-only address file` });
        } else if (matchAny(file, cfg.address_files)) {
          out.push({ rule: 'address-changed', severity: 'block', file, line, message: `address ${addr} added or changed in an address file: an approver must confirm it's the intended recipient, fee, spender or contract` });
        } else {
          out.push({ rule: 'hardcoded-address', severity: 'block', file, line, message: `chain address literal ${addr} outside the repo's address_files` });
        }
      }
    }
  }
  return out;
}

/**
 * Changed sensitive files block. One exception: a file in the repo's `sensitive_paths` (never a
 * built-in one) that matches a `version_only` entry and changed only in that entry's keys is
 * reported instead (see common.mjs versionOnlyChange). `read(side, file)` gives the file's text at
 * 'base' or 'head', or null when it doesn't exist there.
 */
export function sensitiveFindings(changed, cfg, read = () => null) {
  const globs = [...DEFAULT_SENSITIVE, ...cfg.sensitive_paths];
  const block = 'changes what gets installed, scanned or trusted; needs an approver';
  return changed.filter((f) => matchAny(f, globs)).map((file) => {
    const entries = matchAny(file, DEFAULT_SENSITIVE) ? [] : (cfg.version_only ?? []).filter((e) => matchAny(file, [e.path]));
    if (!entries.length) return { rule: 'sensitive-file', severity: 'block', file, message: block };
    const keys = [...new Set(entries.flatMap((e) => e.keys))];
    const v = versionOnlyChange(read('base', file), read('head', file), keys);
    if (v.ok) return { rule: 'sensitive-file', severity: 'report', file, message: `version-only change (${v.changed.map((k) => `\`${k}\``).join(', ') || 'formatting only'}): nothing else in the file differs` };
    return { rule: 'sensitive-file', severity: 'block', file, message: `${block} (not a version-only change: ${v.why})` };
  });
}

export function packageJsonFindings(file, baseText, headText) {
  const parse = (t) => {
    try {
      return t == null ? {} : JSON.parse(t);
    } catch {
      return {};
    }
  };
  const b = parse(baseText);
  const h = parse(headText);
  const out = [];
  const same = (x, y) => JSON.stringify(x ?? null) === JSON.stringify(y ?? null);
  for (const s of LIFECYCLE) {
    if (!same(b.scripts?.[s], h.scripts?.[s])) out.push({ rule: 'lifecycle-script', severity: 'block', file, message: `\`scripts.${s}\` changed: it runs on every install` });
  }
  for (const k of PM_FIELDS) {
    if (!same(b[k], h[k])) out.push({ rule: 'package-manager-config', severity: 'block', file, message: `\`${k}\` changed` });
  }
  for (const k of ['overrides', 'resolutions']) {
    if (!same(b[k], h[k])) out.push({ rule: 'package-manager-config', severity: 'report', file, message: `\`${k}\` changed: check each forced version` });
  }
  return out;
}

export function codeShapeFindings(added) {
  const out = [];
  for (const [file, lines] of Object.entries(added)) {
    if (/\.(wasm|node|so|dylib|dll|exe)$/.test(file)) {
      out.push({ rule: 'binary-code', severity: 'block', file, message: 'executable binary added or changed; it can\'t be reviewed or scanned' });
      continue;
    }
    if (!/\.(m?jsx?|cjs|tsx?|html?)$/.test(file) || matchAny(file, TEST_GLOBS)) continue;
    const long = lines.find((l) => l.text.length > 1000);
    if (long) out.push({ rule: 'minified-code', severity: 'block', file, line: long.line, message: `a ${long.text.length}-character line: minified or generated code can't be reviewed; vendored code needs an approver` });
  }
  return out;
}

/** Semgrep JSON → findings, applying the base config and the promotion rules. */
export function semgrepFindings(sg, cfg, changedCode) {
  const out = [];
  for (const r of sg.results ?? []) {
    const rule = r.check_id.split('.').pop();
    const file = r.path.replace(/^\.\//, '');
    if (matchAny(file, TEST_GLOBS)) continue;
    let severity = r.extra.severity === 'ERROR' ? 'block' : 'report';
    let message = r.extra.message.trim();
    if (rule === 'tao-weak-rng' && matchAny(file, cfg.crypto_paths)) severity = 'block';
    if (rule === 'tao-outbound-host') {
      // Semgrep OSS redacts `lines`, so read the literal from the file.
      let host = '';
      try {
        const buf = readFileSync(file);
        const lit = buf.subarray(r.start.offset, r.end.offset).toString();
        host = (/(?:https?|wss?):\/\/([^/:'"`\s$]+)/.exec(lit)?.[1] ?? '').toLowerCase();
      } catch {
        /* unreadable: keep it reported */
      }
      if (host && hostAllowed(host, cfg.allowed_hosts)) continue;
      message = `URL to \`${host || '?'}\`, which isn't in allowed_hosts. Check the host is ours and is in the CSP.`;
    }
    out.push({ rule, severity, file, line: r.start.line, message });
  }
  // A changed code file Semgrep didn't parse or scan would otherwise pass unseen (Fable #5).
  const scanned = new Set((sg.paths?.scanned ?? []).map((p) => p.replace(/^\.\//, '')));
  const errored = new Set();
  for (const e of sg.errors ?? []) {
    const p = (e.path ?? e.spans?.[0]?.file ?? '').replace(/^\.\//, '');
    if (p && changedCode.includes(p) && !errored.has(p)) {
      errored.add(p);
      out.push({ rule: 'semgrep-error', severity: 'block', file: p, message: `Semgrep couldn't fully analyse this file (${[e.type].flat()[0]}), so the rules didn't see all of it` });
    }
  }
  for (const p of changedCode) {
    if (!scanned.has(p) && !errored.has(p)) out.push({ rule: 'not-scanned', severity: 'block', file: p, message: 'changed code file that Semgrep skipped (too large or excluded)' });
  }
  return out;
}

async function main() {
  const base = process.env.BASE ?? '';
  const enforce = Boolean(base);
  const cfg = loadConfig(base || 'HEAD');
  const findings = [];
  const notes = [];
  if (!cfg.present) notes.push(`This repo has no \`${CONFIG_PATH}\` on its base branch, so nothing is allowlisted and nobody can approve.`);

  if (base) {
    const changed = git('diff', '--name-only', '--no-renames', base, 'HEAD').split('\n').filter(Boolean);
    const existing = git('diff', '--name-only', '--diff-filter=ACMRT', base, 'HEAD').split('\n').filter(Boolean);
    const added = addedLines(base);
    const changedCode = existing.filter((f) => CODE_EXT.test(f) && !matchAny(f, TEST_GLOBS));
    findings.push(...addressFindings(added, cfg), ...sensitiveFindings(changed, cfg, (side, f) => show(side === 'base' ? base : 'HEAD', f)), ...codeShapeFindings(added));
    for (const f of changed.filter((p) => /(^|\/)package\.json$/.test(p))) findings.push(...packageJsonFindings(f, show(base, f), show('HEAD', f)));
    if (cfg.lavamoat_policies.length) {
      const read = (rev) => mergePolicies(...cfg.lavamoat_policies.map((p) => JSON.parse(show(rev, p) ?? '{}')));
      if (cfg.lavamoat_policies.some((p) => changed.includes(p))) findings.push(...policyFindings(cfg.lavamoat_policies[0], read(base), read('HEAD')));
    }
    const sgPath = process.env.SEMGREP_JSON;
    if (!sgPath || !existsSync(sgPath)) throw new Error('Semgrep results are missing: the scan step failed.');
    findings.push(...semgrepFindings(JSON.parse(readFileSync(sgPath, 'utf8')), cfg, changedCode));
  } else {
    const sgPath = process.env.SEMGREP_JSON;
    if (sgPath && existsSync(sgPath)) findings.push(...semgrepFindings(JSON.parse(readFileSync(sgPath, 'utf8')), cfg, []));
  }

  const kept = findings.filter((f) => !ignored(cfg, f));
  let approval;
  if (enforce && kept.some((f) => f.severity === 'block') && process.env.GITHUB_EVENT_PATH) {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    approval = await findApproval({ repo: process.env.GITHUB_REPOSITORY, pr: prNumber(event), token: process.env.GITHUB_TOKEN, approvers: cfg.approvers });
  }
  const extra = notes.length ? `\n${notes.map((n) => `> ${n}`).join('\n')}\n` : '';
  process.exitCode = report({ title: 'funds-safety', findings: kept, approval, enforce, extra });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.log(`::error title=funds-safety::${err.message}`);
    process.exitCode = 1;
  });
}
