// Shared helpers for the funds-safety and dependencies checks: git, the base-branch config, globs,
// review-based approval and the report.
import { execFileSync } from 'node:child_process';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';

export const CONFIG_PATH = '.github/funds-safety.json';

export function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] });
}

/** File text at a commit, or null when it doesn't exist there. */
export function show(rev, path) {
  try {
    return git('show', `${rev}:${path}`);
  } catch {
    return null;
  }
}

/** `*` stays in one folder, `**` crosses folders, `{a,b}` alternates. Anchored to the repo root. */
export function globToRegExp(glob) {
  let re = '';
  let braces = 0;
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      i++;
      if (glob[i + 1] === '/') {
        i++;
        re += '(?:.*/)?';
      } else re += '.*';
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '{') (braces++, (re += '(?:'));
    else if (c === '}' && braces) (braces--, (re += ')'));
    else if (c === ',' && braces) re += '|';
    else re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  // Globs come from the base branch's config, which a PR can't change.
  return new RegExp(`^${re}$`); // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
}
export const matchAny = (path, globs = []) => globs.some((g) => globToRegExp(g).test(path));

/** Test, spec, story and mock-only paths: the code checks skip them. Not `mocks/` or `fixtures/`
 * folders, which production code can import (Fable red-team #5). */
export const TEST_GLOBS = ['**/*.test.*', '**/*.spec.*', '**/*.stories.*', '**/*.e2e.*', '**/__tests__/**', '**/__snapshots__/**', '**/e2e/**', '**/tests/**'];

/**
 * The repo's funds-safety config, from the BASE commit so a PR can't loosen the rules it is checked
 * against. Missing → defaults (nothing allowed, nobody can approve). Invalid → throws.
 */
export function loadConfig(baseRev) {
  // FUNDS_SAFETY_CONFIG_FILE is for local and report-only runs (trying a draft config on old PRs).
  // The action never sets it, and a caller can't set a called workflow's step env.
  const text = process.env.FUNDS_SAFETY_CONFIG_FILE ? readFileSync(process.env.FUNDS_SAFETY_CONFIG_FILE, 'utf8') : show(baseRev, CONFIG_PATH);
  const cfg = text == null ? {} : JSON.parse(text);
  const list = (k) => {
    const v = cfg[k] ?? [];
    if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) throw new Error(`${CONFIG_PATH}: ${k} must be a list of strings`);
    return v;
  };
  return {
    present: text != null,
    approvers: list('approvers').map((s) => s.toLowerCase()),
    address_files: list('address_files'),
    address_report_only: list('address_report_only'),
    crypto_paths: list('crypto_paths'),
    allowed_hosts: list('allowed_hosts').map((s) => s.toLowerCase()),
    sensitive_paths: list('sensitive_paths'),
    lavamoat_policies: list('lavamoat_policies'),
    registries: cfg.registries ?? {},
    private_scopes: cfg.private_scopes ?? {},
    version_only: versionOnlyEntries(cfg.version_only),
    ignore: (cfg.ignore ?? []).map((i) => {
      if (!i.rule || !i.path || !i.reason) throw new Error(`${CONFIG_PATH}: each ignore entry needs rule, path and reason`);
      return i;
    }),
  };
}

// A key path in `version_only`: dot-separated names, no array indexes, nothing that reaches the
// prototype.
const KEY_PATH = /^[A-Za-z0-9_$-]+(\.[A-Za-z0-9_$-]+)*$/;
const FORBIDDEN_KEY = new Set(['__proto__', 'constructor', 'prototype']);

/** `version_only: [{path, keys}]`, checked strictly: any other shape throws. */
function versionOnlyEntries(v = []) {
  const bad = (why) => new Error(`${CONFIG_PATH}: version_only ${why}`);
  if (!Array.isArray(v)) throw bad('must be a list of {path, keys}');
  return v.map((e, i) => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) throw bad(`[${i}] must be an object with path and keys`);
    const extra = Object.keys(e).filter((k) => k !== 'path' && k !== 'keys');
    if (extra.length) throw bad(`[${i}] has unknown keys: ${extra.join(', ')}`);
    if (typeof e.path !== 'string' || !e.path.trim() || e.path.startsWith('/')) throw bad(`[${i}].path must be a repo-relative glob`);
    globToRegExp(e.path); // the same matcher as sensitive_paths
    if (!Array.isArray(e.keys) || !e.keys.length) throw bad(`[${i}].keys must be a non-empty list of dotted key paths`);
    for (const k of e.keys) {
      if (typeof k !== 'string' || !KEY_PATH.test(k) || k.split('.').some((p) => FORBIDDEN_KEY.has(p))) throw bad(`[${i}].keys: ${JSON.stringify(k)} isn't a dotted key path like expo.version`);
    }
    return { path: e.path, keys: [...e.keys] };
  });
}

/** Object keys repeated inside one JSON object, which JSON.parse silently collapses (last wins).
 * Run it on text JSON.parse accepted. */
export function duplicateJsonKeys(text) {
  const dups = [];
  const stack = []; // {keys: Set, expectKey} for objects, null for arrays
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) dups.push(key);
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === '{') stack.push({ keys: new Set(), expectKey: true });
    else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',' && stack[stack.length - 1]) stack[stack.length - 1].expectKey = true;
  }
  return dups;
}

const isScalar = (v) => v === undefined || typeof v === 'string' || typeof v === 'number';
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null || Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
}
/** The value at a dotted path, or undefined; detaches it from the object when `remove`. */
function at(obj, path, remove = false) {
  const parts = path.split('.');
  let o = obj;
  for (const p of parts.slice(0, -1)) {
    if (!o || typeof o !== 'object' || Array.isArray(o) || !Object.prototype.hasOwnProperty.call(o, p)) return undefined;
    // Reads own properties only (checked above), key paths can't name __proto__, constructor or
    // prototype (versionOnlyEntries), and nothing is assigned: it can't reach or change a prototype.
    o = o[p]; // nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
  }
  const last = parts[parts.length - 1];
  if (!o || typeof o !== 'object' || Array.isArray(o) || !Object.prototype.hasOwnProperty.call(o, last)) return undefined;
  const v = o[last];
  if (remove) delete o[last];
  return v;
}

/**
 * Whether a JSON file changed only in the listed key paths. Both sides must exist and parse, with no
 * duplicate keys; a listed key that changed must be a string or number (or absent) on both sides;
 * and with the listed keys removed, the two must be deep-equal. A listed key that exists on one
 * side only counts as a version change; a parent object it leaves behind does not.
 * → {ok: true, changed: [key paths]} or {ok: false, why}
 */
export function versionOnlyChange(baseText, headText, keys) {
  if (baseText == null) return { ok: false, why: 'the file is new (or renamed) in this PR' };
  if (headText == null) return { ok: false, why: 'the file is deleted (or renamed) in this PR' };
  let b;
  let h;
  try {
    b = JSON.parse(baseText);
    h = JSON.parse(headText);
  } catch {
    return { ok: false, why: "one side isn't valid JSON" };
  }
  const dups = [...duplicateJsonKeys(baseText), ...duplicateJsonKeys(headText)];
  if (dups.length) return { ok: false, why: `duplicate JSON keys (${[...new Set(dups)].join(', ')})` };
  if (!b || !h || typeof b !== 'object' || typeof h !== 'object' || Array.isArray(b) || Array.isArray(h)) return { ok: false, why: "the file isn't a JSON object" };
  const changed = [];
  for (const k of keys) {
    const bv = at(b, k, true);
    const hv = at(h, k, true);
    if (deepEqual(bv, hv)) continue;
    if (!isScalar(bv) || !isScalar(hv)) return { ok: false, why: `\`${k}\` changed and isn't a plain string or number` };
    changed.push(k);
  }
  if (!deepEqual(b, h)) return { ok: false, why: 'keys other than the version keys changed' };
  return { ok: true, changed };
}

export const ignored = (cfg, f) => cfg.ignore.some((i) => (i.rule === f.rule || i.rule === '*') && globToRegExp(i.path).test(f.file ?? ''));

export const hostAllowed = (host, allowed) =>
  allowed.some((a) => (a.startsWith('*.') ? host === a.slice(2) || host.endsWith(a.slice(1)) : host === a));

// --- approval ---------------------------------------------------------------------------------------
async function gh(path, token) {
  const res = await fetch(`${process.env.GITHUB_API_URL ?? 'https://api.github.com'}${path}`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
  });
  if (!res.ok) throw new Error(`GET ${path}: ${res.status} ${await res.text()}`);
  return res.json();
}
async function ghAll(path, token) {
  const out = [];
  for (let page = 1; page < 50; page++) {
    const batch = await gh(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`, token);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

/** The PR number for this run: the pull_request event, or the merge queue's head ref. */
export function prNumber(event) {
  if (event.pull_request) return event.pull_request.number;
  const m = /\/pr-(\d+)-[0-9a-f]+$/.exec(event.merge_group?.head_ref ?? '');
  return m ? Number(m[1]) : undefined;
}

/**
 * Whether an approver signed off on exactly this PR head: an APPROVED review whose commit_id is the
 * PR's current head SHA, by a login in the base config's approvers, who is neither the PR author
 * nor the author or committer of any commit in it. A review binds to its commit, so a push after
 * the review voids it. Labels aren't used: anyone with write access can add them (Fable #7).
 */
export async function findApproval({ repo, pr, token, approvers }) {
  if (!pr || !token || !approvers.length) return { approved: false, why: !approvers.length ? 'no approvers in the base config' : 'not a pull request' };
  const p = await gh(`/repos/${repo}/pulls/${pr}`, token);
  const head = p.head.sha;
  const commits = await ghAll(`/repos/${repo}/pulls/${pr}/commits`, token);
  const involved = new Set([p.user.login.toLowerCase()]);
  for (const c of commits) {
    for (const who of [c.author?.login, c.committer?.login]) if (who && who !== 'web-flow') involved.add(who.toLowerCase());
  }
  const reviews = await ghAll(`/repos/${repo}/pulls/${pr}/reviews`, token);
  // Each reviewer's latest decisive review counts, as on GitHub: a later CHANGES_REQUESTED or a
  // dismissal withdraws an earlier approval. Comment-only reviews don't change it.
  const latest = new Map();
  for (const r of reviews) {
    if (['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(r.state)) latest.set(r.user.login.toLowerCase(), r);
  }
  const ok = [...latest.values()].find(
    (r) => r.state === 'APPROVED' && r.commit_id === head && approvers.includes(r.user.login.toLowerCase()) && !involved.has(r.user.login.toLowerCase()),
  );
  return ok
    ? { approved: true, by: ok.user.login, head }
    : { approved: false, head, why: `no APPROVED review on ${head.slice(0, 7)} from an approver who didn't write this PR (${approvers.join(', ')})` };
}

// --- report -----------------------------------------------------------------------------------------
const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

/**
 * Prints annotations and a job summary for findings [{rule, severity: block|report, file, line?, message}]
 * and returns the exit code: 1 when anything blocks and there's no approval (and enforce is on).
 */
export function report({ title, findings, approval, enforce, extra = '' }) {
  if (process.env.FINDINGS_JSON) writeFileSync(process.env.FINDINGS_JSON, JSON.stringify(findings));
  const blocking = findings.filter((f) => f.severity === 'block');
  for (const f of findings) {
    const level = f.severity === 'block' && !approval?.approved && enforce ? 'error' : 'warning';
    const loc = f.file ? ` file=${esc(f.file)}${f.line ? `,line=${f.line}` : ''}` : '';
    console.log(`::${level}${loc},title=${esc(`${title}: ${f.rule}`)}::${esc(f.message)}`);
  }
  let md = `## ${title}\n\n`;
  if (!findings.length) md += 'No findings.\n';
  else {
    md += `${blocking.length} blocking, ${findings.length - blocking.length} reported.\n\n| | Rule | Where | Finding |\n| --- | --- | --- | --- |\n`;
    for (const f of [...blocking, ...findings.filter((x) => x.severity !== 'block')]) {
      md += `| ${f.severity === 'block' ? '⛔' : 'ℹ️'} | \`${cell(f.rule)}\` | ${f.file ? `\`${cell(f.file)}${f.line ? `:${f.line}` : ''}\`` : ''} | ${cell(f.message)} |\n`;
    }
  }
  if (blocking.length) {
    md += approval?.approved
      ? `\nApproved by @${approval.by} on ${approval.head.slice(0, 7)}: blocking findings are accepted for this head.\n`
      : `\n**To merge:** fix the blocking findings, or have an approver from \`.github/funds-safety.json\` (not the author or a committer) approve this exact head commit, then re-run this job.${approval?.why ? ` (${approval.why})` : ''}\n`;
    if (!enforce) md += '\n_Report-only run (no pull request base): nothing fails._\n';
  }
  md += extra;
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
  else console.log(md);
  return blocking.length && enforce && !approval?.approved ? 1 : 0;
}
