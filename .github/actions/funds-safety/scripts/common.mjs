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
    ignore: (cfg.ignore ?? []).map((i) => {
      if (!i.rule || !i.path || !i.reason) throw new Error(`${CONFIG_PATH}: each ignore entry needs rule, path and reason`);
      return i;
    }),
  };
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
  const ok = reviews.find(
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
