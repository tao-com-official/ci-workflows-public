// Whether a PR is Dependabot's alone and changes dependency files only. The shared code and security
// reviews then leave it to the repo's own Dependabot review (dependabot-review.yml) instead of
// calling Claude. Everything is read from the PR's content, never from `github.actor`, which changes
// on a label or a re-run:
// - the PR was opened by Dependabot (user id, not login);
// - every commit is authored by Dependabot, committed by GitHub (web-flow) and verified. A person can
//   push to a Dependabot branch, and can even author a commit as Dependabot; only GitHub signs as
//   web-flow;
// - every changed path (and a rename's old path) is a manifest, a lockfile, a workflow or an
//   action.yml. Submodule pointers, Gemfile.lock and gradle files keep the AI review: the
//   Dependabot review can't read them, so it can't stand in.
// And it follows the app's own rule for standing in for a required check on a Dependabot PR
// (dependabot-review.yml, DEPENDABOT_READY_CHECKS): only when the repo variable names this check, and
// only once the head's `Dependabot review` status, set by GitHub Actions, is success (LOW, or a person
// accepted it). Pending, failed or missing after the wait: the AI review runs, as it did before.
// Fails safe: anything it can't read or doesn't recognise means "not only", and the AI review runs.
import { appendFileSync } from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

export const DEPENDABOT_ID = 49699333;
const DEPENDENCY_FILE = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/;
const WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const ACTION = /^\.github\/actions\/(.+\/)?action\.ya?ml$/;

/** Whether one path may change in a PR the Dependabot review stands in for. */
export function dependencyPath(path) {
  return DEPENDENCY_FILE.test(path) || WORKFLOW.test(path) || ACTION.test(path);
}

/** { only, why } from the PR, its commits and its files, as the REST API returns them. */
export function decide({ pr, commits, files }) {
  if (pr?.user?.id !== DEPENDABOT_ID || pr?.user?.login !== 'dependabot[bot]') {
    return { only: false, why: `opened by ${pr?.user?.login ?? 'unknown'}, not Dependabot` };
  }
  if (!Array.isArray(commits) || commits.length === 0) return { only: false, why: 'no commits read' };
  for (const c of commits) {
    const sha = String(c?.sha ?? '').slice(0, 7);
    if (c?.author?.id !== DEPENDABOT_ID) return { only: false, why: `commit ${sha} isn't authored by Dependabot` };
    if (c?.committer?.login !== 'web-flow') return { only: false, why: `commit ${sha} wasn't committed by GitHub (web-flow)` };
    if (c?.commit?.verification?.verified !== true) return { only: false, why: `commit ${sha} isn't verified` };
  }
  if (!Array.isArray(files) || files.length === 0) return { only: false, why: 'no files read' };
  const paths = [...new Set(files.flatMap((f) => [f?.filename, f?.previous_filename].filter(Boolean)))];
  const other = paths.filter((p) => !dependencyPath(p));
  if (other.length) {
    return { only: false, why: `changes ${other.slice(0, 3).join(', ')}${other.length > 3 ? ` and ${other.length - 3} more` : ''}, not only dependency files` };
  }
  return { only: true, why: `Dependabot-only PR (${commits.length} verified commit(s)), dependency files only (${paths.length})` };
}

/** Whether the app opted this check in: DEPENDABOT_READY_CHECKS is comma-separated check names. */
export function optedIn(readyChecks, check) {
  return String(readyChecks || '')
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean)
    .includes(check);
}

/** The Dependabot review's verdict from the commit's statuses (newest first, as the API lists them):
 * 'success', 'failure', 'error', 'pending' or 'none'. Only a status GitHub Actions set counts. */
export function reviewState(statuses, context) {
  const mine = (Array.isArray(statuses) ? statuses : []).filter((st) => st?.context === context && st?.creator?.login === 'github-actions[bot]');
  return mine.length ? String(mine[0].state) : 'none';
}

async function gh(path) {
  const api = process.env.GITHUB_API_URL || 'https://api.github.com';
  const out = [];
  for (let page = 1; page <= 30; page += 1) {
    const sep = path.includes('?') ? '&' : '?';
    const res = await fetch(`${api}/${path}${sep}per_page=100&page=${page}`, {
      headers: { authorization: `Bearer ${process.env.GH_TOKEN}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    });
    if (!res.ok) throw new Error(`GET ${path}: HTTP ${res.status}`);
    const body = await res.json();
    if (!Array.isArray(body)) return body;
    out.push(...body);
    if (body.length < 100) break;
  }
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const { REPO, PR, GITHUB_OUTPUT, CHECK, READY_CHECKS, REVIEW_STATUS = 'Dependabot review' } = process.env;
  const waitSeconds = Number(process.env.WAIT_SECONDS ?? 600);
  let result;
  try {
    if (!/^\d+$/.test(String(PR))) throw new Error(`bad PR number '${PR}'`);
    const [pr, commits, files] = await Promise.all([
      gh(`repos/${REPO}/pulls/${PR}`),
      gh(`repos/${REPO}/pulls/${PR}/commits`),
      gh(`repos/${REPO}/pulls/${PR}/files`),
    ]);
    // The API lists at most 250 commits and 3000 files; anything at the limit isn't judged.
    if (commits.length >= 250 || files.length >= 3000) result = { only: false, why: 'too many commits or files to judge' };
    else result = decide({ pr, commits, files });
    if (result.only && !optedIn(READY_CHECKS, CHECK)) {
      result = { only: false, why: `${result.why}, but DEPENDABOT_READY_CHECKS doesn't name '${CHECK}', so the Dependabot review doesn't stand in for it (the app's opt-in)` };
    } else if (result.only) {
      const sha = pr.head.sha;
      let state = 'none';
      for (let waited = 0; ; waited += 15) {
        state = reviewState(await gh(`repos/${REPO}/commits/${sha}/statuses`), REVIEW_STATUS);
        if (!['none', 'pending'].includes(state) || waited >= waitSeconds) break;
        await sleep(15_000);
      }
      result =
        state === 'success'
          ? { only: true, why: `${result.why}; '${REVIEW_STATUS}' is success on ${sha.slice(0, 7)}` }
          : { only: false, why: `${result.why}, but '${REVIEW_STATUS}' is ${state} on ${sha.slice(0, 7)}, so the AI review runs` };
    }
  } catch (e) {
    result = { only: false, why: `couldn't read the PR (${e.message})` };
  }
  console.log(`${result.only ? 'Dependabot-only' : 'Not Dependabot-only'}: ${result.why}.`);
  if (GITHUB_OUTPUT) appendFileSync(GITHUB_OUTPUT, `only=${result.only}\nwhy=${result.why.replace(/[\r\n]+/g, ' ')}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) await main();
