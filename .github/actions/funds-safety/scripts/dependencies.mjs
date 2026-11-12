// The `security-scans / dependencies` check. Diffs every lockfile between the base and the change,
// lists each added, changed and removed package in the job summary, and checks the new entries:
//   block   source isn't the ecosystem registry (or an allowed private one); integrity lost or
//           missing; integrity differs from the registry's; tarball URL doesn't match the package;
//           version published under 7 days ago; provenance regression (the previous version was
//           published with an npm provenance attestation, this one isn't); version not on the registry;
//           a private scope resolving anywhere but its registry.
//   report  install scripts, patches, deprecated versions, unpinned requirements.
// No install and no package code runs. Network: registry.npmjs.org, crates.io, pypi.org (read-only).
//
// env: BASE (empty = report the whole tree, fail nothing), GITHUB_TOKEN, GITHUB_REPOSITORY,
//      GITHUB_EVENT_PATH, GITHUB_STEP_SUMMARY, FINDINGS_OUT (optional: write the new packages as JSON
//      for GuardDog), NOW (tests)
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { findApproval, git, ignored, loadConfig, prNumber, report, show } from './common.mjs';
import { diffEntries, lockfileFindings, readLockfiles, sourceHost } from './dep-diff.mjs';
import { LOCKFILE_RE } from './lockfiles.mjs';

const DAY = 86400e3;
export const MIN_AGE_DAYS = 7;
const UA = 'tao-ci-workflows-funds-safety';

function lockfilesAt(rev) {
  const files = {};
  for (const p of git('ls-tree', '-r', '--name-only', rev).split('\n')) {
    if (p && LOCKFILE_RE.test(p) && !/(^|\/)node_modules\//.test(p)) files[p] = show(rev, p);
  }
  return files;
}

async function getJson(url, cache) {
  if (cache.has(url)) return cache.get(url);
  const p = (async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json' } });
      if (res.status === 404) return null;
      if (res.ok) return res.json();
      if (res.status < 500 && res.status !== 429) throw new Error(`GET ${url}: ${res.status}`);
      await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
    }
    throw new Error(`GET ${url}: still failing after retries`);
  })();
  cache.set(url, p);
  return p;
}

/**
 * The host an npm entry downloads from, or null when the lockfile doesn't say (yarn berry). A
 * default-registry entry counts as registry.npmjs.org: for a private scope that is the
 * dependency-confusion case, not "the registry".
 */
export function resolvedHost(e) {
  if (e.resolved) return sourceHost(e.resolved);
  if (e.source !== 'registry') return sourceHost(e.source) || e.source;
  if (e.key !== undefined) return 'registry.npmjs.org'; // bun.lock: '' means the default registry
  return null;
}

const scopeOf = (name) => (name.startsWith('@') ? name.split('/')[0] : '');

/** Registry checks for one new npm entry from the public registry. */
export function checkNpm(e, doc, baseVersions, now) {
  const at = { file: e.file, name: e.name, version: e.version };
  const out = [];
  const v = doc?.versions?.[e.version];
  if (!v) return [{ rule: 'registry-missing', severity: 'block', ...at, message: `${e.name}@${e.version} isn't on registry.npmjs.org` }];
  // Yarn berry's checksum hashes its cache zip, not the tarball, so only sha*- integrities compare.
  if (/^sha(1|256|384|512)-/.test(e.integrity)) {
    const want = v.dist?.integrity ?? (v.dist?.shasum ? `sha1-${Buffer.from(v.dist.shasum, 'hex').toString('base64')}` : '');
    const algo = e.integrity.split('-')[0];
    if (want && want.split('-')[0] === algo && want !== e.integrity) {
      out.push({ rule: 'integrity-mismatch', severity: 'block', ...at, message: `lockfile integrity differs from the registry's for ${e.name}@${e.version}: the lockfile points at a different tarball` });
    }
  }
  if (e.resolved && /^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//.test(e.resolved)) {
    const tail = `/${e.name}/-/${e.name.split('/').pop()}-${e.version}.tgz`;
    if (!new URL(e.resolved).pathname.endsWith(tail)) {
      out.push({ rule: 'tarball-mismatch', severity: 'block', ...at, message: `resolved URL \`${e.resolved}\` isn't ${e.name}@${e.version}'s tarball` });
    }
  }
  const published = Date.parse(doc.time?.[e.version] ?? '');
  if (published && now - published < MIN_AGE_DAYS * DAY) {
    out.push({ rule: 'too-new', severity: 'block', ...at, message: `${e.name}@${e.version} was published ${((now - published) / DAY).toFixed(1)} days ago; wait ${MIN_AGE_DAYS} days so a compromised release can be caught and pulled` });
  }
  const prevWithProvenance = baseVersions.find((bv) => doc.versions?.[bv]?.dist?.attestations);
  if (prevWithProvenance && !v.dist?.attestations) {
    out.push({ rule: 'provenance-regression', severity: 'block', ...at, message: `${e.name}@${prevWithProvenance} was published with npm provenance; ${e.version} wasn't. A stolen publish token gives exactly this` });
  }
  const scripts = Object.keys(v.scripts ?? {}).filter((s) => ['preinstall', 'install', 'postinstall'].includes(s));
  if (scripts.length && !e.installScript) out.push({ rule: 'install-script', severity: 'report', ...at, message: `runs ${scripts.join(', ')} on install` });
  if (v.deprecated) out.push({ rule: 'deprecated', severity: 'report', ...at, message: `deprecated: ${String(v.deprecated).slice(0, 120)}` });
  return out;
}

export function checkCrate(e, doc, now) {
  const at = { file: e.file, name: e.name, version: e.version };
  const v = doc?.version;
  if (!v) return [{ rule: 'registry-missing', severity: 'block', ...at, message: `${e.name} ${e.version} isn't on crates.io` }];
  const out = [];
  if (e.integrity && v.checksum && v.checksum !== e.integrity) out.push({ rule: 'integrity-mismatch', severity: 'block', ...at, message: 'Cargo.lock checksum differs from crates.io\'s' });
  if (v.yanked) out.push({ rule: 'yanked', severity: 'block', ...at, message: 'version is yanked' });
  const published = Date.parse(v.created_at ?? '');
  if (published && now - published < MIN_AGE_DAYS * DAY) out.push({ rule: 'too-new', severity: 'block', ...at, message: `published ${((now - published) / DAY).toFixed(1)} days ago (minimum ${MIN_AGE_DAYS})` });
  return out;
}

export function checkPypi(e, doc, now) {
  const at = { file: e.file, name: e.name, version: e.version };
  if (!doc?.urls) return [{ rule: 'registry-missing', severity: 'block', ...at, message: `${e.name}==${e.version} isn't on PyPI` }];
  const out = [];
  const hashes = new Set(doc.urls.map((u) => `sha256:${u.digests?.sha256}`));
  if (e.integrity?.startsWith('sha256:') && !hashes.has(e.integrity)) out.push({ rule: 'integrity-mismatch', severity: 'block', ...at, message: 'hash matches no file PyPI has for this version' });
  const published = Math.min(...doc.urls.map((u) => Date.parse(u.upload_time_iso_8601 ?? '')).filter(Boolean));
  if (Number.isFinite(published) && now - published < MIN_AGE_DAYS * DAY) out.push({ rule: 'too-new', severity: 'block', ...at, message: `published ${((now - published) / DAY).toFixed(1)} days ago (minimum ${MIN_AGE_DAYS})` });
  return out;
}

async function pool(items, n, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) {
      const item = items[i++];
      out.push(...(await fn(item)));
    }
  }));
  return out;
}

export async function registryFindings(diff, cfg, now) {
  const cache = new Map();
  const jobs = [];
  for (const c of diff.changes) {
    if (c.kind === 'removed') continue;
    for (const e of c.entries) {
      const scope = scopeOf(e.name);
      const privateHost = cfg.private_scopes[scope];
      if (e.eco === 'npm' && privateHost) {
        const host = resolvedHost(e);
        // null: yarn berry, whose lockfile has no URL; .yarnrc.yml decides (a sensitive file).
        if (host !== null && host !== privateHost) {
          jobs.push(() => [{ rule: 'private-scope-source', severity: 'block', file: e.file, name: e.name, version: e.version, message: `${scope} must resolve to ${privateHost}, not ${host} (dependency confusion)` }]);
        }
        continue;
      }
      if (e.source !== 'registry') continue; // lockfileFindings handles other sources
      const baseVersions = c.base.map((b) => b.version);
      if (e.eco === 'npm') jobs.push(async () => checkNpm(e, await getJson(`https://registry.npmjs.org/${e.name.replace('/', '%2F')}`, cache), baseVersions, now));
      if (e.eco === 'cargo') jobs.push(async () => checkCrate(e, await getJson(`https://crates.io/api/v1/crates/${e.name}/${e.version}`, cache), now));
      if (e.eco === 'pypi' && e.version) jobs.push(async () => checkPypi(e, await getJson(`https://pypi.org/pypi/${e.name}/${e.version}/json`, cache), now));
    }
  }
  return pool(jobs, 12, async (job) => {
    try {
      return await job();
    } catch (err) {
      return [{ rule: 'registry-unreachable', severity: 'block', message: `couldn't check a package: ${err.message}. Re-run the job.` }];
    }
  });
}

function changesTable(changes, unreadable) {
  if (!changes.length && !unreadable.length) return '\nNo dependency changes.\n';
  let md = `\n### Dependency changes (${changes.filter((c) => c.kind === 'added').length} added, ${changes.filter((c) => c.kind === 'changed').length} changed, ${changes.filter((c) => c.kind === 'removed').length} removed)\n\n`;
  md += '<details><summary>Every package</summary>\n\n| Lockfile | Package | Change |\n| --- | --- | --- |\n';
  for (const c of changes) {
    const v = c.kind === 'added' ? `added ${c.to.join(', ')}` : c.kind === 'removed' ? `removed ${c.from.join(', ')}` : `${c.from.join(', ')} → ${c.to.join(', ')}`;
    md += `| \`${c.file}\` | \`${c.name}\` (${c.eco}) | ${v} |\n`;
  }
  md += '\n</details>\n';
  for (const u of unreadable) md += `\n> ⚠️ \`${u.file}\`: ${u.reason}\n`;
  return md;
}

async function main() {
  const base = process.env.BASE ?? '';
  const now = Number(process.env.NOW) || Date.now();
  const cfg = loadConfig(base || 'HEAD');
  const head = readLockfiles(lockfilesAt('HEAD'));
  const before = base ? readLockfiles(lockfilesAt(base)) : { entries: [], unreadable: [] };
  const diff = diffEntries(before.entries, head.entries);
  const unreadable = head.unreadable.filter((u) => !before.unreadable.some((b) => b.file === u.file && b.reason === u.reason));
  const findings = unreadable.map((u) => ({ rule: 'lockfile-unreadable', severity: 'block', file: u.file, message: u.reason }));
  // Without a base (push, schedule) there's no change to judge: list unreadable lockfiles only.
  if (base) findings.push(...lockfileFindings(diff, cfg.registries), ...(await registryFindings(diff, cfg, now)));
  if (process.env.FINDINGS_OUT) {
    const fresh = diff.fresh.filter((e) => e.source === 'registry' && (e.eco === 'npm' || e.eco === 'pypi') && !cfg.private_scopes[scopeOf(e.name)]);
    writeFileSync(process.env.FINDINGS_OUT, JSON.stringify(fresh.map((e) => ({ eco: e.eco, name: e.name, version: e.version }))));
  }
  const kept = findings.filter((f) => !ignored(cfg, f));
  const enforce = Boolean(base);
  let approval;
  if (enforce && kept.some((f) => f.severity === 'block') && process.env.GITHUB_EVENT_PATH) {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    approval = await findApproval({ repo: process.env.GITHUB_REPOSITORY, pr: prNumber(event), token: process.env.GITHUB_TOKEN, approvers: cfg.approvers });
  }
  const shown = kept.map((f) => (f.name ? { ...f, message: `${f.name}${f.version ? `@${f.version}` : ''}: ${f.message}` } : f));
  process.exitCode = report({ title: 'dependencies', findings: shown, approval, enforce, extra: changesTable(base ? diff.changes : [], unreadable) });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.log(`::error title=dependencies::${err.message}`);
    process.exitCode = 1;
  });
}
