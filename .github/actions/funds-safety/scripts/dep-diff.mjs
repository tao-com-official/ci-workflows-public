// Diffs lockfile entries between the base and the change, and applies the lockfile rules that
// need no network: where an entry resolves from and whether it kept its integrity hash.
import { parserFor } from './lockfiles.mjs';

const keyOf = (e) => `${e.file}\u0000${e.eco}\u0000${e.name}`;

/** Parses every lockfile in `files` ({path: text|null}); returns {entries, unreadable[]}. */
export function readLockfiles(files) {
  const entries = [];
  const unreadable = [];
  for (const [path, text] of Object.entries(files)) {
    if (text == null) continue;
    const parse = parserFor(path);
    if (!parse) continue;
    try {
      const r = parse(text, path);
      if (r.unreadable) unreadable.push({ file: path, reason: r.unreadable });
      entries.push(...r.entries);
    } catch (err) {
      unreadable.push({ file: path, reason: `couldn't parse: ${err.message}` });
    }
  }
  return { entries, unreadable };
}

/**
 * Compares base and head entries. Returns
 *   changes: [{kind: added|changed|removed, file, eco, name, from: [versions], to: [versions], entries: [head entries new in this change]}]
 *   fresh:   head entries whose name@version (and source) weren't in the base: the ones to check.
 */
export function diffEntries(base, head) {
  const group = (list) => {
    const m = new Map();
    for (const e of list) {
      if (e.local) continue;
      const k = keyOf(e);
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(e);
    }
    return m;
  };
  const b = group(base);
  const h = group(head);
  const ident = (e) => `${e.version}\u0000${e.source}\u0000${e.integrity}`;
  const changes = [];
  const fresh = [];
  for (const [k, hs] of h) {
    const bs = b.get(k) ?? [];
    const seen = new Set(bs.map(ident));
    const novel = hs.filter((e) => !seen.has(ident(e)));
    if (!novel.length) continue;
    fresh.push(...novel);
    const versions = (l) => [...new Set(l.map((e) => e.version))].sort();
    changes.push({ kind: bs.length ? 'changed' : 'added', file: hs[0].file, eco: hs[0].eco, name: hs[0].name, from: versions(bs), to: versions(hs), entries: novel, base: bs });
  }
  for (const [k, bs] of b) {
    if (!h.has(k)) changes.push({ kind: 'removed', file: bs[0].file, eco: bs[0].eco, name: bs[0].name, from: [...new Set(bs.map((e) => e.version))].sort(), to: [], entries: [], base: bs });
  }
  changes.sort((x, y) => x.file.localeCompare(y.file) || x.name.localeCompare(y.name));
  return { changes, fresh };
}

/** Host of a source string, or '' when it has none (github:owner/repo, file:…). */
export function sourceHost(source) {
  const s = source.replace(/^(git\+|registry\+|sparse\+|registry:|index:|git:|url:|legacy:)/, '');
  try {
    return new URL(s).hostname;
  } catch {
    return '';
  }
}

const hostAllowed = (host, allowed) =>
  allowed.some((a) => (a.startsWith('*.') ? host === a.slice(2) || host.endsWith(a.slice(1)) : host === a));

/**
 * The no-network lockfile rules, on the entries this change adds or changes. `registries` is the
 * base branch's extra allowed hosts per ecosystem ({npm: ['npm.hugeicons.com'], …}).
 * Returns findings [{rule, severity: block|report, file, name, version, message}].
 */
export function lockfileFindings({ changes }, registries = {}) {
  const out = [];
  for (const c of changes) {
    if (c.kind === 'removed') continue;
    for (const e of c.entries) {
      const at = { file: e.file, name: e.name, version: e.version };
      if (e.source !== 'registry') {
        const host = sourceHost(e.source);
        const isHttps = /^(git\+|registry\+|sparse\+|registry:|index:|url:)?https:/.test(e.source);
        // An https source on a host the base branch allows for this ecosystem (a private registry).
        if (host && isHttps && hostAllowed(host, registries[e.eco] ?? [])) {
          /* allowed */
        } else {
          out.push({
            rule: 'lockfile-source',
            severity: 'block',
            ...at,
            message: `resolves to \`${e.source}\`, not the ${e.eco} registry${host ? ` (host ${host} isn't in this repo's \`registries.${e.eco}\`)` : ''}`,
          });
        }
      }
      if (e.unpinned) {
        out.push({ rule: 'lockfile-unpinned', severity: 'report', ...at, message: 'requirement isn\'t pinned with `==`' });
      }
      const hadHash = c.base.some((x) => x.integrity);
      if (!e.integrity && !e.conditional && (hadHash || e.source === 'registry' || e.eco === 'cargo')) {
        out.push({
          rule: 'lockfile-integrity',
          // requirements.txt without --hash is common and says nothing about tampering: report it.
          severity: !hadHash && /requirements[^/]*\.txt$/.test(e.file) ? 'report' : 'block',
          ...at,
          message: hadHash ? 'lost the integrity hash it had on the base branch' : 'has no integrity hash',
        });
      }
      if (e.patch && !/^optional!builtin</.test(e.patch)) {
        out.push({ rule: 'lockfile-patch', severity: 'report', ...at, message: `is patched by \`${e.patch}\`: review the patch file, it changes the dependency's code` });
      }
      if (e.installScript) {
        out.push({ rule: 'install-script', severity: 'report', ...at, message: 'runs an install script (preinstall/install/postinstall)' });
      }
    }
  }
  return out;
}
