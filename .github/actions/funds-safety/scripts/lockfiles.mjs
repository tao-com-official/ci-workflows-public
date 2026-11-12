// Lockfile parsers for the dependency guard. No dependencies: each parser reads one format's text
// and returns entries { eco, name, version, source, integrity, installScript, file }.
//   eco        npm | cargo | pypi
//   source     where the package resolves: 'registry' for the ecosystem's default registry, or the
//              URL / protocol it resolves to otherwise (a tarball URL, git+…, github:…, file:…).
//   integrity  the lockfile's hash for the artefact, or '' when it has none.
// `local` marks workspace / link / portal entries, which are the repo's own code, not a download.

const NPM_REGISTRY_HOSTS = ['registry.npmjs.org', 'registry.yarnpkg.com', 'registry.npmjs.com'];

export const LOCKFILE_RE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|bun\.lockb?|Cargo\.lock|poetry\.lock|uv\.lock|Pipfile\.lock|requirements[^/]*\.txt)$/;

/** The parser for a lockfile path, or undefined. */
export function parserFor(path) {
  const base = path.split('/').pop();
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return parseNpmLock;
  if (base === 'yarn.lock') return parseYarnLock;
  if (base === 'bun.lock') return parseBunLock;
  if (base === 'bun.lockb') return () => ({ entries: [], unreadable: 'bun.lockb is binary; commit the text bun.lock (bun >= 1.2) so it can be checked' });
  if (base === 'Cargo.lock') return parseCargoLock;
  if (base === 'poetry.lock') return parsePoetryLock;
  if (base === 'uv.lock') return parseUvLock;
  if (base === 'Pipfile.lock') return parsePipfileLock;
  if (/^requirements[^/]*\.txt$/.test(base)) return parseRequirements;
  return undefined;
}

/** Classifies an npm tarball URL: 'registry' when it's on a default npm registry host. */
export function npmSource(resolved) {
  if (!resolved) return 'registry';
  try {
    const u = new URL(resolved);
    if (u.protocol === 'https:' && NPM_REGISTRY_HOSTS.includes(u.hostname)) return 'registry';
  } catch {
    /* not a URL: git+ssh:, file:, github: … */
  }
  return resolved;
}

const isLocalSpec = (s) => /^(workspace|link|portal|file):/.test(s);

// --- npm: package-lock.json / npm-shrinkwrap.json, lockfileVersion 1–3 ----------------------------
export function parseNpmLock(text, file) {
  const lock = JSON.parse(text);
  const entries = [];
  if (lock.packages) {
    for (const [path, p] of Object.entries(lock.packages)) {
      if (path === '') continue;
      const name = p.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const local = Boolean(p.link) || !path.includes('node_modules/');
      entries.push({
        eco: 'npm',
        name,
        version: p.version ?? '',
        source: local ? `file:${p.resolved ?? path}` : npmSource(p.resolved),
        integrity: p.integrity ?? '',
        resolved: p.resolved,
        installScript: Boolean(p.hasInstallScript),
        local,
        file,
      });
    }
    return { entries };
  }
  const walk = (deps) => {
    for (const [name, p] of Object.entries(deps ?? {})) {
      const local = /^file:/.test(p.version ?? '');
      entries.push({
        eco: 'npm',
        name,
        version: p.version ?? '',
        source: local ? p.version : npmSource(p.resolved),
        integrity: p.integrity ?? '',
        installScript: false,
        local,
        file,
      });
      walk(p.dependencies);
    }
  };
  walk(lock.dependencies);
  return { entries };
}

// --- yarn.lock: v1 (classic) and berry (v2+) --------------------------------------------------------
export function parseYarnLock(text, file) {
  const entries = [];
  const berry = /^__metadata:/m.test(text);
  let block = null;
  const flush = () => {
    if (!block) return;
    const f = block.fields;
    const firstKey = block.keys[0] ?? '';
    const name = firstKey.replace(/^(@?[^@]+)@.*$/, '$1');
    if (berry) {
      if (name === '__metadata') return void (block = null);
      const resolution = f.resolution ?? '';
      const spec = resolution.slice(resolution.indexOf('@', 1) + 1);
      let source;
      if (/^npm:/.test(spec)) source = 'registry';
      else if (/^patch:/.test(spec)) {
        // patch:<inner>#<patch file or builtin>. The inner spec decides where it downloads from.
        const inner = decodeURIComponent(spec.slice('patch:'.length).split('#')[0]);
        const innerSpec = inner.slice(inner.indexOf('@', 1) + 1);
        source = /^npm:/.test(innerSpec) ? 'registry' : innerSpec;
      } else source = spec;
      entries.push({
        eco: 'npm',
        name,
        version: f.version ?? '',
        source: isLocalSpec(spec) ? spec : source,
        integrity: f.checksum ?? '',
        installScript: false,
        local: isLocalSpec(spec),
        // Yarn writes no checksum for an optional platform package it didn't fetch (`conditions:`).
        conditional: 'conditions' in f,
        patch: /^patch:/.test(spec) ? decodeURIComponent(spec.split('#').slice(1).join('#')) : undefined,
        file,
      });
    } else {
      const local = /^file:|^link:/.test(f.version ?? '') || /^(file|link):/.test(f.resolved ?? '');
      entries.push({
        eco: 'npm',
        name,
        version: f.version ?? '',
        source: local ? f.resolved ?? 'file:' : npmSource((f.resolved ?? '').split('#')[0]),
        integrity: f.integrity ?? '',
        resolved: (f.resolved ?? '').split('#')[0],
        installScript: false,
        local,
        file,
      });
    }
    block = null;
  };
  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) {
      flush();
      const keys = line
        .replace(/:$/, '')
        .split(/,\s*/)
        .map((k) => k.trim().replace(/^"|"$/g, ''));
      block = { keys, fields: {} };
      continue;
    }
    // Only the block's own fields (2-space indent), not nested dependency maps.
    const m = /^ {2}([A-Za-z]+):? +"?(.*?)"?$/.exec(line);
    if (block && m && !/^ {4}/.test(line)) block.fields[m[1]] = m[2];
  }
  flush();
  return { entries };
}

// --- bun.lock (text, JSONC) -----------------------------------------------------------------------
export function parseBunLock(text, file) {
  // JSONC: trailing commas only (bun writes no comments).
  const lock = JSON.parse(text.replace(/,(\s*[}\]])/g, '$1'));
  const entries = [];
  for (const [key, v] of Object.entries(lock.packages ?? {})) {
    if (!Array.isArray(v)) continue;
    const ident = v[0];
    const at = ident.indexOf('@', 1);
    const name = ident.slice(0, at);
    const spec = ident.slice(at + 1);
    let source;
    let integrity = '';
    let local = false;
    if (isLocalSpec(spec) || /^root:/.test(spec)) {
      source = spec;
      local = true;
    } else if (/^(github|git\+|git:|https?:)/.test(spec)) {
      // git / github: [ident, meta, "owner-repo-sha"]; tarball URL: [ident, meta]
      source = spec;
      integrity = typeof v[2] === 'string' ? v[2] : '';
    } else {
      // npm: [ident, registry ('' = default), meta, integrity]
      source = v[1] ? npmSource(v[1].endsWith('/') ? v[1] + 'x' : v[1]) : 'registry';
      if (source !== 'registry') source = v[1];
      integrity = typeof v[3] === 'string' ? v[3] : '';
    }
    entries.push({ eco: 'npm', name, version: local ? '' : spec, source, integrity, installScript: false, local, key, file });
  }
  return { entries };
}

// --- minimal TOML for [[package]] arrays (Cargo.lock, poetry.lock, uv.lock) ------------------------
function tomlPackages(text) {
  const pkgs = [];
  let cur = null;
  let sub = null; // e.g. [package.source]
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '[[package]]') {
      cur = { _hashes: [] };
      sub = null;
      pkgs.push(cur);
      continue;
    }
    if (line.startsWith('[')) {
      // [package.source] and friends belong to the current package; any other table ends it.
      const m = /^\[([^\]]+)\]$/.exec(line);
      if (cur && m && m[1].startsWith('package.')) sub = m[1].slice('package.'.length);
      else cur = sub = null;
      continue;
    }
    if (!cur) continue;
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
    if (kv) {
      const target = sub ? (cur[sub] ??= {}) : cur;
      target[kv[1]] = tomlValue(kv[2]);
    }
    for (const h of raw.matchAll(/hash\s*=\s*"([^"]+)"/g)) cur._hashes.push(h[1]);
  }
  return pkgs;
}
function tomlValue(v) {
  v = v.trim();
  if (v.startsWith('"')) return v.slice(1, v.indexOf('"', 1));
  if (v.startsWith('{')) {
    const o = {};
    for (const m of v.matchAll(/([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"/g)) o[m[1]] = m[2];
    return o;
  }
  return v;
}

export function parseCargoLock(text, file) {
  const entries = tomlPackages(text).map((p) => {
    const src = p.source ?? '';
    const registry = src === 'registry+https://github.com/rust-lang/crates.io-index' || src === 'sparse+https://index.crates.io/';
    return {
      eco: 'cargo',
      name: p.name,
      version: p.version ?? '',
      source: src === '' ? 'path' : registry ? 'registry' : src,
      integrity: p.checksum ?? '',
      installScript: false,
      local: src === '',
      file,
    };
  });
  return { entries };
}

const PYPI = (u) => /^https:\/\/(pypi\.org|files\.pythonhosted\.org)\//.test(u ?? '');

export function parsePoetryLock(text, file) {
  const entries = tomlPackages(text).map((p) => {
    const s = p.source ?? {};
    const local = s.type === 'directory' || s.type === 'file';
    const source = !s.type ? 'registry' : s.type === 'legacy' && PYPI(s.url) ? 'registry' : `${s.type}:${s.url ?? ''}`;
    return { eco: 'pypi', name: p.name, version: p.version ?? '', source, integrity: p._hashes.length ? p._hashes[0] : '', installScript: false, local, file };
  });
  return { entries };
}

export function parseUvLock(text, file) {
  const entries = tomlPackages(text).map((p) => {
    const s = typeof p.source === 'object' ? p.source : {};
    const local = Boolean(s.editable || s.virtual || s.directory || s.path);
    let source = 'registry';
    if (s.registry && !/^https:\/\/pypi\.org\/simple\/?$/.test(s.registry)) source = `registry:${s.registry}`;
    else if (s.git) source = `git:${s.git}`;
    else if (s.url) source = s.url;
    else if (local) source = `path:${s.editable ?? s.virtual ?? s.directory ?? s.path}`;
    return { eco: 'pypi', name: p.name, version: p.version ?? '', source, integrity: p._hashes.length ? p._hashes[0] : '', installScript: false, local, file };
  });
  return { entries };
}

export function parsePipfileLock(text, file) {
  const lock = JSON.parse(text);
  const sources = Object.fromEntries((lock._meta?.sources ?? []).map((s) => [s.name, s.url]));
  const entries = [];
  for (const group of ['default', 'develop']) {
    for (const [name, p] of Object.entries(lock[group] ?? {})) {
      const idx = p.index ? sources[p.index] : undefined;
      let source = 'registry';
      if (p.git) source = `git:${p.git}`;
      else if (p.file || p.path) source = `file:${p.file ?? p.path}`;
      else if (idx && !/^https:\/\/pypi\.org\/simple\/?$/.test(idx)) source = `registry:${idx}`;
      entries.push({
        eco: 'pypi',
        name,
        version: (p.version ?? '').replace(/^==/, ''),
        source,
        integrity: (p.hashes ?? [])[0] ?? '',
        installScript: false,
        local: Boolean(p.path || p.editable),
        file,
      });
    }
  }
  return { entries };
}

export function parseRequirements(text, file) {
  const entries = [];
  const indexes = [];
  // Join backslash continuations so `--hash` lines attach to their requirement.
  for (const line of text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
    const l = line.replace(/(^|\s)#.*$/, '').trim();
    if (!l) continue;
    const idx = /^(?:-i|--index-url|--extra-index-url|-f|--find-links)[\s=]+(\S+)/.exec(l);
    if (idx) {
      indexes.push(idx[1]);
      continue;
    }
    if (l.startsWith('-')) continue;
    const hashes = [...l.matchAll(/--hash[=\s]+(\S+)/g)].map((m) => m[1]);
    const direct = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*@\s*(\S+)/.exec(l);
    if (direct) {
      entries.push({ eco: 'pypi', name: direct[1].toLowerCase(), version: '', source: direct[2], integrity: hashes[0] ?? '', installScript: false, local: /^file:/.test(direct[2]), file });
      continue;
    }
    if (/^(git\+|https?:)/.test(l)) {
      entries.push({ eco: 'pypi', name: l.split(/[#/]/).pop(), version: '', source: l.split(/\s/)[0], integrity: hashes[0] ?? '', installScript: false, local: false, file });
      continue;
    }
    const pin = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(===?)\s*([^\s;]+)/.exec(l);
    const name = (pin?.[1] ?? /^[A-Za-z0-9._-]+/.exec(l)?.[0] ?? l).toLowerCase();
    entries.push({ eco: 'pypi', name, version: pin?.[3] ?? '', source: 'registry', integrity: hashes[0] ?? '', installScript: false, local: false, unpinned: !pin, file });
  }
  const custom = indexes.filter((u) => !PYPI(u) && !/^https:\/\/pypi\.org\/simple\/?$/.test(u));
  if (custom.length) for (const e of entries) if (e.source === 'registry') e.source = `index:${custom.join(',')}`;
  return { entries, indexes };
}
