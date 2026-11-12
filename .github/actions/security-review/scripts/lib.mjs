// Small helpers shared by the review scripts. No dependencies: the runner has only node.

// Glob → RegExp: `**` crosses directories, `*` and `?` don't, `{a,b}` alternates.
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:.*/)?';
        } else re += '.*';
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else if (ch === '{') {
      const end = glob.indexOf('}', i);
      re += `(?:${glob.slice(i + 1, end).split(',').map((s) => s.replace(/[.+^$()|[\]\\]/g, '\\$&')).join('|')})`;
      i = end;
    } else re += ch.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  // The globs come from the repo's own config on the base branch (risk.yml, skip_paths), not from
  // the PR, and every regex metacharacter outside * ? {} is escaped above.
  return new RegExp(`^${re}$`); // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
}

export const matchesAny = (path, globs) => globs.some((g) => globToRegExp(g).test(path));

// Reads `.github/risk.yml`: three lists of globs under high, medium and low.
export function parseRiskYml(text) {
  const tiers = { high: [], medium: [], low: [] };
  let current = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+#.*$/, '').trimEnd();
    const key = line.match(/^(high|medium|low):\s*$/);
    if (key) current = key[1];
    else if (/^\S/.test(line)) current = null;
    const item = line.match(/^\s+-\s+['"]?([^'"]+?)['"]?$/);
    if (item && current) tiers[current].push(item[1]);
  }
  return tiers;
}

// The deterministic path floor. Anything unmatched is Medium; one High file makes the PR High.
export function pathTier(files, tiers) {
  if (files.some((f) => matchesAny(f, tiers.high))) return 'High';
  if (files.length && files.every((f) => matchesAny(f, tiers.low) && !matchesAny(f, tiers.medium))) return 'Low';
  return 'Medium';
}

// Splits a unified diff into per-file sections and drops those whose path matches a skip glob.
export function filterDiff(diff, skipGlobs) {
  if (!skipGlobs.length) return { diff, skipped: [] };
  const parts = diff.split(/(?=^diff --git )/m);
  const kept = [];
  const skipped = [];
  for (const part of parts) {
    const m = part.match(/^diff --git a\/(.+?) b\/(.+)$/m);
    if (m && matchesAny(m[2], skipGlobs)) skipped.push(m[2]);
    else kept.push(part);
  }
  return { diff: kept.join(''), skipped };
}

export const changedFiles = (diff) => [...diff.matchAll(/^diff --git a\/.+? b\/(.+)$/gm)].map((m) => m[1]);
