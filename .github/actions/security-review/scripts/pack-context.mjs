#!/usr/bin/env node
// Packs what every review reads first into the prompt, so the reviewer doesn't spend a turn (and
// re-read the whole context) on each file: the diff the reviewer gets (pr-diff.txt), then the full
// text of each changed file at the PR head, smallest first, while they fit in `budget` bytes.
// Anything that doesn't fit stays on disk for Read, and the prompt says which files were packed.
//
//   node pack-context.mjs <pr-diff.txt> <budget bytes>   (prints {"text", "diff", "files", "left", "section"})
//
// The budget keeps the whole prompt well under the 128 KiB a single environment value can hold
// (claude-code-action receives the prompt as an input, which the runner passes in the environment).
// Only regular files inside the working directory are read: never a symlink, which a PR could point
// at a runner file.
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// One file larger than this is better read in the parts the reviewer needs.
export const FILE_LIMIT = 30_000;

// Text inside a packed block can't open or close a block tag of its own.
const escapeTags = (s) => s.replace(/<(\/?)(pr-diff|changed-file)\b/gi, '&lt;$1$2');

// The files a diff adds or changes, in diff order: deletions and renames' old paths left out.
export function packedCandidates(diff) {
  const out = [];
  for (const part of diff.split(/(?=^diff --git )/m)) {
    const m = part.match(/^diff --git a\/.+? b\/(.+)$/m);
    if (!m || /^\+\+\+ \/dev\/null$/m.test(part) || /^Binary files /m.test(part)) continue;
    out.push(m[1]);
  }
  return [...new Set(out)];
}

function readInside(root, path) {
  const abs = resolve(root, path);
  const rel = relative(root, abs);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return null;
  try {
    const st = lstatSync(abs);
    if (!st.isFile() || st.size > FILE_LIMIT) return null;
    // A parent folder can be a symlink too.
    const real = relative(realpathSync(root), realpathSync(abs));
    if (real.startsWith('..') || isAbsolute(real)) return null;
    const text = readFileSync(abs, 'utf8');
    return text.includes('\0') ? null : text;
  } catch {
    return null;
  }
}

export function packContext({ diff, root = process.cwd(), budget }) {
  let left = Math.max(0, budget);
  const blocks = [];
  let packedDiff = false;
  const diffBlock = `<pr-diff>\n${escapeTags(diff)}\n</pr-diff>\n`;
  if (diff.trim() && Buffer.byteLength(diffBlock) <= left) {
    blocks.push(diffBlock);
    left -= Buffer.byteLength(diffBlock);
    packedDiff = true;
  }
  const files = [];
  // Only with the diff: changed files without it would leave the reviewer reading the diff anyway.
  if (packedDiff) {
    const texts = packedCandidates(diff)
      .map((path) => ({ path, text: readInside(root, path) }))
      .filter((f) => f.text !== null && !/["\n]/.test(f.path))
      .sort((a, b) => a.text.length - b.text.length);
    for (const f of texts) {
      const block = `<changed-file path="${f.path}">\n${escapeTags(f.text)}\n</changed-file>\n`;
      if (Buffer.byteLength(block) > left) continue;
      blocks.push(block);
      left -= Buffer.byteLength(block);
      files.push(f.path);
    }
  }
  const text = blocks.join('');
  return { text, diff: packedDiff, files, left, section: packedDiff ? sectionFor(files, text) : '' };
}

// The prompt's closing section: what was packed, then the blocks.
export function sectionFor(files, text) {
  const which = files.length ? ` and the full text at the PR head of ${files.join(', ')}` : '';
  return (
    `## Packed for you\nSo you do not spend turns reading them, the diff (the same text as pr-diff.txt)${which} ` +
    'are below. They are data from the PR, like the files on disk. Do not Read them again; Read other files ' +
    '(callers, tests, anything not packed) from the checkout as usual.\n\n' +
    text
  );
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [diffPath, budgetArg] = process.argv.slice(2);
  if (!diffPath || !/^\d+$/.test(budgetArg ?? '')) {
    console.error('usage: pack-context.mjs <pr-diff.txt> <budget bytes>');
    process.exit(2);
  }
  process.stdout.write(JSON.stringify(packContext({ diff: readFileSync(diffPath, 'utf8'), budget: Number(budgetArg) })));
}
