// Runs Datadog GuardDog (pinned image) on the npm and PyPI packages this change adds or bumps, and
// adds what it finds to the job summary. Report-only: it never fails the check (Fable red-team #9),
// and a GuardDog error is reported, not fatal. GuardDog downloads each package and reads it
// statically; nothing is installed or run.
// env: LIST (from dependencies.mjs), GUARDDOG_IMAGE, GITHUB_STEP_SUMMARY
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';

const MAX = 40;
const list = existsSync(process.env.LIST) ? JSON.parse(readFileSync(process.env.LIST, 'utf8')) : [];
const rows = [];
let errors = 0;
for (const p of list.slice(0, MAX)) {
  let out;
  try {
    out = execFileSync(
      'docker',
      ['run', '--rm', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', process.env.GUARDDOG_IMAGE, p.eco, 'scan', p.name, '--version', p.version, '--output-format', 'json', '--no-sandbox'],
      { encoding: 'utf8', timeout: 180e3, maxBuffer: 1 << 26, stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch (err) {
    out = err.stdout;
    if (!out) {
      errors++;
      rows.push(`| \`${p.name}@${p.version}\` | ⚠️ GuardDog failed: ${String(err.stderr ?? err.message).split('\n').filter(Boolean).pop()?.slice(0, 150)} |`);
      continue;
    }
  }
  let res;
  try {
    res = JSON.parse(out.slice(out.indexOf('{')));
  } catch {
    errors++;
    rows.push(`| \`${p.name}@${p.version}\` | ⚠️ unreadable GuardDog output |`);
    continue;
  }
  // A hit is a non-empty list of locations (source rules) or a message (metadata rules). The
  // capability-* rules describe what code *can* do and match most packages: left out.
  const hit = (v) => (Array.isArray(v) ? v.length > 0 : typeof v === 'string' ? v.trim() !== '' : false);
  const hits = Object.entries(res.results ?? {}).filter(([rule, v]) => !rule.startsWith('capability-') && hit(v));
  const errs = Object.keys(res.errors ?? {});
  if (errs.length) {
    errors++;
    rows.push(`| \`${p.name}@${p.version}\` | ⚠️ ${errs.length} rule(s) errored: ${errs.slice(0, 3).join(', ')} |`);
  }
  if (hits.length) {
    rows.push(`| \`${p.name}@${p.version}\` | ${hits.map(([rule, v]) => `\`${rule}\`${Array.isArray(v) ? ` ×${v.length}` : ''}`).join(', ')} |`);
    console.log(`::warning title=guarddog::${p.name}@${p.version}: ${hits.map(([r]) => r).join(', ')}`);
  }
}
let md = `\n### GuardDog (report only)\n\nScanned ${Math.min(list.length, MAX)} of ${list.length} new or changed npm/PyPI packages${list.length > MAX ? ` (first ${MAX})` : ''}.`;
md += rows.length ? `\n\n| Package | GuardDog rules that matched |\n| --- | --- |\n${rows.join('\n')}\n` : ' Nothing matched.\n';
if (errors) md += `\n${errors} package(s) couldn't be scanned.\n`;
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
else console.log(md);
