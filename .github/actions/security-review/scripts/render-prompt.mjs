#!/usr/bin/env node
// Fills a prompt template's {{name}} placeholders in one pass, so text inside a value (a PR
// description that contains "{{round}}", say) is never expanded again. Fails on a placeholder
// with no value, so a renamed variable can't ship a prompt with a literal "{{tier}}" in it.
//
//   node render-prompt.mjs <template> <vars.json>   (prints the prompt)
//
// The composite action and evals/run.mjs both use this, so the eval scores the prompt CI sends.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function renderPrompt(template, vars) {
  const missing = new Set();
  const out = template.replace(/\{\{([a-z_]+)\}\}/g, (_, key) => {
    if (!(key in vars)) {
      missing.add(key);
      return '';
    }
    let value = String(vars[key]);
    // The description sits inside <pr-description> tags; it must not be able to close them.
    // Every match starts with its one `<`, so swapping that character is the whole escape.
    if (key === 'pr_description') value = value.replace(/<\/?pr-description/gi, (m) => `&lt;${m.slice(1)}`);
    return value;
  });
  if (missing.size) throw new Error(`No value for placeholder(s): ${[...missing].join(', ')}`);
  return out;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [templatePath, varsPath] = process.argv.slice(2);
  if (!templatePath || !varsPath) {
    console.error('usage: render-prompt.mjs <template> <vars.json>');
    process.exit(2);
  }
  process.stdout.write(renderPrompt(readFileSync(templatePath, 'utf8'), JSON.parse(readFileSync(varsPath, 'utf8'))));
}
