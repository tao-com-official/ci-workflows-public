// Did claude-code-action fail before the model did anything? A throttled or briefly unavailable
// token ends the run within a second or so: the result is is_error:true with no model usage. That
// is worth one retry. A failure after the model ran (the turn cap, a timeout) is not: a retry
// would spend the same again and most likely fail the same way.
//
// node instant-failure.mjs <step outcome> <execution file>
// Appends retry=true|false to $GITHUB_OUTPUT and prints why.
import { appendFileSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/** Longest run, in ms, that still counts as instant. */
export const INSTANT_MS = 60_000;

/**
 * Why the run is worth a retry, or null when it isn't.
 * @param {string} outcome the step's outcome (success, failure, skipped)
 * @param {string | null} text the execution file's contents, or null when there is none
 */
export function instantFailure(outcome, text) {
  if (outcome !== 'failure') return null;
  if (!text || !text.trim()) return 'the action failed before writing an execution log';
  let log;
  try {
    log = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(log)) return null;
  const result = log.filter((m) => m?.type === 'result').at(-1);
  // A run that crashed after the model took turns already cost something: no retry.
  if (!result) return log.some((m) => m?.type === 'assistant') ? null : 'the action failed before Claude returned a result';
  if (result.is_error !== true) return null;
  const usage = result.modelUsage;
  const used = usage && typeof usage === 'object' && Object.keys(usage).length > 0;
  if (used || (result.num_turns ?? 0) > 1) return null;
  if (typeof result.duration_ms === 'number' && result.duration_ms > INSTANT_MS) return null;
  return `is_error after ${result.duration_ms ?? '?'} ms with no model usage`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [outcome, file] = process.argv.slice(2);
  let text = null;
  try {
    text = file ? readFileSync(file, 'utf8') : null;
  } catch {
    text = null;
  }
  const why = instantFailure(outcome, text);
  console.log(why ? `Claude failed instantly (${why}); retrying after a wait.` : `No retry (step outcome: ${outcome}).`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `retry=${why ? 'true' : 'false'}\n`);
}
