// Pure Decision Trace model shared by the AI Rule Generator and the AI Risk Analyst views.
// Everything shown comes from backend events; nothing here invents a stage or a timer.

export const TERMINAL_EVENTS = new Set([
  'run_completed', 'run_failed', 'clarification_required',
  // rows written before the generic orchestrator
  'analysis_completed', 'analysis_failed',
]);
export const TERMINAL_RUN_STATUSES = new Set(['COMPLETED', 'FAILED', 'TIMEOUT', 'CANCELLED', 'NEEDS_CLARIFICATION']);

const LEGACY = {
  analysis_started: 'run_started',
  model_answer_delta: 'answer_delta',
  analysis_completed: 'run_completed',
  analysis_failed: 'run_failed',
};

const THINK_BLOCK = /<think>[\s\S]*?(<\/think>|$)/gi;
/** Defence in depth: the backend already strips model thinking; the UI never renders it either. */
export function scrubThinking(value, depth = 0) {
  if (typeof value === 'string') return value.replace(THINK_BLOCK, '').replace(/<\/?think>/gi, '');
  if (depth > 6 || value == null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => scrubThinking(item, depth + 1));
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrubThinking(v, depth + 1)]));
}

export const eventType = (ev) => LEGACY[ev?.event_type] || ev?.event_type;
export const isTerminalEvent = (ev) => TERMINAL_EVENTS.has(ev?.event_type) || TERMINAL_EVENTS.has(eventType(ev));

/** Merge events by sequence (dedupe on reconnect replays), sorted. */
export function mergeEvents(previous, incoming) {
  const bySeq = new Map();
  for (const ev of [...(previous || []), ...(incoming || [])]) {
    if (ev && Number.isFinite(Number(ev.sequence))) bySeq.set(Number(ev.sequence), scrubThinking(ev));
  }
  return [...bySeq.values()].sort((a, b) => a.sequence - b.sequence);
}

/**
 * One card per executed stage, in the order the backend ran them. A stage that runs again
 * (a revision after a failed verification) gets its own card with attempt = 2, 3, ...
 */
export function buildStageCards(events) {
  const cards = [];
  const open = new Map();
  const counts = new Map();
  const deltas = [];
  for (const ev of events || []) {
    const type = eventType(ev);
    if (type === 'answer_delta') {
      deltas.push(ev);
      const host = open.get(ev.stage) || [...cards].reverse().find((c) => c.stage === ev.stage);
      if (host) host.deltas.push(ev);
      continue;
    }
    if (!ev.stage || ev.stage === 'RUN') continue;
    if (type === 'run_started') continue;
    if (type === 'stage_started' || !open.has(ev.stage)) {
      const attempt = (counts.get(ev.stage) || 0) + 1;
      counts.set(ev.stage, attempt);
      const card = { key: `${ev.stage}-${attempt}`, stage: ev.stage, attempt, event: ev, started: ev, deltas: [] };
      cards.push(card);
      if (type === 'stage_started') {
        open.set(ev.stage, card);
        continue;
      }
    }
    const card = open.get(ev.stage) || cards[cards.length - 1];
    card.event = ev;
    open.delete(ev.stage);
  }
  return { cards, deltas };
}

/** Run status as the backend reports it; the stream state only says whether we are still connected. */
export function runStatus(run, events) {
  const last = [...(events || [])].reverse().find((ev) => isTerminalEvent(ev));
  if (last) return last.status;
  return run?.status || (events?.length ? 'RUNNING' : null);
}

/**
 * Follow a run: replay from the cursor, then live events; reconnect with Last-Event-ID after a
 * dropped connection until a terminal event or terminal run status arrives.
 * deps: { stream(runId, opts) → Promise, snapshot(runId) → Promise<{run, events}>, wait(ms) → Promise }
 */
export async function followRun(runId, { onEvents, onRun, signal, maxReconnects = 5, afterSequence = 0 } = {}, deps) {
  let cursor = afterSequence;
  let finished = false;
  for (let attempt = 0; attempt <= maxReconnects && !finished && !signal?.aborted; attempt += 1) {
    if (attempt > 0) {
      await deps.wait(Math.min(8000, 500 * 2 ** (attempt - 1)));
      if (signal?.aborted) return 'aborted';
      // Fill anything missed while disconnected, from the persisted trace.
      const snap = await deps.snapshot(runId).catch(() => null);
      if (snap?.run) onRun?.(snap.run);
      const missed = (snap?.events || []).filter((ev) => ev.sequence > cursor);
      if (missed.length) {
        cursor = missed[missed.length - 1].sequence;
        onEvents?.(missed);
      }
      if (missed.some(isTerminalEvent) || TERMINAL_RUN_STATUSES.has(snap?.run?.status)) return 'done';
    }
    let error = null;
    await deps.stream(runId, {
      afterSequence: cursor,
      signal,
      onEvent: (ev) => {
        if (ev.sequence > cursor) cursor = ev.sequence;
        onEvents?.([ev]);
        if (isTerminalEvent(ev)) finished = true;
      },
      onError: (err) => { error = err; },
      onClose: () => {},
    });
    if (finished) return 'done';
    if (error?.status && [401, 403, 404].includes(error.status)) return 'denied';
  }
  return signal?.aborted ? 'aborted' : finished ? 'done' : 'gave_up';
}

export const CERTAINTY_LABELS = {
  OBSERVED: { label: 'Quan sát trực tiếp', color: '#10b981' },
  CORRELATED: { label: 'Liên kết đa nguồn', color: '#3b82f6' },
  INFERRED: { label: 'Suy luận', color: '#a855f7' },
  UNKNOWN: { label: 'Chưa xác minh', color: '#94a3b8' },
};
