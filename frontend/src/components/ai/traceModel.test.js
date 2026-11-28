import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildStageCards, followRun, isTerminalEvent, mergeEvents, runStatus } from './traceModel.js';

const ev = (sequence, event_type, stage, status, extra = {}) => ({ sequence, event_type, stage, status, ...extra });

test('stage cards follow backend order and a revised stage gets its own card', () => {
  const events = [
    ev(1, 'run_started', 'RUN', 'RUNNING'),
    ev(2, 'stage_started', 'ANSWER_GENERATION', 'RUNNING'),
    ev(3, 'stage_completed', 'ANSWER_GENERATION', 'COMPLETED'),
    ev(4, 'stage_started', 'ANSWER_VERIFICATION', 'RUNNING'),
    ev(5, 'stage_failed', 'ANSWER_VERIFICATION', 'FAILED'),
    ev(6, 'stage_started', 'ANSWER_GENERATION', 'RUNNING'),
    ev(7, 'stage_completed', 'ANSWER_GENERATION', 'COMPLETED'),
    ev(8, 'stage_skipped', 'PROCESS_NETWORK_CORRELATION', 'SKIPPED'),
    ev(9, 'answer_delta', 'RESULT_SYNTHESIS', 'RUNNING', { summary: 'kết luận' }),
    ev(10, 'run_completed', 'RUN', 'COMPLETED'),
  ];
  const { cards, deltas } = buildStageCards(events);
  assert.deepEqual(cards.map((c) => [c.key, c.event.status]), [
    ['ANSWER_GENERATION-1', 'COMPLETED'],
    ['ANSWER_VERIFICATION-1', 'FAILED'],
    ['ANSWER_GENERATION-2', 'COMPLETED'],
    ['PROCESS_NETWORK_CORRELATION-1', 'SKIPPED'],
  ]);
  assert.equal(deltas.length, 1);
  assert.equal(runStatus({ status: 'RUNNING' }, events), 'COMPLETED');
});

test('status comes from the backend: a timeout is never shown as completed', () => {
  const events = [ev(1, 'run_started', 'RUN', 'RUNNING'), ev(2, 'run_failed', 'RUN', 'TIMEOUT')];
  assert.equal(runStatus({ status: 'RUNNING' }, events), 'TIMEOUT');
  assert.equal(runStatus({ status: 'RUNNING' }, [ev(1, 'run_started', 'RUN', 'RUNNING')]), 'RUNNING');
  assert.ok(isTerminalEvent(ev(3, 'clarification_required', 'CLARIFICATION', 'NEEDS_CLARIFICATION')));
  assert.ok(isTerminalEvent(ev(3, 'analysis_completed', 'RESPONSE_RECOMMENDATION', 'COMPLETED')), 'legacy rows');
});

test('reconnect resumes after the last sequence and loses nothing', async () => {
  const all = [1, 2, 3, 4, 5].map((n) => ev(n, n === 5 ? 'run_completed' : 'stage_completed', 'X', 'COMPLETED'));
  const streamCalls = [];
  let received = [all[0]]; // the caller already holds the snapshot up to sequence 1
  const outcome = await followRun('run_1', {
    afterSequence: 1,
    onEvents: (batch) => { received = mergeEvents(received, batch); },
  }, {
    stream: async (_id, { afterSequence, onEvent, onError }) => {
      streamCalls.push(afterSequence);
      if (streamCalls.length === 1) {   // first connection drops after event 2
        onEvent(all[1]);
        onError(new Error('network'));
        return;
      }
      all.filter((e) => e.sequence > afterSequence).forEach(onEvent);
    },
    snapshot: async () => ({ run: { status: 'RUNNING' }, events: all.slice(0, 3) }), // 3 was persisted meanwhile
    wait: async () => {},
  });
  assert.equal(outcome, 'done');
  assert.deepEqual(streamCalls, [1, 3]);
  assert.deepEqual(received.map((e) => e.sequence), [1, 2, 3, 4, 5]);
});

test('a denied stream stops instead of retrying forever', async () => {
  let calls = 0;
  const outcome = await followRun('run_x', {}, {
    stream: async (_id, { onError }) => { calls += 1; onError(Object.assign(new Error('forbidden'), { status: 404 })); },
    snapshot: async () => null,
    wait: async () => {},
  });
  assert.equal(outcome, 'denied');
  assert.equal(calls, 1);
});

test('model thinking never reaches rendered trace data', async () => {
  const { scrubThinking } = await import('./traceModel.js');
  const merged = mergeEvents([], [ev(1, 'stage_completed', 'X', 'COMPLETED', {
    summary: '<think>secret plan</think>Kết luận', safe_result: { notices: ['<think>unterminated'] } })]);
  assert.equal(merged[0].summary, 'Kết luận');
  assert.deepEqual(merged[0].safe_result.notices, ['']);
  assert.equal(scrubThinking({ a: ['x</think>'] }).a[0], 'x');
});
