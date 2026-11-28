import { useEffect, useState } from 'react';
import { getRunTrace, streamRunTrace } from '../api/threatMemory';
import { followRun, mergeEvents, runStatus, scrubThinking, TERMINAL_RUN_STATUSES } from '../components/ai/traceModel';

const readKey = (key) => (key ? sessionStorage.getItem(key) : null);
const EMPTY = { id: null, run: null, events: [], streaming: false, error: null };

/**
 * Follow one Decision Trace run: load the persisted trace, stream the rest, reconnect with the last
 * sequence after a drop. The run id is kept in sessionStorage under ``persistKey`` so a reload
 * reattaches to the same run instead of starting a new one. Hiding the panel never calls this again.
 */
export default function useRunTrace(persistKey) {
  const [key, setKey] = useState(persistKey);
  const [runId, setRunId] = useState(() => readKey(persistKey));
  const [data, setData] = useState(EMPTY);

  if (key !== persistKey) { // another incident: follow the run stored for it
    setKey(persistKey);
    setRunId(readKey(persistKey));
  }

  const attach = (id) => {
    if (persistKey) {
      if (id) sessionStorage.setItem(persistKey, id);
      else sessionStorage.removeItem(persistKey);
    }
    setRunId(id || null);
  };

  useEffect(() => {
    if (!runId) return undefined;
    const controller = new AbortController();
    const { signal } = controller;
    const update = (patch) => {
      if (signal.aborted) return;
      setData((prev) => {
        const base = prev.id === runId ? prev : { ...EMPTY, id: runId };
        return { ...base, ...patch(base) };
      });
    };
    (async () => {
      try {
        const snap = await getRunTrace(runId);
        update(() => ({ run: scrubThinking(snap.run), events: mergeEvents([], snap.events), error: null }));
        if (signal.aborted || TERMINAL_RUN_STATUSES.has(snap.run?.status)) return;
        update(() => ({ streaming: true }));
        const outcome = await followRun(runId, {
          signal,
          afterSequence: (snap.events || []).at(-1)?.sequence || 0,
          onRun: (run) => update(() => ({ run: scrubThinking(run) })),
          onEvents: (batch) => update((prev) => ({ events: mergeEvents(prev.events, batch) })),
        }, {
          stream: streamRunTrace,
          snapshot: getRunTrace,
          wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
        });
        if (signal.aborted) return;
        const final = await getRunTrace(runId).catch(() => null);
        update((prev) => ({
          run: final?.run ? scrubThinking(final.run) : prev.run,
          events: mergeEvents(prev.events, final?.events || []),
          streaming: false,
          error: outcome === 'gave_up' ? 'Mất kết nối luồng phân tích; trạng thái bên dưới là bản đã lưu gần nhất.'
            : outcome === 'denied' ? 'Không có quyền xem phiên phân tích này.' : null,
        }));
      } catch (err) {
        update(() => ({ streaming: false, error: err?.message || 'Không tải được phiên phân tích' }));
      }
    })();
    return () => controller.abort();
  }, [runId]);

  const current = data.id === runId ? data : EMPTY;
  return {
    runId,
    run: current.run,
    events: current.events,
    streaming: current.streaming,
    error: current.error,
    status: runId ? runStatus(current.run, current.events) : null,
    attach,
  };
}
