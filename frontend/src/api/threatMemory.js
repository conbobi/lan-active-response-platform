// AI Threat Memory & Decision Trace API + authenticated SSE streaming client.
import api, { BASE_URL, refreshAccessToken } from './api.js';
import { readSession } from './operatorSession.js';
import { isTerminalEvent } from '../components/ai/traceModel.js';

export const getAnalysisSource = (incidentId) => api.get(`/ai/incidents/${incidentId}/analysis-source`);
export const runAnalysis = (incidentId, mode) => api.post(`/ai/incidents/${incidentId}/analysis/run`, { mode });
export const markAnalysisIncorrect = (incidentId, reason) => api.post(`/ai/incidents/${incidentId}/analysis/incorrect`, { reason });
export const listThreatMemory = (params = {}) => api.get('/ai/threat-memory', { params });
export const threatMemoryMetrics = (days = 7) => api.get('/ai/threat-memory/metrics', { params: { days } });
export const changeThreatMemory = (id, operation, reason) => api.post(`/ai/threat-memory/${id}/${operation}`, { reason });

export const listAnalysisRuns = (incidentId, limit = 15) =>
  api.get(`/ai/incidents/${encodeURIComponent(incidentId)}/analysis/runs`, { params: { limit } });

export const askRiskAnalyst = (incidentId, question) =>
  api.post(`/ai/incidents/${encodeURIComponent(incidentId)}/questions`, { question });

export const listQuestionRuns = (incidentId, limit = 10) =>
  api.get(`/ai/incidents/${encodeURIComponent(incidentId)}/analysis/runs`, { params: { limit, task_type: 'risk_question' } });

export const startRuleAssistantRun = (body) => api.post('/rules/assistant/runs', body);

export const getRunTrace = (runId) =>
  api.get(`/ai/runs/${encodeURIComponent(runId)}/trace`);

/**
 * Connect to an authenticated SSE decision trace stream using fetch + Bearer header
 * (never passing credentials in URL query parameters) with single-flight 401 refresh.
 */
export async function streamRunTrace(
  runId,
  { afterSequence = 0, onEvent, onError, onClose, signal } = {},
) {
  let cursor = Number.isFinite(afterSequence) ? Math.max(0, afterSequence) : 0;
  let retriedAuth = false;

  const openStream = async (token) => {
    const query = cursor > 0 ? `?after_sequence=${cursor}` : '';
    const headers = {
      Accept: 'text/event-stream',
      'Cache-Control': 'no-cache',
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (cursor > 0) headers['Last-Event-ID'] = String(cursor);

    return fetch(`${BASE_URL}/ai/runs/${encodeURIComponent(runId)}/stream${query}`, {
      method: 'GET',
      credentials: 'include',
      headers,
      signal,
    });
  };

  try {
    let response = await openStream(readSession());
    if (response.status === 401 && !retriedAuth && !signal?.aborted) {
      retriedAuth = true;
      const freshToken = await refreshAccessToken();
      if (freshToken) {
        response = await openStream(freshToken);
      }
    }

    if (!response.ok || !response.body) {
      const err = new Error(`Không thể kết nối luồng trace (HTTP ${response.status})`);
      err.status = response.status;
      onError?.(err);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    const processBlock = (rawBlock) => {
      const lines = rawBlock.split(/\r?\n/);
      let eventId = null;
      const dataLines = [];

      for (const line of lines) {
        if (!line || line.startsWith(':')) continue; // SSE comment / heartbeat
        if (line.startsWith('id:')) {
          eventId = line.slice(3).trim();
        } else if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        }
      }

      if (dataLines.length === 0) return false;
      try {
        const parsed = JSON.parse(dataLines.join('\n'));
        const seq = Number(parsed?.sequence ?? eventId ?? 0);
        if (Number.isFinite(seq) && seq > cursor) {
          cursor = seq;
        }
        onEvent?.(parsed);
        return isTerminalEvent(parsed);
      } catch {
        return false;
      }
    };

    while (true) {
      if (signal?.aborted) break;
      const { value, done } = await reader.read();
      if (value) {
        buffer += decoder.decode(value, { stream: !done });
        const parts = buffer.split(/\r?\n\r?\n/);
        buffer = parts.pop() || '';
        for (const block of parts) {
          if (block.trim()) {
            const terminal = processBlock(block);
            if (terminal) {
              try {
                await reader.cancel();
              } catch {
                // Ignore cancel errors
              }
              onClose?.();
              return;
            }
          }
        }
      }
      if (done) {
        if (buffer.trim()) processBlock(buffer);
        onClose?.();
        break;
      }
    }
  } catch (err) {
    if (err?.name === 'AbortError' || signal?.aborted) return;
    onError?.(err);
  }
}
