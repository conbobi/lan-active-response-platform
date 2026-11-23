import { useCallback, useEffect, useRef, useState } from 'react';
import api from '../api/api';
import { useDashboardSocket } from './useDashboardSocket';

const UPDATES = new Set([
  'ACTIVITY_UPDATED', 'dead_agent', 'AGENT_DELETED', 'INCIDENT_NEW',
  'INCIDENT_CREATED', 'INCIDENT_RESOLVED', 'INCIDENT_STATUS_CHANGED',
]);

export function useDashboardSummary() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [snapshotReady, setSnapshotReady] = useState(false);
  const request = useRef(null);
  const timer = useRef(null);
  const rerun = useRef(false);
  const mounted = useRef(false);
  const versions = useRef(new Map());

  const refresh = useCallback(async () => {
    if (!mounted.current) return;
    if (request.current) {
      rerun.current = true;
      return;
    }
    const controller = new AbortController();
    request.current = controller;
    try {
      const snapshot = await api.get('/dashboard/summary', { signal: controller.signal });
      if (!controller.signal.aborted) {
        setSummary({ ...snapshot, browserClockOffset: Date.parse(snapshot.as_of) - Date.now() });
        setError(null);
        setSnapshotReady(true);
      }
    } catch (err) {
      if (!controller.signal.aborted) setError(err);
    } finally {
      if (request.current === controller) request.current = null;
      if (!controller.signal.aborted) {
        setLoading(false);
        if (rerun.current && !timer.current) timer.current = setTimeout(() => {
          timer.current = null;
          rerun.current = false;
          refresh();
        }, 2500);
      }
    }
  }, []);

  const onEvent = useCallback((message) => {
    if (!UPDATES.has(message.type || message.event)) return;
    if (message.version) {
      const key = `${message.agent_id}:${message.stream}`;
      if (versions.current.get(key) >= message.version) return;
      if (versions.current.size >= 1024) versions.current.clear();
      versions.current.set(key, message.version);
    }
    if (!timer.current) timer.current = setTimeout(() => {
      timer.current = null;
      rerun.current = false;
      refresh();
    }, 2500);
  }, [refresh]);

  const resync = useCallback(() => {
    setSnapshotReady(false);
    request.current?.abort();
    request.current = null;
    refresh();
  }, [refresh]);
  const { isConnected } = useDashboardSocket(onEvent, resync);
  useEffect(() => {
    mounted.current = true;
    refresh();
    const recovery = setInterval(refresh, 60000);
    return () => {
      mounted.current = false;
      clearInterval(recovery);
      clearTimeout(timer.current);
      timer.current = null;
      rerun.current = false;
      request.current?.abort();
      request.current = null;
    };
  }, [refresh]);
  return { summary, error, loading, isConnected, snapshotReady, refresh };
}
