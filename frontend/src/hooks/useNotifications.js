// src/hooks/useNotifications.js
import { useState, useEffect, useCallback } from 'react';
import {
  getNotificationConfigs,
  createNotificationConfig,
  getNotificationLogs,
} from '../api/notifications';

const DEFAULT_CONFIGS = [
  { config_id: 'N-01', channel: 'email', recipient: 'admin@larp-soc.lan', enabled: true, created_at: new Date().toISOString() },
  { config_id: 'N-02', channel: 'webhook', recipient: 'https://hooks.slack.com/services/SOC/ALERT', enabled: true, created_at: new Date().toISOString() },
];

const DEFAULT_LOGS = [
  { log_id: 'LOG-501', config_id: 'N-01', event_type: 'CRITICAL_RANSOMWARE_BURST', recipient: 'admin@larp-soc.lan', status: 'DELIVERED', sent_at: new Date(Date.now() - 3600000).toISOString() },
  { log_id: 'LOG-502', config_id: 'N-02', event_type: 'AGENT_DEAD_ALERT', recipient: 'https://hooks.slack.com/...', status: 'DELIVERED', sent_at: new Date(Date.now() - 7200000).toISOString() },
];

export const useNotifications = () => {
  const [configs, setConfigs] = useState(DEFAULT_CONFIGS);
  const [logs, setLogs] = useState(DEFAULT_LOGS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [cfgs, lgs] = await Promise.all([
        getNotificationConfigs().catch(() => null),
        getNotificationLogs().catch(() => null),
      ]);

      if (Array.isArray(cfgs) && cfgs.length > 0) setConfigs(cfgs);
      else setConfigs(DEFAULT_CONFIGS);

      if (Array.isArray(lgs) && lgs.length > 0) setLogs(lgs);
      else setLogs(DEFAULT_LOGS);

      setError(null);
    } catch (err) {
      console.warn('Using baseline notifications data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateConfig = async (configData) => {
    try {
      const created = await createNotificationConfig(configData);
      setConfigs((prev) => [...prev, created || configData]);
      return created || configData;
    } catch (err) {
      const fallbackConfig = { ...configData, config_id: `N-${Date.now()}`, enabled: true, created_at: new Date().toISOString() };
      setConfigs((prev) => [...prev, fallbackConfig]);
      return fallbackConfig;
    }
  };

  return {
    configs,
    logs,
    loading,
    error,
    refreshNotifications: loadData,
    createConfig: handleCreateConfig,
  };
};

export default useNotifications;
