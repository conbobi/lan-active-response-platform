// src/hooks/useSettings.js
import { useState, useEffect, useCallback } from 'react';
import {
  getSettings,
  updateSetting,
  getRiskThresholds,
  updateRiskThresholds as apiUpdateRiskThresholds,
  getFileChangesThresholds,
  updateFileChangesThresholds as apiUpdateFileChangesThresholds,
} from '../api/settings';

const DEFAULT_SETTINGS = {
  risk_thresholds: {
    auto_isolate: 85,
    alert_with_buttons: 70,
    alert: 50,
    log: 20,
  },
  file_changes_thresholds: {
    file_changes_critical: 100,
    file_changes_elevated: 30,
  },
  auto_response_enabled: true,
  email_notifications_enabled: true,
  admin_email: 'admin@larp-soc.lan',
  telemetry_interval_sec: 5,
};

export const useSettings = () => {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const [allData, riskT, fileT] = await Promise.all([
        getSettings().catch(() => null),
        getRiskThresholds().catch(() => DEFAULT_SETTINGS.risk_thresholds),
        getFileChangesThresholds().catch(() => DEFAULT_SETTINGS.file_changes_thresholds),
      ]);

      const newSettings = { ...DEFAULT_SETTINGS };
      if (allData && typeof allData === 'object') {
        if (Array.isArray(allData)) {
          allData.forEach((item) => {
            newSettings[item.key] = item.value?.data ?? item.value;
          });
        } else {
          Object.assign(newSettings, allData);
        }
      }
      newSettings.risk_thresholds = riskT || DEFAULT_SETTINGS.risk_thresholds;
      newSettings.file_changes_thresholds = fileT || DEFAULT_SETTINGS.file_changes_thresholds;

      setSettings(newSettings);
      setError(null);
    } catch (err) {
      console.warn('Using default system settings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleUpdateSettingKey = async (key, value) => {
    setSaving(true);
    setSettings((prev) => ({ ...prev, [key]: value }));
    try {
      await updateSetting(key, value);
    } catch (err) {
      console.warn(`Setting ${key} updated locally`);
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateRiskThresholds = async (newThresholds) => {
    setSaving(true);
    const updated = { ...settings.risk_thresholds, ...newThresholds };
    setSettings((prev) => ({ ...prev, risk_thresholds: updated }));
    try {
      await apiUpdateRiskThresholds(updated);
    } catch (err) {
      console.warn('Risk thresholds updated locally');
    } finally {
      setSaving(false);
    }
  };

  const handleUpdateFileChangesThresholds = async (newThresholds) => {
    setSaving(true);
    const updated = { ...settings.file_changes_thresholds, ...newThresholds };
    setSettings((prev) => ({ ...prev, file_changes_thresholds: updated }));
    try {
      await apiUpdateFileChangesThresholds(updated);
    } catch (err) {
      console.warn('File changes thresholds updated locally');
    } finally {
      setSaving(false);
    }
  };

  return {
    settings,
    loading,
    saving,
    error,
    refreshSettings: loadSettings,
    updateSettingKey: handleUpdateSettingKey,
    updateRiskThresholds: handleUpdateRiskThresholds,
    updateFileChangesThresholds: handleUpdateFileChangesThresholds,
  };
};

export default useSettings;
