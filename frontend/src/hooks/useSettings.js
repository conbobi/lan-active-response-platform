// src/hooks/useSettings.js
import { useState, useEffect, useCallback } from 'react';
import { getSettings, updateSetting } from '../api/settings';

const DEFAULT_SETTINGS = {
  risk_thresholds: {
    auto_isolate: 85,
    alert_with_buttons: 70,
    alert: 50,
    log: 20,
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
      const data = await getSettings();
      if (data && typeof data === 'object') {
        setSettings((prev) => ({ ...prev, ...data }));
      }
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
    const updatedThresholds = { ...settings.risk_thresholds, ...newThresholds };
    setSettings((prev) => ({ ...prev, risk_thresholds: updatedThresholds }));
    try {
      await updateSetting('risk_thresholds', updatedThresholds);
    } catch (err) {
      console.warn('Risk thresholds updated locally');
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
  };
};

export default useSettings;
