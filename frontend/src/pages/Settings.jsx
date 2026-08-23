// src/pages/Settings.jsx
import React, { useState, useEffect } from 'react';
import useSettings from '../hooks/useSettings';
import Button from '../components/ui/Button';
import { FiSave, FiShield, FiSliders, FiCheckCircle } from 'react-icons/fi';

export default function Settings() {
  const { settings, loading, saving, refreshSettings, updateSettingKey, updateRiskThresholds } = useSettings();

  const [autoIsolate, setAutoIsolate] = useState(85);
  const [alertWithButtons, setAlertWithButtons] = useState(70);
  const [alertThreshold, setAlertThreshold] = useState(50);
  const [logThreshold, setLogThreshold] = useState(20);

  const [autoResponse, setAutoResponse] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [adminEmail, setAdminEmail] = useState('admin@larp-soc.lan');
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    if (settings && settings.risk_thresholds) {
      setAutoIsolate(settings.risk_thresholds.auto_isolate ?? 85);
      setAlertWithButtons(settings.risk_thresholds.alert_with_buttons ?? 70);
      setAlertThreshold(settings.risk_thresholds.alert ?? 50);
      setLogThreshold(settings.risk_thresholds.log ?? 20);
    }
    if (settings) {
      setAutoResponse(settings.auto_response_enabled ?? true);
      setNotifyEmail(settings.email_notifications_enabled ?? true);
      setAdminEmail(settings.admin_email || 'admin@larp-soc.lan');
    }
  }, [settings]);

  const handleSaveAll = async () => {
    await updateRiskThresholds({
      auto_isolate: Number(autoIsolate),
      alert_with_buttons: Number(alertWithButtons),
      alert: Number(alertThreshold),
      log: Number(logThreshold),
    });
    await updateSettingKey('auto_response_enabled', autoResponse);
    await updateSettingKey('email_notifications_enabled', notifyEmail);
    await updateSettingKey('admin_email', adminEmail);

    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const Section = ({ title, desc, children }) => (
    <div className="card settings-section" style={{ marginBottom: '1.25rem' }}>
      <div className="settings-section-title">{title}</div>
      <div className="settings-section-desc">{desc}</div>
      {children}
    </div>
  );

  const Row = ({ label, desc, children }) => (
    <div className="settings-row">
      <div>
        <div className="settings-row-label">{label}</div>
        {desc && <div className="settings-row-desc">{desc}</div>}
      </div>
      {children}
    </div>
  );

  if (loading) {
    return (
      <div style={{ maxWidth: 720 }}>
        <div className="page-header">
          <h1 className="page-title">SOC Platform Settings</h1>
        </div>
        <div className="card skeleton" style={{ height: '400px' }} />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 720 }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">SOC Platform Settings</h1>
          <p className="page-subtitle">Configure risk escalation thresholds, automated response policies, and notifications</p>
        </div>
        <Button variant="primary" size="md" iconLeft={<FiSave size={14} />} onClick={handleSaveAll} disabled={saving}>
          {saving ? 'Saving...' : savedSuccess ? '✓ Settings Saved' : 'Save Changes'}
        </Button>
      </div>

      {/* Risk Thresholds Policy */}
      <Section title="Risk Threshold Escalation Policy" desc="Configure exact risk score cutoffs for automated response and alerts.">
        <Row label="Auto Isolation Threshold" desc="Automatically isolate agent network link when score exceeds this value">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <input
              type="range"
              min={50}
              max={100}
              value={autoIsolate}
              onChange={(e) => setAutoIsolate(+e.target.value)}
              style={{ width: 140, accentColor: 'var(--error)' }}
            />
            <span style={{ fontWeight: 700, color: 'var(--error)', minWidth: 32, textAlign: 'right' }}>{autoIsolate}</span>
          </div>
        </Row>

        <Row label="Interactive Alert with Action Buttons" desc="Trigger high-priority alert with instant 'Isolate' and 'Kill' buttons">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <input
              type="range"
              min={30}
              max={90}
              value={alertWithButtons}
              onChange={(e) => setAlertWithButtons(+e.target.value)}
              style={{ width: 140, accentColor: 'var(--warning)' }}
            />
            <span style={{ fontWeight: 700, color: 'var(--warning)', minWidth: 32, textAlign: 'right' }}>{alertWithButtons}</span>
          </div>
        </Row>

        <Row label="Standard Alert Threshold" desc="Create standard alert entry in SOC dashboard">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <input
              type="range"
              min={10}
              max={80}
              value={alertThreshold}
              onChange={(e) => setAlertThreshold(+e.target.value)}
              style={{ width: 140, accentColor: 'var(--primary)' }}
            />
            <span style={{ fontWeight: 700, color: 'var(--primary)', minWidth: 32, textAlign: 'right' }}>{alertThreshold}</span>
          </div>
        </Row>

        <Row label="Telemetry Log Threshold" desc="Log low risk telemetry events for background auditing">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <input
              type="range"
              min={0}
              max={50}
              value={logThreshold}
              onChange={(e) => setLogThreshold(+e.target.value)}
              style={{ width: 140, accentColor: 'var(--text-secondary)' }}
            />
            <span style={{ fontWeight: 700, color: 'var(--text-secondary)', minWidth: 32, textAlign: 'right' }}>{logThreshold}</span>
          </div>
        </Row>
      </Section>

      {/* Automation & Notification Settings */}
      <Section title="Automated Defense & Notifications" desc="Control automatic active response actions and admin dispatch email.">
        <Row label="Automated Active Response" desc="Permit backend manager to auto-isolate agents matching auto_isolate threshold">
          <label className="switch">
            <input type="checkbox" checked={autoResponse} onChange={(e) => setAutoResponse(e.target.checked)} />
            <span className="switch-slider" />
          </label>
        </Row>

        <Row label="Email Notifications Dispatch" desc="Send critical incident emails directly to Security Operations Center team">
          <label className="switch">
            <input type="checkbox" checked={notifyEmail} onChange={(e) => setNotifyEmail(e.target.checked)} />
            <span className="switch-slider" />
          </label>
        </Row>

        <Row label="SOC Admin Email" desc="Primary recipient address for critical alerts and report dispatches">
          <input
            type="email"
            value={adminEmail}
            onChange={(e) => setAdminEmail(e.target.value)}
            style={{
              width: 240,
              padding: '0.45rem 0.65rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
            }}
          />
        </Row>
      </Section>
    </div>
  );
}
