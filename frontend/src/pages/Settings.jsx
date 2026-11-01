import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import useSettings from '../hooks/useSettings';
import Button from '../components/ui/Button';
import Whitelist from './Whitelist';
import Notifications from './Notifications';
import Reports from './Reports';
import DockerMonitorTable from '../components/ui/DockerMonitorTable';
import { getDockerStatus } from '../api/docker';
import {
  FiSave,
  FiShield,
  FiSliders,
  FiFileText,
  FiCheckSquare,
  FiBell,
  FiActivity,
  FiServer,
  FiRotateCw,
} from 'react-icons/fi';

const SETTINGS_TABS = [
  { id: 'thresholds', label: 'Thresholds & Automation', icon: FiSliders },
  { id: 'whitelist', label: 'Process & IP Exclusions', icon: FiCheckSquare },
  { id: 'notifications', label: 'Alert Channels & Webhooks', icon: FiBell },
  { id: 'reports', label: 'Executive Reports', icon: FiFileText },
  { id: 'system', label: 'System & Docker Health', icon: FiActivity },
];

export default function Settings({ initialTab }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryTab = searchParams.get('tab') || initialTab || 'thresholds';
  const [activeTab, setActiveTab] = useState(queryTab);

  useEffect(() => {
    if (queryTab && queryTab !== activeTab) {
      setActiveTab(queryTab);
    }
  }, [queryTab]);

  const switchTab = (tabId) => {
    setActiveTab(tabId);
    setSearchParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('tab', tabId);
      return p;
    });
  };

  // Settings hook
  const {
    settings,
    loading: settingsLoading,
    saving,
    updateSettingKey,
    updateRiskThresholds,
    updateFileChangesThresholds,
  } = useSettings();

  const [incidentCreationThreshold, setIncidentCreationThreshold] = useState(50);
  const [autoKillThreshold, setAutoKillThreshold] = useState(85);
  const [autoIsolate, setAutoIsolate] = useState(85);
  const [alertWithButtons, setAlertWithButtons] = useState(70);
  const [alertThreshold, setAlertThreshold] = useState(50);
  const [logThreshold, setLogThreshold] = useState(20);

  const [fileCritical, setFileCritical] = useState(100);
  const [fileElevated, setFileElevated] = useState(30);

  const [autoResponse, setAutoResponse] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [adminEmail, setAdminEmail] = useState('admin@larp-soc.lan');
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Docker status state for System Health tab
  const [dockerContainers, setDockerContainers] = useState([]);
  const [dockerLoading, setDockerLoading] = useState(false);
  const [dockerError, setDockerError] = useState(null);

  const fetchDocker = async () => {
    setDockerLoading(true);
    setDockerError(null);
    try {
      const data = await getDockerStatus();
      setDockerContainers(data.containers || []);
    } catch (err) {
      setDockerError(err.message || 'Failed to fetch container telemetry');
    } finally {
      setDockerLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'system') {
      fetchDocker();
    }
  }, [activeTab]);

  useEffect(() => {
    if (settings && settings.risk_thresholds) {
      setIncidentCreationThreshold(settings.risk_thresholds.incident_creation_threshold ?? 50);
      setAutoKillThreshold(settings.risk_thresholds.auto_kill_threshold ?? 85);
      setAutoIsolate(settings.risk_thresholds.auto_isolate ?? 85);
      setAlertWithButtons(settings.risk_thresholds.alert_with_buttons ?? 70);
      setAlertThreshold(settings.risk_thresholds.alert ?? 50);
      setLogThreshold(settings.risk_thresholds.log ?? 20);
    }
    if (settings && settings.file_changes_thresholds) {
      setFileCritical(settings.file_changes_thresholds.file_changes_critical ?? 100);
      setFileElevated(settings.file_changes_thresholds.file_changes_elevated ?? 30);
    }
    if (settings) {
      setAutoResponse(settings.auto_response_enabled ?? true);
      setNotifyEmail(settings.email_notifications_enabled ?? true);
      setAdminEmail(settings.admin_email || 'admin@larp-soc.lan');
    }
  }, [settings]);

  const handleSaveAll = async () => {
    await updateRiskThresholds({
      incident_creation_threshold: Number(incidentCreationThreshold),
      auto_kill_threshold: Number(autoKillThreshold),
      auto_isolate: Number(autoIsolate),
      alert_with_buttons: Number(alertWithButtons),
      alert: Number(alertThreshold),
      log: Number(logThreshold),
    });
    await updateFileChangesThresholds({
      file_changes_critical: Number(fileCritical),
      file_changes_elevated: Number(fileElevated),
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', paddingBottom: '2.5rem' }}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Platform Settings & Administration</h1>
          <p className="page-subtitle">
            Configure risk thresholds, trusted process exclusions, outbound notification channels, and infrastructure telemetry
          </p>
        </div>
        {activeTab === 'thresholds' && (
          <Button variant="primary" size="md" iconLeft={<FiSave size={14} />} onClick={handleSaveAll} disabled={saving}>
            {saving ? 'Saving...' : savedSuccess ? '✓ Settings Saved' : 'Save Changes'}
          </Button>
        )}
      </div>

      {/* Settings Navigation Tabs */}
      <div style={{ display: 'flex', gap: '0.4rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem', overflowX: 'auto' }}>
        {SETTINGS_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => switchTab(tab.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.55rem 1rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                background: isActive ? 'var(--primary)' : 'transparent',
                color: isActive ? '#fff' : 'var(--text-secondary)',
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
              }}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Contents */}
      {activeTab === 'thresholds' && (
        <div style={{ maxWidth: 840 }}>
          {settingsLoading ? (
            <div className="card skeleton" style={{ height: '350px' }} />
          ) : (
            <>
              {/* Risk Thresholds Policy */}
              <Section title="Risk Threshold Escalation Policy" desc="Configure exact risk score cutoffs for automated response, incident generation, and alerts.">
                <Row label="Incident Creation Threshold" desc="Automatically generate security incident record when risk score exceeds this value (default: 50)">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <input
                      type="range"
                      min={20}
                      max={90}
                      value={incidentCreationThreshold}
                      onChange={(e) => setIncidentCreationThreshold(+e.target.value)}
                      style={{ width: 140, accentColor: 'var(--primary)' }}
                    />
                    <span style={{ fontWeight: 700, color: 'var(--primary)', minWidth: 32, textAlign: 'right' }}>{incidentCreationThreshold}</span>
                  </div>
                </Row>

                <Row label="Auto Kill Process Tree Threshold" desc="Automatically dispatch kill_process_tree command to agent when risk score exceeds this value (default: 85)">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <input
                      type="range"
                      min={50}
                      max={100}
                      value={autoKillThreshold}
                      onChange={(e) => setAutoKillThreshold(+e.target.value)}
                      style={{ width: 140, accentColor: '#ff4d4f' }}
                    />
                    <span style={{ fontWeight: 700, color: '#ff4d4f', minWidth: 32, textAlign: 'right' }}>{autoKillThreshold}</span>
                  </div>
                </Row>

                <Row label="Auto Network Isolation Threshold" desc="Automatically isolate agent network link when score exceeds this value (default: 85)">
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

              {/* File Changes Anomaly Thresholds */}
              <Section title="File Changes Anomaly Thresholds" desc="Configure file modification event count cutoffs for triggering risk anomalies.">
                <Row label="Critical File Changes Threshold" desc="Trigger maximum risk points when modified files count exceeds this number (default: 100)">
                  <input
                    type="number"
                    min="10"
                    max="10000"
                    value={fileCritical}
                    onChange={(e) => setFileCritical(+e.target.value)}
                    style={{
                      width: 100,
                      padding: '0.4rem 0.6rem',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                      fontWeight: 600,
                    }}
                  />
                </Row>

                <Row label="Elevated File Changes Threshold" desc="Trigger medium risk points when modified files count exceeds this number (default: 30)">
                  <input
                    type="number"
                    min="5"
                    max="1000"
                    value={fileElevated}
                    onChange={(e) => setFileElevated(+e.target.value)}
                    style={{
                      width: 100,
                      padding: '0.4rem 0.6rem',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                      fontWeight: 600,
                    }}
                  />
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
            </>
          )}
        </div>
      )}

      {activeTab === 'whitelist' && (
        <Whitelist embedded={true} />
      )}

      {activeTab === 'notifications' && (
        <Notifications embedded={true} />
      )}

      {activeTab === 'reports' && (
        <Reports embedded={true} />
      )}

      {activeTab === 'system' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Backend Microservices & Docker Infrastructure Telemetry
            </span>
            <Button
              variant="outline"
              size="sm"
              iconLeft={<FiRotateCw size={14} className={dockerLoading ? 'spin' : ''} />}
              onClick={fetchDocker}
            >
              Refresh Containers
            </Button>
          </div>
          <DockerMonitorTable
            containers={dockerContainers}
            loading={dockerLoading}
            error={dockerError}
            onRefresh={fetchDocker}
          />
        </div>
      )}
    </div>
  );
}
