import React, { useState } from 'react';
import Button from '../components/ui/Button';
import { FiSave, FiPlus, FiTrash2 } from 'react-icons/fi';

export default function Settings() {
  const [riskThreshold, setRiskThreshold] = useState(70);
  const [autoResponse, setAutoResponse] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [whitelist, setWhitelist] = useState(['10.0.0.1', '10.0.0.2']);
  const [ipInput, setIpInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const addIp = () => {
    const ip = ipInput.trim();
    if (ip && !whitelist.includes(ip)) {
      setWhitelist((p) => [...p, ip]);
      setIpInput('');
    }
  };

  const handleSave = () => {
    setSaving(true);
    setTimeout(() => { setSaving(false); setSaved(true); setTimeout(() => setSaved(false), 2000); }, 1200);
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
    <div style={{ maxWidth: 700 }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Configure thresholds, automation and notifications</p>
        </div>
        <Button variant="primary" size="md" iconLeft={<FiSave size={14} />} onClick={handleSave} disabled={saving}>
          {saving ? 'Saving…' : saved ? '✓ Saved' : 'Save Changes'}
        </Button>
      </div>

      <Section title="Risk Thresholds" desc="Configure when alerts are triggered based on risk score.">
        <Row label="Risk Score Threshold" desc="Trigger alert when score exceeds this value">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <input type="range" min={0} max={100} value={riskThreshold} onChange={(e) => setRiskThreshold(+e.target.value)}
              style={{ width: 140, accentColor: 'var(--primary)' }} />
            <span style={{ fontWeight: 700, color: riskThreshold > 80 ? 'var(--error)' : riskThreshold > 60 ? 'var(--warning)' : 'var(--success)', minWidth: 32, textAlign: 'right' }}>{riskThreshold}</span>
          </div>
        </Row>
      </Section>

      <Section title="Automation" desc="Control automatic response actions when threats are detected.">
        <Row label="Auto-response" desc="Automatically isolate agents exceeding risk threshold">
          <label className="switch">
            <input type="checkbox" checked={autoResponse} onChange={(e) => setAutoResponse(e.target.checked)} />
            <span className="switch-slider" />
          </label>
        </Row>
        <Row label="Email Notifications" desc="Send alert emails to admin when critical events occur">
          <label className="switch">
            <input type="checkbox" checked={notifyEmail} onChange={(e) => setNotifyEmail(e.target.checked)} />
            <span className="switch-slider" />
          </label>
        </Row>
      </Section>

      <Section title="IP Whitelist" desc="IPs in this list are excluded from blocking rules.">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
          {whitelist.map((ip) => (
            <span key={ip} className="ip-tag">
              {ip}
              <span className="ip-remove" onClick={() => setWhitelist((p) => p.filter((x) => x !== ip))}>×</span>
            </span>
          ))}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && addIp()}
            placeholder="Enter IP address…"
            style={{ flex: 1, padding: '0.5rem 0.75rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontSize: '0.875rem', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none', fontFamily: 'inherit' }}
          />
          <Button variant="secondary" size="sm" iconLeft={<FiPlus size={14} />} onClick={addIp}>Add</Button>
        </div>
      </Section>
    </div>
  );
}
