// src/pages/RiskAssessment.jsx
import React, { useState, useMemo, useEffect } from 'react';
import useRiskAssessment from '../hooks/useRiskAssessment';
import { useAgents } from '../hooks/useAgents';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import RiskGauge from '../components/ui/RiskGauge';
import { FiActivity, FiShield, FiAlertTriangle, FiCheckCircle, FiZap, FiRefreshCw } from 'react-icons/fi';

const PRESETS = {
  RANSOMWARE: {
    cpu_usage: 94.5,
    file_changes_count: 350,
    suspicious_commands: true,
    shadow_copy_deletion: true,
    registry_changes: true,
    credential_access_events: true,
    lateral_movement_events: false,
    mass_file_modification: true,
    dns_queries: ['dga-random-x921.org', 'tor-exit.node.net'],
    process_list_json: JSON.stringify(
      [
        { name: 'vssadmin.exe', pid: 4102, is_suspicious: true, hash: '8f34b2c12a89', path: 'C:\\Windows\\System32\\vssadmin.exe' },
        { name: 'enc_payload.exe', pid: 5890, is_suspicious: true, hash: '7c8d9e0f1a2b', path: 'C:\\Users\\Public\\enc_payload.exe' },
      ],
      null,
      2
    ),
    network_conn_json: JSON.stringify(
      [
        { dst_ip: '185.220.101.5', dst_port: 443, is_suspicious: true },
        { dst_ip: '192.168.1.1', dst_port: 53, is_suspicious: false },
      ],
      null,
      2
    ),
  },
  PRIVILEGE_ESC: {
    cpu_usage: 45.0,
    file_changes_count: 15,
    suspicious_commands: true,
    shadow_copy_deletion: false,
    registry_changes: true,
    credential_access_events: true,
    lateral_movement_events: true,
    mass_file_modification: false,
    dns_queries: ['internal-dc.lan'],
    process_list_json: JSON.stringify(
      [
        { name: 'mimikatz.exe', pid: 3201, is_suspicious: true, hash: 'a1b2c3d4e5f6', path: 'C:\\Temp\\mimikatz.exe' },
        { name: 'psexec.exe', pid: 3290, is_suspicious: true, hash: 'f6e5d4c3b2a1', path: 'C:\\Temp\\psexec.exe' },
      ],
      null,
      2
    ),
    network_conn_json: JSON.stringify(
      [{ dst_ip: '192.168.1.10', dst_port: 445, is_suspicious: true }],
      null,
      2
    ),
  },
  CLEAN: {
    cpu_usage: 12.3,
    file_changes_count: 2,
    suspicious_commands: false,
    shadow_copy_deletion: false,
    registry_changes: false,
    credential_access_events: false,
    lateral_movement_events: false,
    mass_file_modification: false,
    dns_queries: ['google.com', 'github.com'],
    process_list_json: JSON.stringify(
      [{ name: 'node', pid: 1204, is_suspicious: false, hash: 'clean_hash', path: '/usr/bin/node' }],
      null,
      2
    ),
    network_conn_json: JSON.stringify(
      [{ dst_ip: '142.250.190.46', dst_port: 443, is_suspicious: false }],
      null,
      2
    ),
  },
};

export default function RiskAssessment() {
  const { agents } = useAgents();
  const { loading, riskResult, history, evaluateRisk, fetchRiskHistory } = useRiskAssessment();

  const [selectedAgent, setSelectedAgent] = useState('');

  // Form states
  const [cpuUsage, setCpuUsage] = useState(25.0);
  const [fileChangesCount, setFileChangesCount] = useState(5);
  const [suspiciousCommands, setSuspiciousCommands] = useState(false);
  const [shadowCopyDeletion, setShadowCopyDeletion] = useState(false);
  const [registryChanges, setRegistryChanges] = useState(false);
  const [credentialAccessEvents, setCredentialAccessEvents] = useState(false);
  const [lateralMovementEvents, setLateralMovementEvents] = useState(false);
  const [massFileModification, setMassFileModification] = useState(false);

  const [processListJson, setProcessListJson] = useState('[]');
  const [networkConnJson, setNetworkConnJson] = useState('[]');

  useEffect(() => {
    if (agents.length > 0 && !selectedAgent) {
      setSelectedAgent(agents[0].id);
    }
  }, [agents, selectedAgent]);

  useEffect(() => {
    if (selectedAgent) {
      fetchRiskHistory(selectedAgent);
    }
  }, [selectedAgent, fetchRiskHistory]);

  const agentOptions = useMemo(() => {
    return agents.map((a) => ({
      value: a.id,
      label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
    }));
  }, [agents]);

  const loadPreset = (presetKey) => {
    const data = PRESETS[presetKey];
    if (!data) return;
    setCpuUsage(data.cpu_usage);
    setFileChangesCount(data.file_changes_count);
    setSuspiciousCommands(data.suspicious_commands);
    setShadowCopyDeletion(data.shadow_copy_deletion);
    setRegistryChanges(data.registry_changes);
    setCredentialAccessEvents(data.credential_access_events);
    setLateralMovementEvents(data.lateral_movement_events);
    setMassFileModification(data.mass_file_modification);
    setProcessListJson(data.process_list_json);
    setNetworkConnJson(data.network_conn_json);
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    if (!selectedAgent) return;

    let processList = [];
    let networkConnections = [];

    try {
      processList = JSON.parse(processListJson);
    } catch (err) {
      processList = [];
    }

    try {
      networkConnections = JSON.parse(networkConnJson);
    } catch (err) {
      networkConnections = [];
    }

    const payload = {
      agent_id: selectedAgent,
      cpu_usage: Number(cpuUsage),
      file_changes_count: Number(fileChangesCount),
      suspicious_commands: Boolean(suspiciousCommands),
      shadow_copy_deletion: Boolean(shadowCopyDeletion),
      registry_changes: Boolean(registryChanges),
      credential_access_events: Boolean(credentialAccessEvents),
      lateral_movement_events: Boolean(lateralMovementEvents),
      mass_file_modification: Boolean(massFileModification),
      process_list: processList,
      network_connections: networkConnections,
      dns_queries: ['soc-telemetry.lan'],
    };

    await evaluateRisk(payload);
    fetchRiskHistory(selectedAgent);
  };

  const currentScore = riskResult ? Math.round(riskResult.score || riskResult.risk_score || 0) : 0;
  const factors = riskResult?.factors || riskResult?.triggered_rules || [];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Risk Assessment Engine</h1>
          <p className="page-subtitle">Evaluate agent behavioral telemetry against 13 detection risk rules in real-time</p>
        </div>
      </div>

      {/* Quick Scenario Presets */}
      <div className="card" style={{ padding: '0.85rem 1.25rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Quick Telemetry Presets:</span>
        <Button variant="danger" size="sm" iconLeft={<FiZap size={14} />} onClick={() => loadPreset('RANSOMWARE')}>
          Ransomware Burst
        </Button>
        <Button variant="warning" size="sm" iconLeft={<FiAlertTriangle size={14} />} onClick={() => loadPreset('PRIVILEGE_ESC')}>
          Privilege Escalation
        </Button>
        <Button variant="outline" size="sm" iconLeft={<FiCheckCircle size={14} />} onClick={() => loadPreset('CLEAN')}>
          Normal Telemetry
        </Button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* Form Input Card */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiActivity color="var(--primary)" /> Agent Telemetry Payload
          </h3>

          <form onSubmit={handleFormSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <Dropdown
              label="Target Agent"
              options={agentOptions}
              value={selectedAgent}
              onChange={setSelectedAgent}
            />

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
                  CPU Usage (%): <strong>{cpuUsage}%</strong>
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={cpuUsage}
                  onChange={(e) => setCpuUsage(e.target.value)}
                  style={{ width: '100%', accentColor: 'var(--primary)' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
                  File Changes Count
                </label>
                <input
                  type="number"
                  min="0"
                  value={fileChangesCount}
                  onChange={(e) => setFileChangesCount(e.target.value)}
                  style={{ width: '100%', padding: '0.45rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', outline: 'none' }}
                />
              </div>
            </div>

            {/* Checkbox Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem', background: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={shadowCopyDeletion} onChange={(e) => setShadowCopyDeletion(e.target.checked)} />
                <span>Shadow Copy Deletion</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={suspiciousCommands} onChange={(e) => setSuspiciousCommands(e.target.checked)} />
                <span>Suspicious Commands</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={registryChanges} onChange={(e) => setRegistryChanges(e.target.checked)} />
                <span>Registry Run Keys</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={credentialAccessEvents} onChange={(e) => setCredentialAccessEvents(e.target.checked)} />
                <span>Credential Dumping</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={lateralMovementEvents} onChange={(e) => setLateralMovementEvents(e.target.checked)} />
                <span>Lateral Movement</span>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={massFileModification} onChange={(e) => setMassFileModification(e.target.checked)} />
                <span>Mass File Modification</span>
              </label>
            </div>

            {/* JSON editors */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <label style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Process List (JSON Array)</label>
              <textarea
                rows={3}
                value={processListJson}
                onChange={(e) => setProcessListJson(e.target.value)}
                style={{ width: '100%', padding: '0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '0.78rem' }}
              />
            </div>

            <Button variant="primary" type="submit" disabled={loading} iconLeft={<FiShield size={16} />}>
              {loading ? 'Evaluating...' : 'Evaluate Risk Score'}
            </Button>
          </form>
        </div>

        {/* Result Evaluation Output Card */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield color="var(--primary)" /> Evaluation Result & Risk Factors
          </h3>

          {!riskResult ? (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)' }}>
              <FiShield size={48} style={{ opacity: 0.2, marginBottom: '0.75rem' }} />
              <span>Select an agent and submit telemetry payload to compute risk score.</span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Gauge display */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                <RiskGauge value={currentScore} />
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Computed Risk Level:</span>
                  <Badge
                    status={currentScore >= 80 ? 'critical' : currentScore >= 50 ? 'warning' : 'online'}
                    label={currentScore >= 80 ? 'CRITICAL RISK' : currentScore >= 50 ? 'HIGH RISK' : 'LOW RISK'}
                  />
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.3rem' }}>
                    Evaluated at: {new Date().toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {/* Triggered Factors List */}
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  Triggered Risk Factors ({factors.length})
                </h4>
                {factors.length === 0 ? (
                  <div style={{ fontSize: '0.85rem', color: 'var(--success)', background: 'rgba(0,192,123,0.08)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                    ✓ No malicious risk factors detected in this telemetry payload.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: 240, overflowY: 'auto' }}>
                    {factors.map((factor, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '0.65rem 0.85rem',
                          background: 'rgba(239,68,68,0.06)',
                          border: '1px solid rgba(239,68,68,0.2)',
                          borderRadius: 'var(--radius-sm)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <div>
                          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--error)' }}>
                            {factor.rule_name || factor.rule_id || factor.name || `Factor #${idx + 1}`}
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                            {factor.description || factor.reason || 'Threshold triggered'}
                          </div>
                        </div>
                        <Badge status="critical" label={`+${factor.weight || factor.score || 20}`} showDot={false} />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
