// src/components/policies/PolicyDryRunPanel.jsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { useAgents } from '../../hooks/useAgents';
import { evaluatePolicy } from '../../api/policies';
import { getAgentGroups } from '../../api/groups';
import {
  FiPlay,
  FiServer,
  FiSliders,
  FiCheckCircle,
  FiAlertCircle,
  FiAlertTriangle,
  FiLayers,
  FiLock,
  FiSlash,
  FiUsers,
  FiLoader,
  FiRefreshCw,
  FiClock,
  FiShield,
  FiActivity,
  FiCheck,
  FiX,
} from 'react-icons/fi';

const getScoreSeverity = (score) => {
  if (score >= 85) return { label: 'Critical', color: '#991b1b', bg: 'rgba(153, 27, 27, 0.12)' };
  if (score >= 70) return { label: 'Severe', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.12)' };
  if (score >= 50) return { label: 'High', color: '#f97316', bg: 'rgba(249, 115, 22, 0.12)' };
  if (score >= 30) return { label: 'Moderate', color: '#eab308', bg: 'rgba(234, 179, 8, 0.12)' };
  return { label: 'Safe', color: '#10b981', bg: 'rgba(16, 185, 129, 0.12)' };
};

export default function PolicyDryRunPanel({
  isOpen,
  onClose,
  initialPolicy = null,
  initialAgentId = null,
  onApplied = null,
}) {
  const { agents } = useAgents();
  const [selectedAgentId, setSelectedAgentId] = useState(initialAgentId || '');
  const [riskScore, setRiskScore] = useState(75.0);
  const [isLiveMode, setIsLiveMode] = useState(false);
  const [agentGroups, setAgentGroups] = useState([]);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // Confirm modal for Live apply
  const [confirmLiveOpen, setConfirmLiveOpen] = useState(false);
  const [liveExecuting, setLiveExecuting] = useState(false);
  const [liveSuccessMessage, setLiveSuccessMessage] = useState('');

  // Initialize inputs on open
  useEffect(() => {
    if (!isOpen) return;
    setError('');
    setResult(null);
    setIsLiveMode(false);
    setLiveSuccessMessage('');
    setConfirmLiveOpen(false);

    // Initial agent selection
    if (initialAgentId) {
      setSelectedAgentId(initialAgentId);
    } else if (agents.length > 0 && !selectedAgentId) {
      // Default to client1 if present, or first agent
      const foundClient1 = agents.find((a) => a.id === 'client1');
      setSelectedAgentId(foundClient1 ? 'client1' : agents[0].id);
    }

    // Initial score calculation
    if (initialPolicy) {
      const mid = ((initialPolicy.min_score || 0) + (initialPolicy.max_score || 100)) / 2;
      setRiskScore(Number(mid.toFixed(1)));
    } else {
      setRiskScore(75.0);
    }
  }, [isOpen, initialPolicy, initialAgentId, agents]);

  // Fetch groups for selected agent
  useEffect(() => {
    if (!selectedAgentId) {
      setAgentGroups([]);
      return;
    }
    getAgentGroups(selectedAgentId)
      .then((grps) => setAgentGroups(Array.isArray(grps) ? grps : []))
      .catch((err) => {
        console.warn(`Failed to fetch groups for agent ${selectedAgentId}`, err);
        setAgentGroups([]);
      });
  }, [selectedAgentId]);

  // Evaluate function
  const runEvaluation = useCallback(
    async (dryRun = true) => {
      if (!selectedAgentId) {
        setError('Vui lòng chọn một agent để kiểm thử.');
        return null;
      }
      setError('');
      setLoading(true);
      try {
        const res = await evaluatePolicy({
          agent_id: selectedAgentId,
          risk_score: Number(riskScore),
          dry_run: dryRun,
        });
        setResult(res);
        return res;
      } catch (err) {
        console.error('Policy evaluation failed', err);
        const msg = err.response?.data?.detail || err.response?.data?.error || err.message || 'Đánh giá chính sách thất bại';
        setError(msg);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [selectedAgentId, riskScore]
  );

  // Auto-evaluate when agent or score changes (debounced)
  useEffect(() => {
    if (!isOpen || !selectedAgentId) return;
    const timer = setTimeout(() => {
      runEvaluation(true);
    }, 120);
    return () => clearTimeout(timer);
  }, [isOpen, selectedAgentId, riskScore, runEvaluation]);

  const severity = useMemo(() => getScoreSeverity(riskScore), [riskScore]);

  // Execute Live Apply
  const handleExecuteLive = async () => {
    setLiveExecuting(true);
    setError('');
    try {
      const res = await runEvaluation(false);
      if (res && res.executed) {
        setLiveSuccessMessage(
          `Đã kích hoạt hành động LIVE [${res.action_type?.toUpperCase()}] thành công trên ${res.simulated_actions?.length || 1} máy trạm!`
        );
        if (onApplied) onApplied(res);
      }
      setConfirmLiveOpen(false);
    } catch (err) {
      console.error('Live execution failed', err);
      setError(err.response?.data?.detail || err.message || 'Thực thi Live thất bại');
    } finally {
      setLiveExecuting(false);
    }
  };

  const getActionBadge = (actionType) => {
    switch (actionType) {
      case 'isolate':
        return <Badge status="danger" label="Isolate" showDot={true} />;
      case 'block_ip':
        return <Badge status="warning" label="Block IP" showDot={true} />;
      case 'quarantine':
        return <Badge status="info" label="Quarantine" showDot={true} />;
      case 'alert':
        return <Badge status="neutral" label="Alert Only" showDot={false} />;
      default:
        return <Badge status="neutral" label={actionType || 'Unknown'} showDot={false} />;
    }
  };

  if (!isOpen) return null;

  return (
    <>
      <Modal
        isOpen={isOpen}
        onClose={onClose}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiSliders size={20} color="var(--primary)" />
            <span style={{ fontWeight: 700, fontSize: '1.05rem', color: 'var(--text-primary)' }}>
              Response Policy Simulator & Dry-Run Panel
            </span>
          </div>
        }
        maxWidth={720}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {error && (
            <div
              style={{
                padding: '0.65rem 0.85rem',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--error, #ef4444)',
                borderRadius: 'var(--radius-sm, 4px)',
                color: 'var(--error, #ef4444)',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <FiAlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {liveSuccessMessage && (
            <div
              style={{
                padding: '0.65rem 0.85rem',
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid var(--success, #10b981)',
                borderRadius: 'var(--radius-sm, 4px)',
                color: 'var(--success, #10b981)',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <FiCheckCircle size={16} />
              <span>{liveSuccessMessage}</span>
            </div>
          )}

          {/* ========================================================================= */}
          {/* SECTION 1: INPUT CONTROLS                                                 */}
          {/* ========================================================================= */}
          <div
            style={{
              background: 'var(--bg-secondary, #f8fafc)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm, 6px)',
              padding: '1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)' }}>
                1. Thông số mô phỏng (Simulation Inputs)
              </span>

              {/* Mode Toggle: Dry-Run (safe) vs Live (warning) */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  background: 'var(--bg-primary, #ffffff)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-full, 9999px)',
                  padding: '2px',
                }}
              >
                <button
                  type="button"
                  onClick={() => setIsLiveMode(false)}
                  style={{
                    padding: '0.3rem 0.75rem',
                    border: 'none',
                    borderRadius: 'var(--radius-full, 9999px)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: !isLiveMode ? 'var(--primary, #3b82f6)' : 'transparent',
                    color: !isLiveMode ? '#ffffff' : 'var(--text-secondary)',
                    transition: 'all 0.15s',
                  }}
                >
                  (•) Dry-Run (An toàn)
                </button>

                <button
                  type="button"
                  onClick={() => setIsLiveMode(true)}
                  style={{
                    padding: '0.3rem 0.75rem',
                    border: 'none',
                    borderRadius: 'var(--radius-full, 9999px)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: isLiveMode ? 'var(--error, #ef4444)' : 'transparent',
                    color: isLiveMode ? '#ffffff' : 'var(--text-secondary)',
                    transition: 'all 0.15s',
                  }}
                >
                  (!) Live (Thực thi)
                </button>
              </div>
            </div>

            {/* Agent Select & Group Info */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
                  Target Agent (Máy trạm phát sinh sự kiện)
                </label>
                <select
                  className="input"
                  value={selectedAgentId}
                  onChange={(e) => setSelectedAgentId(e.target.value)}
                  style={{ width: '100%', fontSize: '0.85rem' }}
                >
                  {agents.map((ag) => (
                    <option key={ag.id} value={ag.id}>
                      {ag.hostname || ag.id} ({ag.id}) — {ag.ip || 'No IP'}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
                  Agent Groups trực thuộc
                </label>
                <div
                  style={{
                    padding: '0.45rem 0.65rem',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-xs, 4px)',
                    background: 'var(--bg-card, #ffffff)',
                    fontSize: '0.8rem',
                    minHeight: '36px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    flexWrap: 'wrap',
                  }}
                >
                  {agentGroups.length === 0 ? (
                    <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Không thuộc nhóm nào</span>
                  ) : (
                    agentGroups.map((g) => (
                      <span
                        key={g.id}
                        style={{
                          background: 'rgba(168, 85, 247, 0.1)',
                          color: '#a855f7',
                          padding: '0.15rem 0.45rem',
                          borderRadius: '3px',
                          fontSize: '0.725rem',
                          fontWeight: 600,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                        }}
                      >
                        <FiUsers size={11} /> {g.name}
                      </span>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Risk Score Slider with Big Visual Number and Level Badge */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Giả định Risk Score (Smoothed Score)
                </label>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      background: severity.bg,
                      color: severity.color,
                    }}
                  >
                    {severity.label}
                  </span>

                  <span
                    style={{
                      fontFamily: 'monospace',
                      fontWeight: 800,
                      fontSize: '1.25rem',
                      color: severity.color,
                      minWidth: '55px',
                      textAlign: 'right',
                    }}
                  >
                    {Number(riskScore).toFixed(1)}
                  </span>
                </div>
              </div>

              <input
                type="range"
                min="0"
                max="100"
                step="0.5"
                value={riskScore}
                onChange={(e) => setRiskScore(Number(e.target.value))}
                style={{ width: '100%', cursor: 'pointer', accentColor: severity.color }}
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
                <span>0.0 (Safe)</span>
                <span>30.0 (Alert)</span>
                <span>50.0 (Block IP)</span>
                <span>70.0 (Isolate Agent)</span>
                <span>85.0 (Isolate Group)</span>
                <span>100.0</span>
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 2: PREVIEW RESULT                                                 */}
          {/* ========================================================================= */}
          <div
            style={{
              background: 'var(--bg-secondary, #f8fafc)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm, 6px)',
              padding: '1rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)' }}>
                2. Kết quả mô phỏng đánh giá (Evaluation Preview)
              </span>

              {loading && (
                <span style={{ fontSize: '0.75rem', color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <FiLoader size={13} className="animate-spin" /> Đang tính toán...
                </span>
              )}
            </div>

            {result?.matched_policy ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {/* Matched Policy Card */}
                <div
                  style={{
                    background: 'var(--bg-card, #ffffff)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm, 4px)',
                    padding: '0.85rem 1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.5rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                          {result.matched_policy.name}
                        </span>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            padding: '0.1rem 0.4rem',
                            borderRadius: '3px',
                            background: 'rgba(59, 130, 246, 0.1)',
                            color: 'var(--primary)',
                            fontFamily: 'monospace',
                          }}
                        >
                          Priority #{result.matched_policy.priority}
                        </span>
                      </div>

                      {result.matched_policy.description && (
                        <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                          {result.matched_policy.description}
                        </div>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {getActionBadge(result.action_type || result.matched_policy.action_type)}
                      <span
                        style={{
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          background: result.scope === 'group' ? 'rgba(168, 85, 247, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                          color: result.scope === 'group' ? '#a855f7' : 'var(--primary)',
                        }}
                      >
                        SCOPE: {result.scope ? result.scope.toUpperCase() : 'AGENT'}
                      </span>
                    </div>
                  </div>

                  <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                    Trigger range: [{result.matched_policy.min_score} – {result.matched_policy.max_score}] • Auto-rollback: {result.matched_policy.auto_rollback_seconds ? `${result.matched_policy.auto_rollback_seconds}s` : 'None'}
                  </div>
                </div>

                {/* Affected Agents List */}
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                    Máy trạm sẽ bị tác động ({result.affected_agents?.length || 1} agents):
                  </div>

                  <div
                    style={{
                      maxHeight: '120px',
                      overflowY: 'auto',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-xs, 4px)',
                      background: 'var(--bg-card, #ffffff)',
                      padding: '0.4rem 0.6rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.3rem',
                    }}
                  >
                    {(result.affected_agents || []).map((ag) => (
                      <div
                        key={ag.id}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          fontSize: '0.775rem',
                          color: 'var(--text-primary)',
                          fontFamily: 'monospace',
                        }}
                      >
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <FiServer size={13} color="var(--primary)" />
                          <strong>{ag.id}</strong> ({ag.hostname || 'no-hostname'})
                        </span>
                        <span style={{ color: 'var(--text-tertiary)' }}>{ag.ip || ag.ip_address || 'N/A'}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Timeline Preview */}
                <div
                  style={{
                    background: 'var(--bg-primary, #ffffff)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-xs, 4px)',
                    padding: '0.75rem',
                    fontSize: '0.775rem',
                    fontFamily: 'monospace',
                    color: 'var(--text-secondary)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.3rem',
                  }}
                >
                  <div style={{ color: 'var(--text-primary)', fontWeight: 700, marginBottom: '0.2rem' }}>
                    Simulation Timeline:
                  </div>
                  <div>
                    <span style={{ color: 'var(--primary)', fontWeight: 600 }}>T+0s:</span> Gửi lệnh [
                    {(result.action_type || result.matched_policy.action_type).toUpperCase()}] tới{' '}
                    {result.affected_agents?.length || 1} agents
                  </div>
                  <div>
                    <span style={{ color: 'var(--success, #10b981)', fontWeight: 600 }}>T+2s:</span> Nhận ACK phản hồi thành công từ Agent
                  </div>
                  {result.matched_policy.auto_rollback_seconds > 0 && (
                    <div>
                      <span style={{ color: 'var(--warning, #f59e0b)', fontWeight: 600 }}>
                        T+{result.matched_policy.auto_rollback_seconds}s:
                      </span>{' '}
                      Tự động hoàn nguyên (Auto-rollback) nếu không có xác nhận duy trì
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div
                style={{
                  padding: '1.5rem',
                  textAlign: 'center',
                  background: 'var(--bg-card, #ffffff)',
                  border: '1px dashed var(--border)',
                  borderRadius: 'var(--radius-sm, 4px)',
                  color: 'var(--text-tertiary)',
                  fontSize: '0.825rem',
                }}
              >
                <FiShield size={28} style={{ opacity: 0.4, marginBottom: '0.4rem' }} />
                <div>Không có policy nào khớp với mức Risk Score {Number(riskScore).toFixed(1)}.</div>
                <div style={{ fontSize: '0.75rem', marginTop: '0.2rem' }}>Hệ thống sẽ không thực thi hành động tự động.</div>
              </div>
            )}

            {/* Warning Box */}
            <div
              style={{
                padding: '0.75rem 0.85rem',
                borderRadius: 'var(--radius-sm, 4px)',
                background: isLiveMode ? 'rgba(239, 68, 68, 0.1)' : 'rgba(59, 130, 246, 0.08)',
                border: isLiveMode ? '1px solid var(--error, #ef4444)' : '1px solid rgba(59, 130, 246, 0.3)',
                color: isLiveMode ? 'var(--error, #ef4444)' : 'var(--primary, #3b82f6)',
                fontSize: '0.775rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              {isLiveMode ? <FiAlertTriangle size={18} style={{ flexShrink: 0 }} /> : <FiAlertCircle size={18} style={{ flexShrink: 0 }} />}
              <div>
                {isLiveMode ? (
                  <span>
                    <strong>CẢNH BÁO CHẾ ĐỘ LIVE:</strong> Khi nhấn "Apply Now (Live)", lệnh phản ứng sẽ{' '}
                    <strong>thực sự được gửi và áp dụng</strong> lên các máy trạm mục tiêu!
                  </span>
                ) : (
                  <span>
                    <strong>CHẾ ĐỘ DRY-RUN:</strong> Đây là mô phỏng an toàn. Không có bất kỳ lệnh hoặc thay đổi cấu hình mạng nào được gửi tới máy trạm.
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 3: ACTIONS FOOTER                                                 */}
          {/* ========================================================================= */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              paddingTop: '0.5rem',
              borderTop: '1px solid var(--border)',
            }}
          >
            <Button
              variant="outline"
              size="sm"
              onClick={() => runEvaluation(true)}
              disabled={loading}
              iconLeft={<FiRefreshCw size={13} className={loading ? 'animate-spin' : ''} />}
            >
              Re-evaluate
            </Button>

            <div style={{ display: 'flex', gap: '0.65rem' }}>
              <Button variant="outline" size="sm" onClick={onClose}>
                Đóng
              </Button>

              {isLiveMode && result?.matched_policy && (
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => setConfirmLiveOpen(true)}
                  disabled={loading}
                  iconLeft={<FiPlay size={13} />}
                >
                  Apply Now (Live)
                </Button>
              )}
            </div>
          </div>
        </div>
      </Modal>

      {/* Confirmation Modal for Live Execution */}
      <Modal
        isOpen={confirmLiveOpen}
        onClose={() => setConfirmLiveOpen(false)}
        title="Xác nhận thực thi phản ứng LIVE"
        maxWidth={500}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div
            style={{
              padding: '0.85rem',
              borderRadius: 'var(--radius-sm, 4px)',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid var(--error, #ef4444)',
              color: 'var(--error, #ef4444)',
              display: 'flex',
              gap: '0.65rem',
            }}
          >
            <FiAlertTriangle size={22} style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.825rem', lineHeight: 1.4 }}>
              Bạn chuẩn bị thực thi lệnh <strong>[{(result?.action_type || result?.matched_policy?.action_type || '').toUpperCase()}]</strong> thật sự lên{' '}
              <strong>{result?.affected_agents?.length || 1} máy trạm</strong> theo chính sách{' '}
              <strong>"{result?.matched_policy?.name}"</strong>.
            </div>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0 }}>
            Hành động này sẽ thay đổi trạng thái máy mục tiêu và được ghi vào hệ thống Response Actions History & Audit Log.
          </p>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.65rem', marginTop: '0.5rem' }}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmLiveOpen(false)}
              disabled={liveExecuting}
            >
              Cancel (Hủy bỏ)
            </Button>

            <Button
              variant="danger"
              size="sm"
              loading={liveExecuting}
              onClick={handleExecuteLive}
              iconLeft={<FiPlay size={13} />}
            >
              Xác nhận Thực thi Live
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
