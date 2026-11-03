import React, { useState, useEffect, useRef } from 'react';
import toast from 'react-hot-toast';
import {
  FiZap,
  FiShield,
  FiSlash,
  FiLock,
  FiAlertTriangle,
  FiCheckCircle,
  FiXCircle,
  FiRefreshCw,
  FiInfo,
  FiTerminal,
  FiActivity,
  FiRadio,
  FiCpu,
  FiUsers,
  FiRotateCcw,
} from 'react-icons/fi';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Modal from '../ui/Modal';
import {
  getAIAnalysis,
  suggestAIResponse,
  applyAISuggestion,
  dismissAISuggestion,
} from '../../api/incidents';

const ACTION_CONFIG = {
  kill_process_tree: {
    label: 'Kill Process Tree',
    vietnamese: 'Tiêu diệt toàn bộ cây tiến trình',
    icon: <FiSlash size={16} />,
    color: '#ef4444',
    bg: 'rgba(239, 68, 68, 0.12)',
    border: 'rgba(239, 68, 68, 0.35)',
  },
  kill_process: {
    label: 'Kill Process',
    vietnamese: 'Kết thúc tiến trình đơn lẻ',
    icon: <FiSlash size={16} />,
    color: '#f97316',
    bg: 'rgba(249, 115, 22, 0.12)',
    border: 'rgba(249, 115, 22, 0.35)',
  },
  isolate: {
    label: 'Isolate Host',
    vietnamese: 'Cô lập mạng máy trạm',
    icon: <FiLock size={16} />,
    color: '#dc2626',
    bg: 'rgba(220, 38, 38, 0.15)',
    border: 'rgba(220, 38, 38, 0.4)',
  },
  suspend_process: {
    label: 'Suspend Process',
    vietnamese: 'Tạm dừng tiến trình',
    icon: <FiActivity size={16} />,
    color: '#f59e0b',
    bg: 'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.35)',
  },
  block_ip: {
    label: 'Block IP',
    vietnamese: 'Chặn địa chỉ IP C2',
    icon: <FiShield size={16} />,
    color: '#3b82f6',
    bg: 'rgba(59, 130, 246, 0.12)',
    border: 'rgba(59, 130, 246, 0.35)',
  },
  no_action: {
    label: 'No Action Needed',
    vietnamese: 'Không cần can thiệp',
    icon: <FiCheckCircle size={16} />,
    color: '#10b981',
    bg: 'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.35)',
  },
};

export default function AISuggestionPanel({ incidentId, onRefresh }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [suggesting, setSuggesting] = useState(false);
  const [applying, setApplying] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [isDismissModalOpen, setIsDismissModalOpen] = useState(false);
  const [dismissReason, setDismissReason] = useState('');
  const pollTimerRef = useRef(null);

  const fetchAnalysis = async (silent = false) => {
    try {
      if (!silent) setLoading(true);
      const data = await getAIAnalysis(incidentId);
      setAnalysis(data);
      return data;
    } catch (err) {
      if (err.response?.status !== 404 && !err.message?.includes('404')) {
        console.error('Error fetching AI analysis for suggestions:', err);
      }
      setAnalysis(null);
      return null;
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      fetchAnalysis();
    }
    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [incidentId]);

  const handleTriggerSuggest = async () => {
    try {
      setSuggesting(true);
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);

      await suggestAIResponse(incidentId);
      toast.success('AI đang phân tích context & tính toán blast radius...', {
        duration: 4000,
      });

      const POLL_INTERVAL = 4000;
      const MAX_ATTEMPTS = 45; // ~3 mins
      let attempts = 0;

      pollTimerRef.current = setInterval(async () => {
        attempts++;
        if (attempts > MAX_ATTEMPTS) {
          clearInterval(pollTimerRef.current);
          setSuggesting(false);
          pollTimerRef.current = null;
          toast.error('AI suggestion timeout sau 3 phút. Vui lòng thử lại sau.');
          return;
        }

        try {
          const fresh = await fetchAnalysis(true);
          if (fresh && fresh.suggested_action) {
            clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
            setSuggesting(false);
            toast.success(`AI đã đề xuất hành động: ${fresh.suggested_action.toUpperCase()}`);
            if (onRefresh) onRefresh();
          }
        } catch (e) {
          console.debug('Polling suggestion error:', e);
        }
      }, POLL_INTERVAL);
    } catch (err) {
      setSuggesting(false);
      toast.error(err.response?.data?.detail || err.message || 'Lỗi khi yêu cầu gợi ý từ AI');
    }
  };

  const handleApply = async () => {
    if (!analysis?.suggested_action || applying) return;
    try {
      setApplying(true);
      const res = await applyAISuggestion(incidentId, { analyst: 'analyst_soc' });
      toast.success(`Đã thực thi phản ứng: ${analysis.suggested_action} (Action ID: ${res.action_id || 'OK'})`);
      await fetchAnalysis(true);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Apply suggestion error:', err);
      const msg = err.response?.data?.detail || err.response?.data?.error || err.message || 'Lỗi khi áp dụng phản ứng';
      toast.error(msg);
    } finally {
      setApplying(false);
    }
  };

  const handleConfirmDismiss = async () => {
    if (!dismissReason.trim() || dismissing) return;
    try {
      setDismissing(true);
      await dismissAISuggestion(incidentId, {
        analyst: 'analyst_soc',
        reason: dismissReason.trim(),
      });
      toast.success('Đã ghi nhận bỏ qua gợi ý phản ứng');
      setIsDismissModalOpen(false);
      setDismissReason('');
      await fetchAnalysis(true);
      if (onRefresh) onRefresh();
    } catch (err) {
      console.error('Dismiss suggestion error:', err);
      const msg = err.response?.data?.detail || err.response?.data?.error || err.message || 'Lỗi khi bỏ qua gợi ý';
      toast.error(msg);
    } finally {
      setDismissing(false);
    }
  };

  if (loading) {
    return (
      <div
        style={{
          padding: '1.25rem',
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          color: 'var(--text-secondary)',
          fontSize: '0.85rem',
        }}
      >
        <FiRefreshCw className="spin" size={16} />
        <span>Đang kiểm tra đề xuất phản ứng từ AI...</span>
      </div>
    );
  }

  const hasSuggestion = Boolean(analysis?.suggested_action);
  const actionConfig = ACTION_CONFIG[analysis?.suggested_action] || {
    label: analysis?.suggested_action || 'Unknown',
    vietnamese: analysis?.suggested_action || 'Hành động',
    icon: <FiZap size={16} />,
    color: '#3b82f6',
    bg: 'rgba(59, 130, 246, 0.1)',
    border: 'rgba(59, 130, 246, 0.3)',
  };

  const isApplied = Boolean(analysis?.applied_at);
  const isDismissed = Boolean(analysis?.dismissed_at);
  const blastRadius = analysis?.blast_radius || {};
  const suggestionParams = analysis?.suggestion_params || {};
  const confidencePercent = Math.round((analysis?.confidence || 0) * 100);

  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border)',
        overflow: 'hidden',
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
      }}
    >
      {/* Top Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '0.85rem 1.15rem',
          background: 'rgba(255, 255, 255, 0.02)',
          borderBottom: '1px solid var(--border)',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <div
            style={{
              padding: '6px',
              borderRadius: '6px',
              background: 'rgba(239, 68, 68, 0.15)',
              color: '#ef4444',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <FiZap size={16} />
          </div>
          <div>
            <h4 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Đề xuất phản ứng AI (AI Response Assist)
            </h4>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)' }}>
              Khuyến nghị ứng phó tự động dựa trên Triage & Blast Radius • Zero Automated Dispatch
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {hasSuggestion && (
            <span
              style={{
                fontSize: '0.76rem',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                background: confidencePercent >= 75 ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                color: confidencePercent >= 75 ? '#10b981' : '#f59e0b',
                border: `1px solid ${confidencePercent >= 75 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
              }}
            >
              Độ tin cậy: {confidencePercent}%
            </span>
          )}

          {isApplied && (
            <span
              style={{
                fontSize: '0.76rem',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <FiCheckCircle size={12} /> ĐÃ THỰC THI
            </span>
          )}

          {isDismissed && (
            <span
              style={{
                fontSize: '0.76rem',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'rgba(156, 163, 175, 0.15)',
                color: '#9ca3af',
                border: '1px solid rgba(156, 163, 175, 0.4)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              <FiXCircle size={12} /> ĐÃ BỎ QUA
            </span>
          )}

          <Button
            variant="outline"
            size="sm"
            disabled={suggesting || applying}
            onClick={handleTriggerSuggest}
            style={{ fontSize: '0.76rem', padding: '0.3rem 0.65rem' }}
            title="Kích hoạt AI tính toán lại đề xuất ứng phó"
          >
            <FiRefreshCw className={suggesting ? 'spin' : ''} size={12} style={{ marginRight: '4px' }} />
            {suggesting ? 'Đang phân tích...' : 'AI Tính toán lại'}
          </Button>
        </div>
      </div>

      {/* Main Body */}
      <div style={{ padding: '1.15rem' }}>
        {!hasSuggestion ? (
          /* State 1: Chưa có gợi ý */
          <div
            style={{
              padding: '1.75rem 1rem',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.75rem',
            }}
          >
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '50%',
                background: 'rgba(59, 130, 246, 0.1)',
                color: 'var(--primary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <FiZap size={22} />
            </div>
            <div>
              <h5 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Chưa có đề xuất phản ứng cho sự cố này
              </h5>
              <p
                style={{
                  margin: '0.35rem 0 0 0',
                  fontSize: '0.82rem',
                  color: 'var(--text-tertiary)',
                  maxWidth: '480px',
                }}
              >
                AI sẽ đánh giá dữ liệu tiến trình độc hại, kết nối mạng và lịch sử các ca xử lý hiệu quả để đưa ra
                phương án giảm thiểu với phạm vi ảnh hưởng (Blast Radius) tối thiểu.
              </p>
            </div>
            <Button
              variant="primary"
              size="sm"
              disabled={suggesting}
              onClick={handleTriggerSuggest}
              style={{ marginTop: '0.5rem' }}
            >
              <FiZap size={14} style={{ marginRight: '6px' }} />
              {suggesting ? 'AI đang phân tích...' : 'Yêu cầu AI đề xuất phản ứng'}
            </Button>
          </div>
        ) : (
          /* State 2: Đã có gợi ý */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Banner Hành động đề xuất */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.9rem 1.15rem',
                borderRadius: 'var(--radius-sm)',
                background: actionConfig.bg,
                border: `1px solid ${actionConfig.border}`,
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div
                  style={{
                    padding: '8px',
                    borderRadius: '6px',
                    background: actionConfig.color,
                    color: '#fff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {actionConfig.icon}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span
                      style={{
                        fontSize: '0.95rem',
                        fontWeight: 800,
                        color: actionConfig.color,
                        letterSpacing: '0.4px',
                      }}
                    >
                      {actionConfig.label.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      ({actionConfig.vietnamese})
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    {suggestionParams.pid && (
                      <span style={{ marginRight: '1rem' }}>
                        🎯 Mục tiêu: <strong>PID {suggestionParams.pid}</strong>
                        {suggestionParams.process_name ? ` (${suggestionParams.process_name})` : ''}
                      </span>
                    )}
                    {suggestionParams.ip && (
                      <span>
                        🌐 C2 IP: <strong>{suggestionParams.ip}</strong>
                      </span>
                    )}
                    {analysis.suggested_action === 'isolate' && (
                      <span>
                        🛡️ Máy trạm: <strong>Agent {incidentId}</strong>
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Action Buttons (Apply / Dismiss) */}
              {!isApplied && !isDismissed && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <Button
                    variant="danger"
                    size="sm"
                    disabled={applying || dismissing}
                    onClick={handleApply}
                    style={{ fontWeight: 700 }}
                  >
                    <FiCheckCircle size={14} style={{ marginRight: '4px' }} />
                    {applying ? 'Đang thực thi...' : 'Áp dụng phản ứng'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={applying || dismissing}
                    onClick={() => setIsDismissModalOpen(true)}
                  >
                    <FiXCircle size={14} style={{ marginRight: '4px' }} />
                    Bỏ qua
                  </Button>
                </div>
              )}
            </div>

            {/* Banner thông báo trạng thái nếu đã apply hoặc dismiss */}
            {isApplied && (
              <div
                style={{
                  padding: '0.65rem 0.95rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  color: '#10b981',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <FiCheckCircle size={16} />
                <span>
                  Đã thực thi thành công bởi <strong>{analysis.applied_by_analyst || 'analyst'}</strong> vào lúc{' '}
                  {analysis.applied_at ? new Date(analysis.applied_at).toLocaleString() : 'N/A'}.
                </span>
              </div>
            )}

            {isDismissed && (
              <div
                style={{
                  padding: '0.65rem 0.95rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(156, 163, 175, 0.1)',
                  border: '1px solid rgba(156, 163, 175, 0.3)',
                  color: 'var(--text-secondary)',
                  fontSize: '0.82rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <FiXCircle size={16} />
                <span>
                  Đã bỏ qua bởi <strong>{analysis.dismissed_by_analyst || 'analyst'}</strong> vào lúc{' '}
                  {analysis.dismissed_at ? new Date(analysis.dismissed_at).toLocaleString() : 'N/A'} —{' '}
                  <em>"{analysis.dismiss_reason || 'Không nêu lý do'}"</em>
                </span>
              </div>
            )}

            {/* Grid 2 cột: Blast Radius & Reasoning */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))',
                gap: '1rem',
              }}
            >
              {/* Cột 1: Blast Radius Breakdown (Tính toán từ telemetry thực tế) */}
              <div
                style={{
                  background: 'var(--bg-primary)',
                  padding: '0.95rem',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    borderBottom: '1px solid var(--border)',
                    paddingBottom: '0.45rem',
                  }}
                >
                  <span
                    style={{
                      fontSize: '0.84rem',
                      fontWeight: 700,
                      color: 'var(--text-primary)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                    }}
                  >
                    <FiActivity size={14} color="var(--warning)" /> Phạm vi ảnh hưởng (Blast Radius)
                  </span>
                  <span
                    style={{
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '3px',
                      background:
                        blastRadius.system_critical_risk === 'high'
                          ? 'rgba(239, 68, 68, 0.15)'
                          : blastRadius.system_critical_risk === 'medium'
                          ? 'rgba(245, 158, 11, 0.15)'
                          : 'rgba(16, 185, 129, 0.15)',
                      color:
                        blastRadius.system_critical_risk === 'high'
                          ? '#ef4444'
                          : blastRadius.system_critical_risk === 'medium'
                          ? '#f59e0b'
                          : '#10b981',
                    }}
                  >
                    RỦI RO: {(blastRadius.system_critical_risk || 'low').toUpperCase()}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  <div
                    style={{
                      padding: '0.5rem',
                      background: 'var(--bg-secondary)',
                      borderRadius: '4px',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>Tiến trình ảnh hưởng</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                      {blastRadius.processes_affected !== undefined ? blastRadius.processes_affected : 1}
                    </div>
                  </div>

                  <div
                    style={{
                      padding: '0.5rem',
                      background: 'var(--bg-secondary)',
                      borderRadius: '4px',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>Phiên làm việc (Sessions)</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                      {blastRadius.sessions_affected !== undefined ? blastRadius.sessions_affected : 1}
                    </div>
                  </div>
                </div>

                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <div>
                    <strong style={{ color: 'var(--text-primary)' }}>Khả năng hoàn tác: </strong>
                    {blastRadius.reversible ? (
                      <span style={{ color: 'var(--success)' }}>Có thể hoàn tác (Rollback / Un-isolate)</span>
                    ) : (
                      <span style={{ color: 'var(--warning)' }}>Không thể hoàn tác (Kill Process)</span>
                    )}
                  </div>
                  {Array.isArray(blastRadius.target_pids) && blastRadius.target_pids.length > 0 && (
                    <div>
                      <strong style={{ color: 'var(--text-primary)' }}>PIDs mục tiêu: </strong>
                      <code>{blastRadius.target_pids.join(', ')}</code>
                    </div>
                  )}
                  {Array.isArray(blastRadius.target_processes) && blastRadius.target_processes.length > 0 && (
                    <div>
                      <strong style={{ color: 'var(--text-primary)' }}>Tiến trình: </strong>
                      <code>{blastRadius.target_processes.join(', ')}</code>
                    </div>
                  )}
                </div>
              </div>

              {/* Cột 2: Lý do AI đề xuất (Reasoning) */}
              <div
                style={{
                  background: 'var(--bg-primary)',
                  padding: '0.95rem',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem',
                }}
              >
                <div
                  style={{
                    fontSize: '0.84rem',
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px',
                    borderBottom: '1px solid var(--border)',
                    paddingBottom: '0.45rem',
                  }}
                >
                  <FiInfo size={14} color="var(--primary)" /> Căn cứ đề xuất & Lập luận (Rationale)
                </div>

                <div
                  style={{
                    fontSize: '0.82rem',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.6,
                    whiteSpace: 'pre-line',
                  }}
                >
                  {analysis.suggestion_reasoning || 'Không có mô tả chi tiết từ mô hình AI.'}
                </div>
              </div>
            </div>

            {/* Rủi ro nếu không hành động */}
            {blastRadius.risk_if_not_acted && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.6rem',
                  padding: '0.75rem 0.95rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  color: 'var(--text-primary)',
                  fontSize: '0.8rem',
                }}
              >
                <FiAlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <strong style={{ color: '#ef4444' }}>Cảnh báo rủi ro nếu không can thiệp: </strong>
                  <span>{blastRadius.risk_if_not_acted}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Sub-modal: Dismiss Suggestion with Reason */}
      <Modal
        isOpen={isDismissModalOpen}
        onClose={() => !dismissing && setIsDismissModalOpen(false)}
        title="Bỏ qua đề xuất phản ứng của AI"
        maxWidth={460}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Vui lòng nhập lý do bạn không áp dụng hành động này. Dữ liệu này sẽ được lưu làm phản hồi giúp cải thiện
            mô hình AI ở các lần sau.
          </p>

          <textarea
            rows={3}
            value={dismissReason}
            onChange={(e) => setDismissReason(e.target.value)}
            placeholder="Ví dụ: Tiến trình này thuộc script sao lưu hợp lệ của quản trị viên..."
            style={{
              width: '100%',
              padding: '0.6rem 0.75rem',
              fontSize: '0.85rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
              outline: 'none',
              boxSizing: 'border-box',
              fontFamily: 'inherit',
            }}
          />

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
            <Button
              variant="outline"
              size="sm"
              disabled={dismissing}
              onClick={() => setIsDismissModalOpen(false)}
            >
              Hủy
            </Button>
            <Button
              variant="primary"
              size="sm"
              disabled={!dismissReason.trim() || dismissing}
              onClick={handleConfirmDismiss}
            >
              {dismissing ? 'Đang lưu...' : 'Xác nhận bỏ qua'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

