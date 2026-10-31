// src/pages/RiskMonitor.jsx
import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { getAgentRiskScores } from '../api/risk';
import { getAgents } from '../api/agents';
import { FactorBreakdown } from '../components/FactorBreakdown';
import { RiskScoreChart } from '../components/RiskScoreChart';
import { FiActivity, FiRefreshCw, FiEye, FiCopy, FiCheck, FiShield, FiAlertTriangle } from 'react-icons/fi';

export function StatusBadge({ score }) {
  const s = Number(score || 0);
  let label = '🟢 Safe';
  let badgeStyle = { backgroundColor: 'var(--success-dim)', color: 'var(--success)', border: '1px solid rgba(63, 185, 80, 0.4)' };

  if (s >= 50) {
    label = '🔴 Incident';
    badgeStyle = { backgroundColor: 'var(--critical-dim)', color: 'var(--critical)', border: '1px solid rgba(255, 123, 114, 0.4)' };
  } else if (s >= 30) {
    label = '🟠 Alert';
    badgeStyle = { backgroundColor: 'var(--error-dim)', color: 'var(--error)', border: '1px solid rgba(248, 81, 73, 0.4)' };
  } else if (s >= 10) {
    label = '🟡 Warning';
    badgeStyle = { backgroundColor: 'var(--warning-dim)', color: 'var(--warning)', border: '1px solid rgba(210, 153, 34, 0.4)' };
  }

  return (
    <span
      style={{
        ...badgeStyle,
        padding: '3px 8px',
        borderRadius: '9999px',
        fontSize: '12px',
        fontWeight: 600,
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px'
      }}
    >
      {label}
    </span>
  );
}

export default function RiskMonitor() {
  const [scores, setScores] = useState([]);
  const [agentsList, setAgentsList] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Modal detail state
  const [detailRecord, setDetailRecord] = useState(null);
  const [copied, setCopied] = useState(false);

  const agentsListRef = useRef(agentsList);
  agentsListRef.current = agentsList;

  const loadData = useCallback(async (isInitial = false) => {
    try {
      if (isInitial) setLoading(true);
      let targetAgents = agentsListRef.current;
      try {
        const fetched = await getAgents();
        if (Array.isArray(fetched) && fetched.length > 0) {
          const ids = fetched.map((a) => a.id).filter(Boolean);
          targetAgents = Array.from(new Set(ids));
          setAgentsList(targetAgents);
          agentsListRef.current = targetAgents;
        }
      } catch (err) {
        console.warn('Failed to fetch dynamic agent list', err);
      }

      const results = await Promise.all(
        targetAgents.map((agentId) => getAgentRiskScores(agentId, 30).catch(() => []))
      );
      const all = results.flat().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setScores(all);
      setLastRefreshed(new Date());
    } finally {
      if (isInitial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData(true);
    const interval = setInterval(() => loadData(false), 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  const filtered = useMemo(() => {
    return selectedAgent ? scores.filter((s) => s.agent_id === selectedAgent) : scores;
  }, [scores, selectedAgent]);

  // Chart data for selected agent or first available agent
  const chartAgent = selectedAgent || agentsList[0] || (scores[0]?.agent_id || '');
  const chartScores = useMemo(() => {
    return chartAgent ? scores.filter((s) => s.agent_id === chartAgent).slice(0, 30) : [];
  }, [scores, chartAgent]);


  const handleCopyJson = (record) => {
    navigator.clipboard.writeText(JSON.stringify(record, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ padding: '24px', maxWidth: '1400px', margin: '0 auto', color: '#1e293b' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
            <FiActivity style={{ color: 'var(--primary)' }} /> Risk Scoring Monitor (EMA & Debounce)
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginTop: '4px' }}>
            Giám sát điểm rủi ro thời gian thực đã qua lọc nhiễu Exponential Moving Average (alpha=0.35)
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)' }}>
            Cập nhật: {lastRefreshed.toLocaleTimeString('vi-VN')}
          </span>
          <button
            onClick={() => loadData(true)}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-primary)',
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              fontWeight: 500,
              fontSize: '13px'
            }}
          >
            <FiRefreshCw className={loading ? 'animate-spin' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <button
          onClick={() => setSelectedAgent(null)}
          style={{
            padding: '6px 14px',
            borderRadius: '6px',
            fontWeight: 500,
            fontSize: '13px',
            border: selectedAgent === null ? '1px solid #2563eb' : '1px solid #cbd5e1',
            backgroundColor: selectedAgent === null ? '#2563eb' : '#fff',
            color: selectedAgent === null ? '#fff' : '#475569',
            cursor: 'pointer'
          }}
        >
          Tất cả Agent ({scores.length})
        </button>
        {agentsList.map((agent) => {
          const isSel = selectedAgent === agent;
          return (
            <button
              key={agent}
              onClick={() => setSelectedAgent(agent)}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                fontWeight: 500,
                fontSize: '13px',
                border: isSel ? '1px solid #2563eb' : '1px solid #cbd5e1',
                backgroundColor: isSel ? '#2563eb' : '#fff',
                color: isSel ? '#fff' : '#475569',
                cursor: 'pointer'
              }}
            >
              {agent}
            </button>
          );
        })}
      </div>

      {/* Main Table */}
      <div
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-primary)',
          overflow: 'hidden',
          boxShadow: 'var(--shadow-sm)'
        }}
      >
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-tertiary)', borderBottom: '1px solid var(--border-primary)', color: 'var(--text-secondary)' }}>
              <th style={{ padding: '12px 16px' }}>Agent ID</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Raw Score</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Smoothed (EMA)</th>
              <th style={{ padding: '12px 16px' }}>Top Factors</th>
              <th style={{ padding: '12px 16px' }}>Thời gian</th>
              <th style={{ padding: '12px 16px', textAlign: 'center' }}>Trạng thái</th>
              <th style={{ padding: '12px 16px', textAlign: 'center' }}>Hành động</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                  {loading ? 'Đang tải dữ liệu telemetry...' : 'Chưa có bản ghi điểm rủi ro nào'}
                </td>
              </tr>
            ) : (
              filtered.slice(0, 25).map((r) => (
                <tr
                  key={r.id}
                  style={{
                    borderBottom: '1px solid var(--border-subtle)',
                    transition: 'background-color 0.15s'
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td style={{ padding: '12px 16px', fontWeight: 600, fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                    {r.agent_id}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right', color: 'var(--text-secondary)' }}>
                    {Number(r.score).toFixed(2)}
                  </td>
                  <td
                    style={{
                      padding: '12px 16px',
                      textAlign: 'right',
                      fontWeight: 700,
                      color: (r.smoothed_score ?? r.score) > 30 ? 'var(--critical)' : 'var(--text-primary)'
                    }}
                  >
                    {Number(r.smoothed_score ?? r.score).toFixed(2)}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <FactorBreakdown factors={r.factors} />
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    {new Date(r.timestamp).toLocaleString('vi-VN')}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <StatusBadge score={r.smoothed_score ?? r.score} />
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <button
                      onClick={() => setDetailRecord(r)}
                      style={{
                        padding: '4px 8px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border-primary)',
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--text-primary)',
                        cursor: 'pointer',
                        fontSize: '12px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                    >
                      <FiEye /> Chi tiết
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Chart Section */}
      <div
        style={{
          marginTop: '24px',
          backgroundColor: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-primary)',
          padding: '20px',
          boxShadow: 'var(--shadow-sm)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)' }}>
            <FiActivity style={{ color: 'var(--success)' }} />
            Biểu đồ so sánh Raw vs Smoothed Score (30 chu kỳ gần nhất — {chartAgent})
          </h2>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Đường xanh lá: Smoothed (EMA) | Đường tím nhạt: Raw telemetry score
          </span>
        </div>
        <RiskScoreChart data={chartScores} />
      </div>

      {/* Detail Modal */}
      {detailRecord && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'var(--bg-overlay)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            backdropFilter: 'blur(4px)'
          }}
          onClick={() => setDetailRecord(null)}
        >
          <div
            style={{
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-lg)',
              padding: '24px',
              maxWidth: '650px',
              width: '90%',
              maxHeight: '85vh',
              overflowY: 'auto',
              boxShadow: 'var(--shadow-lg)',
              color: 'var(--text-primary)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid var(--border-primary)', paddingBottom: '12px' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--text-primary)' }}>
                Chi tiết đánh giá rủi ro — {detailRecord.agent_id}
              </h3>
              <button
                onClick={() => setDetailRecord(null)}
                style={{
                  border: 'none',
                  background: 'transparent',
                  fontSize: '18px',
                  cursor: 'pointer',
                  color: 'var(--text-secondary)'
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
              <div style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', padding: '12px', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Raw Score</div>
                <div style={{ fontSize: '20px', fontWeight: 'bold', color: 'var(--text-primary)' }}>
                  {Number(detailRecord.score).toFixed(2)}
                </div>
              </div>
              <div style={{ backgroundColor: 'var(--success-dim)', border: '1px solid rgba(63, 185, 80, 0.3)', padding: '12px', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '12px', color: 'var(--success)' }}>Smoothed Score (EMA)</div>
                <div style={{ fontSize: '20px', fontWeight: 'bold', color: 'var(--success)' }}>
                  {Number(detailRecord.smoothed_score ?? detailRecord.score).toFixed(2)}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <h4 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>Yếu tố phát hiện (Factors)</h4>
              <div style={{ backgroundColor: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', padding: '12px', borderRadius: 'var(--radius-sm)' }}>
                <FactorBreakdown factors={detailRecord.factors} />
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 600 }}>Raw Factors JSON</h4>
                <button
                  onClick={() => handleCopyJson(detailRecord)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    border: '1px solid #cbd5e1',
                    backgroundColor: '#fff',
                    cursor: 'pointer',
                    fontSize: '12px'
                  }}
                >
                  {copied ? <FiCheck style={{ color: '#16a34a' }} /> : <FiCopy />}
                  {copied ? 'Đã sao chép' : 'Copy JSON'}
                </button>
              </div>
              <pre
                style={{
                  backgroundColor: '#0f172a',
                  color: '#38bdf8',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  maxHeight: '180px',
                  overflowX: 'auto'
                }}
              >
                {JSON.stringify(detailRecord, null, 2)}
              </pre>
            </div>

            <div style={{ textAlign: 'right' }}>
              <button
                onClick={() => setDetailRecord(null)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  backgroundColor: '#2563eb',
                  color: '#fff',
                  border: 'none',
                  cursor: 'pointer',
                  fontWeight: 500
                }}
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
