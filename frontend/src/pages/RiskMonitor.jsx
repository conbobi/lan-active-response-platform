// src/pages/RiskMonitor.jsx
import React, { useEffect, useState, useMemo } from 'react';
import { getAgentRiskScores } from '../api/risk';
import { FactorBreakdown } from '../components/FactorBreakdown';
import { RiskScoreChart } from '../components/RiskScoreChart';
import { FiActivity, FiRefreshCw, FiEye, FiCopy, FiCheck, FiShield, FiAlertTriangle } from 'react-icons/fi';

const AGENTS = ['client1', 'client2', 'client3', 'client4', 'attacker'];

export function StatusBadge({ score }) {
  const s = Number(score || 0);
  let label = '🟢 Safe';
  let badgeStyle = { backgroundColor: '#dcfce7', color: '#15803d', border: '1px solid #bbf7d0' };

  if (s >= 50) {
    label = '🔴 Incident';
    badgeStyle = { backgroundColor: '#fee2e2', color: '#b91c1c', border: '1px solid #fca5a5' };
  } else if (s >= 30) {
    label = '🟠 Alert';
    badgeStyle = { backgroundColor: '#ffedd5', color: '#c2410c', border: '1px solid #fed7aa' };
  } else if (s >= 10) {
    label = '🟡 Warning';
    badgeStyle = { backgroundColor: '#fef9c3', color: '#854d0e', border: '1px solid #fef08a' };
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
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Modal detail state
  const [detailRecord, setDetailRecord] = useState(null);
  const [copied, setCopied] = useState(false);

  async function loadData() {
    try {
      setLoading(true);
      const results = await Promise.all(
        AGENTS.map((agentId) => getAgentRiskScores(agentId, 30).catch(() => []))
      );
      const all = results.flat().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setScores(all);
      setLastRefreshed(new Date());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 12000);
    return () => clearInterval(interval);
  }, []);

  const filtered = useMemo(() => {
    return selectedAgent ? scores.filter((s) => s.agent_id === selectedAgent) : scores;
  }, [scores, selectedAgent]);

  // Chart data for selected agent or top agent
  const chartAgent = selectedAgent || 'attacker';
  const chartScores = useMemo(() => {
    return scores.filter((s) => s.agent_id === chartAgent).slice(0, 30);
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
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FiActivity style={{ color: '#3b82f6' }} /> Risk Scoring Monitor (EMA & Debounce)
          </h1>
          <p style={{ color: '#64748b', fontSize: '14px', marginTop: '4px' }}>
            Giám sát điểm rủi ro thời gian thực đã qua lọc nhiễu Exponential Moving Average (alpha=0.35)
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '12px', color: '#94a3b8' }}>
            Cập nhật: {lastRefreshed.toLocaleTimeString('vi-VN')}
          </span>
          <button
            onClick={loadData}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              border: '1px solid #cbd5e1',
              backgroundColor: '#fff',
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
        {AGENTS.map((agent) => {
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
          backgroundColor: '#fff',
          borderRadius: '8px',
          border: '1px solid #e2e8f0',
          overflow: 'hidden',
          boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
        }}
      >
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0', color: '#475569' }}>
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
                <td colSpan="7" style={{ padding: '32px', textAlign: 'center', color: '#94a3b8' }}>
                  {loading ? 'Đang tải dữ liệu telemetry...' : 'Chưa có bản ghi điểm rủi ro nào'}
                </td>
              </tr>
            ) : (
              filtered.slice(0, 25).map((r) => (
                <tr
                  key={r.id}
                  style={{
                    borderBottom: '1px solid #f1f5f9',
                    transition: 'background-color 0.15s'
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#f8fafc')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td style={{ padding: '12px 16px', fontWeight: 600, fontFamily: 'monospace' }}>
                    {r.agent_id}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right', color: '#64748b' }}>
                    {Number(r.score).toFixed(2)}
                  </td>
                  <td
                    style={{
                      padding: '12px 16px',
                      textAlign: 'right',
                      fontWeight: 700,
                      color: (r.smoothed_score ?? r.score) > 30 ? '#dc2626' : '#1e293b'
                    }}
                  >
                    {Number(r.smoothed_score ?? r.score).toFixed(2)}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <FactorBreakdown factors={r.factors} />
                  </td>
                  <td style={{ padding: '12px 16px', color: '#64748b', fontSize: '12px' }}>
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
                        borderRadius: '4px',
                        border: '1px solid #cbd5e1',
                        backgroundColor: '#fff',
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
          backgroundColor: '#fff',
          borderRadius: '8px',
          border: '1px solid #e2e8f0',
          padding: '20px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FiActivity style={{ color: '#10b981' }} />
            Biểu đồ so sánh Raw vs Smoothed Score (30 chu kỳ gần nhất — {chartAgent})
          </h2>
          <span style={{ fontSize: '12px', color: '#64748b' }}>
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
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            backdropFilter: 'blur(3px)'
          }}
          onClick={() => setDetailRecord(null)}
        >
          <div
            style={{
              backgroundColor: '#fff',
              borderRadius: '12px',
              padding: '24px',
              maxWidth: '650px',
              width: '90%',
              maxHeight: '85vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)'
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '18px', fontWeight: 'bold' }}>
                Chi tiết đánh giá rủi ro — {detailRecord.agent_id}
              </h3>
              <button
                onClick={() => setDetailRecord(null)}
                style={{
                  border: 'none',
                  background: 'transparent',
                  fontSize: '18px',
                  cursor: 'pointer',
                  color: '#64748b'
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
              <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
                <div style={{ fontSize: '12px', color: '#64748b' }}>Raw Score</div>
                <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#475569' }}>
                  {Number(detailRecord.score).toFixed(2)}
                </div>
              </div>
              <div style={{ backgroundColor: '#f0fdf4', padding: '12px', borderRadius: '6px' }}>
                <div style={{ fontSize: '12px', color: '#16a34a' }}>Smoothed Score (EMA)</div>
                <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#15803d' }}>
                  {Number(detailRecord.smoothed_score ?? detailRecord.score).toFixed(2)}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <h4 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>Yếu tố phát hiện (Factors)</h4>
              <div style={{ backgroundColor: '#f8fafc', padding: '12px', borderRadius: '6px' }}>
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
