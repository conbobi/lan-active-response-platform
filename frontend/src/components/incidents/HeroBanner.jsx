// src/components/incidents/HeroBanner.jsx
import React from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import {
  FiAlertTriangle,
  FiShield,
  FiLock,
  FiUnlock,
  FiSlash,
  FiActivity,
  FiClock,
  FiServer,
  FiDownload,
  FiTerminal
} from 'react-icons/fi';

export default function HeroBanner({
  incident,
  onAction,
  actionLoading,
  isIsolated,
}) {
  if (!incident) return null;

  const culprit = incident.culpritProcess || {
    name: 'suspicious_process',
    pid: 4128,
    exe_path: 'C:\\Users\\AppData\\Local\\Temp\\key_test.exe',
  };
  const parent = incident.parentProcess || { name: 'cmd.exe', pid: 3500 };

  // Generate natural language human narrative
  const generateNarrative = () => {
    const pName = culprit.name || 'key_test.exe';
    const pid = culprit.pid || 'N/A';
    const parentName = parent.name || 'cmd.exe';
    const score = incident.riskScore || 50;

    let text = `Tiến trình \`${pName}\` (PID ${pid}) được khởi chạy bởi \`${parentName}\`, hoạt động từ thư mục bất thường (Temp). `;
    text += `Hệ thống phân tích rủi ro kích hoạt điểm đe dọa ${score}/100. `;
    if (isIsolated) {
      text += `Chính sách an ninh tự động đã CÔ LẬP MẠNG máy trạm ${incident.agentId} để ngăn chặn lây lan.`;
    } else {
      text += `Khuyến nghị cô lập máy trạm ${incident.agentId} hoặc tiêu diệt cây tiến trình ngay lập tức.`;
    }
    return text;
  };

  const severityColor =
    incident.severity === 'critical'
      ? 'var(--error)'
      : incident.severity === 'high'
      ? 'var(--warning)'
      : 'var(--primary)';

  return (
    <div
      style={{
        background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        padding: '1.25rem 1.5rem',
        marginBottom: '1.25rem',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Top Bar: Title & Severity */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
            <span
              style={{
                background: `${severityColor}20`,
                color: severityColor,
                border: `1px solid ${severityColor}`,
                padding: '0.2rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.75rem',
                fontWeight: 800,
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
                display: 'flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              <FiAlertTriangle size={12} />
              {incident.severity} THREAT
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
              ID: <strong style={{ color: 'var(--text-secondary)' }}>{incident.id}</strong>
            </span>
          </div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            {incident.title}
          </h2>
        </div>

        {/* Action Quick Buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {isIsolated ? (
            <Button
              variant="outline"
              size="sm"
              iconLeft={<FiUnlock size={14} />}
              disabled={actionLoading}
              onClick={() => onAction && onAction('unisolate')}
            >
              Undo Isolate
            </Button>
          ) : (
            <Button
              variant="danger"
              size="sm"
              iconLeft={<FiLock size={14} />}
              disabled={actionLoading}
              onClick={() => onAction && onAction('isolate')}
            >
              Isolate Host
            </Button>
          )}

          {culprit.pid && (
            <Button
              variant="warning"
              size="sm"
              iconLeft={<FiSlash size={14} />}
              disabled={actionLoading}
              onClick={() => onAction && onAction('kill_process_tree', { pid: culprit.pid, process_name: culprit.name })}
            >
              Kill Tree ({culprit.name})
            </Button>
          )}
        </div>
      </div>

      {/* Auto-generated Human Narrative Box */}
      <div
        style={{
          marginTop: '1rem',
          padding: '0.85rem 1rem',
          background: 'rgba(0, 0, 0, 0.35)',
          borderLeft: `4px solid ${severityColor}`,
          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
          fontSize: '0.88rem',
          color: 'var(--text-primary)',
          lineHeight: 1.5,
        }}
      >
        <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
          📖 Auto-Generated Threat Storyline
        </div>
        {generateNarrative()}
      </div>

      {/* Metric Cards Row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.75rem',
          marginTop: '1rem',
        }}
      >
        <div style={{ background: 'var(--bg-secondary)', padding: '0.6rem 0.8rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <FiServer size={12} /> Target Agent
          </div>
          <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--primary)', marginTop: '0.15rem' }}>
            {incident.agentId || 'Unknown'}
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '0.6rem 0.8rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <FiActivity size={12} /> Risk Assessment
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: severityColor, marginTop: '0.15rem' }}>
            {incident.riskScore} <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontWeight: 500 }}>/ 100</span>
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '0.6rem 0.8rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <FiShield size={12} /> Host Containment
          </div>
          <div style={{ fontSize: '0.85rem', fontWeight: 700, marginTop: '0.25rem' }}>
            {isIsolated ? (
              <span style={{ color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <FiLock size={12} /> ISOLATED
              </span>
            ) : (
              <span style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <FiUnlock size={12} /> NORMAL
              </span>
            )}
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '0.6rem 0.8rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <FiClock size={12} /> Detected At
          </div>
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            {incident.createdAt ? new Date(incident.createdAt).toLocaleTimeString() : 'N/A'}
          </div>
        </div>
      </div>
    </div>
  );
}
