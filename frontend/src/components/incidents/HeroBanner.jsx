import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import InfoTooltip from '../ui/InfoTooltip';
import { TOOLTIPS } from '../../constants/tooltips';
import { isKernelOrSystem } from '../../constants/processExclusions';
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
  httpIncident = false,
  onOpenAssist,
  onAction,
  actionLoading,
  isIsolated,
}) {
  const navigate = useNavigate();
  if (!incident) return null;

  const culprit = incident.culpritProcess || incident.culprit_process || null;
  const behavior = incident.detection_evidence?.behavior;

  const generateNarrative = () => incident.story || incident.description || 'Chưa có bằng chứng chi tiết.';
  const isFalsePositive = incident.status === 'false_positive' || incident.label === 'false_positive';
  const isResolved = incident.status === 'resolved' || incident.status === 'closed' || incident.label === 'benign';
  const isInactive = isFalsePositive || isResolved;

  const severityColor =
    isFalsePositive
      ? '#9ca3af'
      : incident.severity === 'critical'
      ? 'var(--error)'
      : incident.severity === 'high'
      ? 'var(--warning)'
      : 'var(--primary)';

  const mitreTags = useMemo(() => {
    if (isInactive) {
      return [];
    }
    if (Array.isArray(incident.mitreTags) && incident.mitreTags.length > 0) {
      return incident.mitreTags;
    }
    if (Array.isArray(incident.mitre_techniques) && incident.mitre_techniques.length > 0) {
      return incident.mitre_techniques.map(t => typeof t === 'string' ? { id: t, name: t } : t);
    }
    const text = `${incident.title || ''} ${incident.description || ''} ${JSON.stringify(incident.details || {})}`;
    const matches = text.match(/T\d{4}(?:\.\d{3})?/g) || [];
    const unique = Array.from(new Set(matches));
    if (unique.length > 0) {
      return unique.map(id => ({ id, name: TOOLTIPS[id]?.term || id }));
    }
    return [];
  }, [incident, isInactive]);

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
              {isFalsePositive
                ? 'FALSE POSITIVE'
                : isResolved
                ? 'RESOLVED'
                : `${incident.severity} THREAT`}
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
              ID: <strong style={{ color: 'var(--text-secondary)' }}>{incident.id}</strong>
            </span>
          </div>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            {incident.title}
          </h2>
          {behavior?.classification && (
            <div style={{ marginTop: '0.4rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              <strong>{behavior.classification}</strong>
              {behavior.source_ip && <span> · {behavior.source_ip}</span>}
              {behavior.service && <span> · {behavior.service}</span>}
              {Number.isInteger(behavior.failed_attempts) && (
                <span> · {behavior.failed_attempts} bản ghi thất bại</span>
              )}
              {Number.isInteger(behavior.successful_attempts) && (
                <span> · {behavior.successful_attempts} bản ghi thành công</span>
              )}
              {behavior.legacy_duplicate_status === 'unresolved_mirrors' && (
                <div>Có thể có bản ghi trùng giữa các file log.</div>
              )}
              {behavior.exploitation_outcome === 'undetermined' && <div>Kết quả khai thác chưa xác định.</div>}
            </div>
          )}
          <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.4rem', flexWrap: 'wrap' }}>
            {mitreTags.map(tag => (
              <span key={tag.id} className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', background: 'rgba(59, 130, 246, 0.15)', border: '1px solid rgba(59, 130, 246, 0.3)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.78rem' }}>
                🎯 <InfoTooltip 
                  term={TOOLTIPS[tag.id]?.term || tag.id}
                  definition={TOOLTIPS[tag.id]?.definition || tag.name}
                >
                  {tag.id}
                </InfoTooltip>
              </span>
            ))}
            {incident.label && (
              <span
                className="badge"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '0.78rem',
                  fontWeight: 600,
                  background:
                    incident.label === 'true_positive'
                      ? 'rgba(239, 68, 68, 0.15)'
                      : incident.label === 'false_positive'
                      ? 'rgba(156, 163, 175, 0.15)'
                      : incident.label === 'benign'
                      ? 'rgba(16, 185, 129, 0.15)'
                      : 'rgba(245, 158, 11, 0.15)',
                  border:
                    incident.label === 'true_positive'
                      ? '1px solid rgba(239, 68, 68, 0.4)'
                      : incident.label === 'false_positive'
                      ? '1px solid rgba(156, 163, 175, 0.4)'
                      : incident.label === 'benign'
                      ? '1px solid rgba(16, 185, 129, 0.4)'
                      : '1px solid rgba(245, 158, 11, 0.4)',
                  color:
                    incident.label === 'true_positive'
                      ? '#ef4444'
                      : incident.label === 'false_positive'
                      ? '#9ca3af'
                      : incident.label === 'benign'
                      ? '#10b981'
                      : '#f59e0b',
                }}
                title={`Ground Truth: ${incident.label} (bởi ${incident.labeledBy || 'N/A'})${incident.labelReason ? `\nLý do: ${incident.labelReason}` : ''}`}
              >
                🏷️ AI Ground Truth: {incident.label.toUpperCase()}
              </span>
            )}
          </div>
        </div>

        {/* Action Quick Buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {isInactive ? (
            <span
              style={{
                fontSize: '0.85rem',
                color: 'var(--text-tertiary)',
                alignSelf: 'center',
                fontStyle: 'italic',
                padding: '0.25rem 0.5rem',
                background: 'rgba(255, 255, 255, 0.04)',
                borderRadius: 'var(--radius-sm)',
                border: '1px dashed var(--border)'
              }}
            >
              ✓ Sự cố {isFalsePositive ? 'được phân loại Báo Động Giả (False Positive)' : 'đã được xử lý'} — Không cần can thiệp.
            </span>
          ) : (
            <>
              {httpIncident && !isIsolated ? (
                <Button
                  variant="primary"
                  size="sm"
                  iconLeft={<FiTerminal size={14} />}
                  onClick={() => onOpenAssist && onOpenAssist()}
                  title="Cô lập máy chủ cần bằng chứng process/socket đã xác minh; sự cố HTTP dùng đề xuất theo bằng chứng."
                >
                  AI Response Assist
                </Button>
              ) : isIsolated ? (
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

              {incident.detection_evidence?.process && incident.process_activity === 'running' && culprit?.pid && !isKernelOrSystem(culprit) && (
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
            </>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              const targetAgent = incident.agentId || incident.agent_id || incident.agent_hostname || '';
              const target = culprit?.pid && culprit.process_start_time ? `&pid=${culprit.pid}&started=${culprit.process_start_time}` : '';
              navigate(`/investigate?tab=process${targetAgent ? `&agent=${encodeURIComponent(targetAgent)}` : ''}&incident=${encodeURIComponent(incident.id)}${target}`);
            }}
            title="Open culprit process in interactive root cause tree"
          >
            🌳 Jump to Process Tree
          </Button>
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
                  <span style={{ display: 'block' }}>
                    {incident.detection_activity || 'historical'} · {incident.incident_status || incident.status}
                    {incident.disposition && ` · ${incident.disposition}`}
                  </span>
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
