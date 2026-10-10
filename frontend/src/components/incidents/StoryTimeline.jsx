// src/components/incidents/StoryTimeline.jsx
import React, { useState, useEffect } from 'react';
import { getIncidentTimeline } from '../../api/incidents';
import Button from '../ui/Button';
import {
  FiTerminal,
  FiGlobe,
  FiAlertTriangle,
  FiCheckCircle,
  FiShield,
  FiChevronDown,
  FiChevronUp,
  FiSlash,
  FiLock,
  FiRotateCcw,
  FiClock,
  FiRefreshCw
} from 'react-icons/fi';

export default function StoryTimeline({
  incidentId,
  onAction,
  actionLoading,
}) {
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedIndices, setExpandedIndices] = useState(new Set([0, 1, 2, 3])); // expand top events by default

  const fetchTimelineData = async () => {
    if (!incidentId) return;
    setLoading(true);
    try {
      const items = await getIncidentTimeline(incidentId);
      setTimeline(Array.isArray(items) ? items : []);
    } catch (err) {
      console.warn('Failed to fetch timeline:', err);
      setTimeline([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimelineData();
  }, [incidentId]);

  const toggleExpand = (idx) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const getEventIcon = (type) => {
    switch (type) {
      case 'process_spawn':
        return <FiTerminal size={15} />;
      case 'network':
        return <FiGlobe size={15} />;
      case 'rule_trigger':
        return <FiAlertTriangle size={15} />;
      case 'action':
        return <FiShield size={15} />;
      default:
        return <FiClock size={15} />;
    }
  };

  const getSeverityColors = (severity) => {
    switch (severity) {
      case 'critical':
        return {
          color: 'var(--error)',
          bg: 'rgba(239, 68, 68, 0.15)',
          border: 'rgba(239, 68, 68, 0.4)',
        };
      case 'warning':
        return {
          color: 'var(--warning)',
          bg: 'rgba(245, 158, 11, 0.15)',
          border: 'rgba(245, 158, 11, 0.4)',
        };
      case 'success':
        return {
          color: 'var(--success)',
          bg: 'rgba(34, 197, 94, 0.15)',
          border: 'rgba(34, 197, 94, 0.4)',
        };
      case 'info':
      default:
        return {
          color: 'var(--primary)',
          bg: 'rgba(97, 0, 255, 0.15)',
          border: 'rgba(97, 0, 255, 0.4)',
        };
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
        <FiRefreshCw className="animate-spin" size={24} style={{ margin: '0 auto 0.75rem' }} />
        <p>Synthesizing chronological incident story from telemetry...</p>
      </div>
    );
  }

  if (timeline.length === 0) {
    return (
      <div
        style={{
          textAlign: 'center',
          padding: '2.5rem',
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
          color: 'var(--text-tertiary)',
        }}
      >
        <FiAlertTriangle size={32} style={{ margin: '0 auto 0.5rem', opacity: 0.5 }} />
        <p>No timeline events available for this incident yet.</p>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', paddingLeft: '1rem', marginTop: '0.5rem' }}>
      {/* Vertical Track Line */}
      <div
        style={{
          position: 'absolute',
          left: '1.75rem',
          top: '0.5rem',
          bottom: '1rem',
          width: '2px',
          background: 'var(--border)',
          zIndex: 1,
        }}
      />

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {timeline.map((item, idx) => {
          const colors = getSeverityColors(item.severity);
          const isExpanded = expandedIndices.has(idx);
          const eventTime = item.time ? new Date(item.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';

          return (
            <div key={idx} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start', position: 'relative', zIndex: 2 }}>
              {/* Event Icon Node */}
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  background: colors.bg,
                  color: colors.color,
                  border: `2px solid ${colors.color}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  boxShadow: '0 0 10px rgba(0,0,0,0.5)',
                }}
              >
                {getEventIcon(item.type)}
              </div>

              {/* Event Card */}
              <div
                style={{
                  flex: 1,
                  background: 'var(--bg-secondary)',
                  border: `1px solid ${colors.border}`,
                  borderRadius: 'var(--radius-sm)',
                  overflow: 'hidden',
                  transition: 'all 0.2s ease',
                }}
              >
                {/* Header */}
                <div
                  onClick={() => toggleExpand(idx)}
                  style={{
                    padding: '0.65rem 1rem',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: 'pointer',
                    background: 'rgba(255, 255, 255, 0.02)',
                    userSelect: 'none',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <span
                      style={{
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '0.15rem 0.4rem',
                        borderRadius: 'var(--radius-xs)',
                        background: colors.bg,
                        color: colors.color,
                      }}
                    >
                      {item.type.replace('_', ' ')}
                    </span>
                    <strong style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                      {item.title}
                    </strong>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <FiClock size={12} /> {eventTime}
                    </span>
                    {isExpanded ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                  </div>
                </div>

                {/* Details Section */}
                {isExpanded && item.details && (
                  <div
                    style={{
                      padding: '0.75rem 1rem',
                      borderTop: '1px solid var(--border)',
                      fontSize: '0.82rem',
                      color: 'var(--text-secondary)',
                      background: 'rgba(0, 0, 0, 0.2)',
                    }}
                  >
                    {/* Process Spawn specifics */}
                    {item.type === 'process_spawn' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        <div>
                          <strong>PID:</strong> <code style={{ color: 'var(--primary)' }}>{item.details.pid}</code> |{' '}
                          <strong>Name:</strong> <code>{item.details.name}</code>
                        </div>
                        {item.details.path && (
                          <div>
                            <strong>Path:</strong> <code>{item.details.path}</code>
                          </div>
                        )}
                        {item.details.cmdline && (
                          <div>
                            <strong>Commandline:</strong> <code style={{ color: 'var(--warning)' }}>{item.details.cmdline}</code>
                          </div>
                        )}
                        {item.details.parent && (
                          <div>
                            <strong>Parent:</strong> {item.details.parent.name} (PID: {item.details.parent.pid})
                          </div>
                        )}
                        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
                          <Button
                            variant="danger"
                            size="sm"
                            disabled={actionLoading}
                            iconLeft={<FiSlash size={12} />}
                            onClick={() => onAction && onAction('kill_process_tree', { pid: item.details.pid, process_name: item.details.name })}
                          >
                            Kill PID {item.details.pid}
                          </Button>
                        </div>
                      </div>
                    )}

                    {/* Network specifics */}
                    {item.type === 'network' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        <div>
                          <strong>Destination:</strong>{' '}
                          <code style={{ color: 'var(--warning)' }}>
                            {item.details.dst_ip}:{item.details.dst_port}
                          </code>{' '}
                          ({item.details.protocol || 'TCP'})
                        </div>
                        {item.details.bytes_sent != null && (
                          <div>
                            <strong>Traffic:</strong> {item.details.bytes_sent} bytes ({item.details.packets_sent || 0} packets)
                          </div>
                        )}
                        <div style={{ marginTop: '0.5rem' }}>
                          <Button
                            variant="warning"
                            size="sm"
                            disabled={actionLoading}
                            iconLeft={<FiLock size={12} />}
                            onClick={() => onAction && onAction('block_ip', { ip: item.details.dst_ip })}
                          >
                            Block IP {item.details.dst_ip}
                          </Button>
                        </div>
                      </div>
                    )}

                    {/* Rule Trigger specifics */}
                    {item.type === 'rule_trigger' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        <div>
                          <strong>Rule ID:</strong> <code>{item.details.rule}</code> |{' '}
                          <strong>Score Contribution:</strong>{' '}
                          <span style={{ color: colors.color, fontWeight: 700 }}>+{item.details.score}</span>
                        </div>
                        <div style={{ color: 'var(--text-primary)', fontStyle: 'italic', marginTop: '0.2rem' }}>
                          "{item.details.reason}"
                        </div>
                      </div>
                    )}

                    {/* Action specifics */}
                    {item.type === 'action' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        <div>
                          <strong>Action ID:</strong> <code>{item.details.action_id}</code> |{' '}
                          <strong>Status:</strong>{' '}
                          <span style={{ color: colors.color, fontWeight: 700, textTransform: 'uppercase' }}>
                            {item.details.status}
                          </span>
                        </div>
                        {item.details.snapshot && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.25rem' }}>
                            Host snapshot captured: {item.details.snapshot.action_type || 'system_state'} pre-action baseline
                          </div>
                        )}
                        {item.details.status === 'applied' && (
                          <div style={{ marginTop: '0.5rem' }}>
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={actionLoading}
                              iconLeft={<FiRotateCcw size={12} />}
                              onClick={() => onAction && onAction('unisolate')}
                            >
                              Rollback Action
                            </Button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
