// src/components/agents/AgentSecurityContext.jsx
import React, { useState, useEffect } from 'react';
import { getIncidents } from '../../api/incidents';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import IncidentDetailModal from '../incidents/IncidentDetailModal';
import {
  FiAlertTriangle,
  FiCheckCircle,
  FiShield,
  FiClock,
  FiEye,
  FiActivity,
  FiBookOpen,
  FiLock
} from 'react-icons/fi';

export default function AgentSecurityContext({ agent }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const fetchAgentIncidents = async () => {
    if (!agent?.id) return;
    setLoading(true);
    try {
      const all = await getIncidents();
      const agentIncs = all.filter((inc) => inc.agentId === agent.id);
      setIncidents(agentIncs);
    } catch (err) {
      console.error('Failed to fetch incidents for agent:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgentIncidents();
  }, [agent?.id]);

  const activeIncidents = incidents.filter(
    (i) => i.status !== 'resolved' && i.status !== 'closed' && i.status !== 'false_positive'
  );

  const renderSeverityBadge = (sev) => {
    const s = sev ? sev.toLowerCase() : 'medium';
    if (s === 'critical') return <Badge status="critical" label="CRITICAL" />;
    if (s === 'high') return <Badge status="danger" label="HIGH" />;
    if (s === 'medium') return <Badge status="warning" label="MEDIUM" />;
    return <Badge status="info" label="LOW" />;
  };

  const renderStatusBadge = (status) => {
    switch (status) {
      case 'open':
        return <Badge status="danger" label="Open" />;
      case 'investigating':
        return <Badge status="warning" label="Investigating" />;
      case 'contained':
        return <Badge status="info" label="Contained" />;
      case 'resolved':
        return <Badge status="success" label="Resolved" />;
      default:
        return <Badge status="neutral" label={status} />;
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.875rem' }}>
        <FiActivity className="animate-spin" style={{ display: 'inline', marginRight: '0.5rem' }} />
        Đang quét tình trạng an ninh của máy trạm {agent.hostname || agent.id}...
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Active Threats Section */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield size={16} color={activeIncidents.length > 0 ? 'var(--error)' : 'var(--success)'} />
            Mối đe dọa đang hoạt động ({activeIncidents.length})
          </h4>
          {agent.is_isolated && (
            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--warning)', background: 'rgba(234, 179, 8, 0.1)', padding: '0.2rem 0.5rem', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(234, 179, 8, 0.3)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <FiLock size={12} /> HOST ISOLATED
            </span>
          )}
        </div>

        {activeIncidents.length === 0 ? (
          <div
            style={{
              padding: '1.75rem 1rem',
              textAlign: 'center',
              background: 'rgba(34, 197, 94, 0.05)',
              border: '1px solid rgba(34, 197, 94, 0.2)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--success)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <FiCheckCircle size={28} />
            <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>
              ✅ Agent an toàn, không có mối đe dọa
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Không phát hiện tiến trình độc hại, hành vi C2 hoặc vi phạm chính sách chưa xử lý.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {activeIncidents.map((inc) => (
              <div
                key={inc.id}
                style={{
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  borderLeft: inc.severity === 'critical' ? '4px solid var(--error)' : '4px solid var(--warning)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '1rem',
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    {renderSeverityBadge(inc.severity)}
                    {renderStatusBadge(inc.status)}
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <FiClock size={11} /> {new Date(inc.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {inc.title}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {inc.description}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>Risk Score</div>
                    <div style={{ fontWeight: 800, fontSize: '1rem', color: inc.riskScore >= 80 ? 'var(--error)' : 'var(--warning)' }}>
                      {inc.riskScore}/100
                    </div>
                  </div>
                  <Button
                    variant="primary"
                    size="sm"
                    iconLeft={<FiBookOpen size={14} />}
                    onClick={() => setSelectedIncident(inc)}
                  >
                    📖 View Story
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Resolved History Quick Preview */}
      {incidents.filter((i) => i.status === 'resolved' || i.status === 'closed').length > 0 && (
        <div style={{ marginTop: '0.5rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', marginBottom: '0.4rem' }}>
            Lịch sử sự cố đã giải quyết ({incidents.filter((i) => i.status === 'resolved' || i.status === 'closed').length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            {incidents.filter((i) => i.status === 'resolved' || i.status === 'closed').slice(0, 2).map((inc) => (
              <div
                key={inc.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  fontSize: '0.8rem',
                  padding: '0.4rem 0.6rem',
                  background: 'var(--bg)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <span style={{ color: 'var(--text-secondary)' }}>{inc.title}</span>
                <Button variant="ghost" size="xs" onClick={() => setSelectedIncident(inc)}>
                  Chi tiết
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5-Tab Storyboard Modal popup from Agent Detail */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onRefresh={fetchAgentIncidents}
        />
      )}
    </div>
  );
}
