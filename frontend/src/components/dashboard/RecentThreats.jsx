import React from 'react';
import { useNavigate } from 'react-router-dom';
import { FiTrash2 } from 'react-icons/fi';

function getScore(i) {
  const v = i?.risk_score ?? i?.riskScore ?? i?.score;
  return typeof v === 'number' ? v : 0;
}

function getTimeAgo(timestamp) {
  if (!timestamp) return '';
  const mins = Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000);
  if (mins < 1) return 'vừa xong';
  if (mins < 60) return `${mins}p`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

function extractAttackType(incident) {
  if (incident.detection_evidence?.behavior?.classification) return incident.detection_evidence.behavior.classification;
  if (incident.detection_evidence?.classification) return incident.detection_evidence.classification;
  if (incident.parent_process?.name && incident.culprit_process?.name) {
    return `${incident.parent_process.name} → ${incident.culprit_process.name}`;
  }
  const factors = incident.factors || {};
  if (Array.isArray(incident.factors_breakdown)) {
    const pc = incident.factors_breakdown.find(f => f.rule === 'process_chain');
    if (pc) {
      const match = String(pc.reason || '').match(/'([^']+)'\s+spawned\s+'([^']+)'/);
      if (match) return `${match[1]} → ${match[2]}`;
    }
    const rules = incident.factors_breakdown.map(f => f.rule);
    if (rules.includes('living_off_land')) return 'LOLBin Abuse';
    if (rules.includes('credential_dumping')) return 'Credential Dumping';
    if (rules.includes('c2_communication') || rules.includes('http_beaconing') || rules.includes('dns_tunneling')) return 'Possible C2 Communication';
    if (rules.includes('ml_behavioral_anomaly')) return 'Behavioral Anomaly';
    if (rules.includes('suspicious_process')) return 'Suspicious Process';
  }
  if (factors.process_chain) {
    const match = String(factors.process_chain).match(/'([^']+)'\s+spawned\s+'([^']+)'/);
    if (match) return `${match[1]} → ${match[2]}`;
  }
  if (factors.living_off_land) return 'LOLBin Abuse';
  if (factors.credential_dumping) return 'Credential Dumping';
  if (factors.c2_communication) return 'Possible C2 Communication';
  if (factors.suspicious_process) return 'Suspicious Process';
  if (factors.ml_behavioral_anomaly) return 'Behavioral Anomaly';
  return incident.title || incident.description || 'Unknown Attack';
}

export default function RecentThreats({ incidents = [], onSelectIncident, onDeleteIncident, onClearAll }) {
  const navigate = useNavigate();
  
  const threats = incidents.filter(incident => getScore(incident) >= 30).slice(0, 5);

  if (threats.length === 0) {
    return (
      <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <h3 style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '1rem', color: 'var(--text-primary)' }}>
          Recent Detections
        </h3>
        <div style={{ textAlign: 'center', padding: '2rem 0', color: 'var(--success)' }}>
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>✅</div>
          <div style={{ fontWeight: 600 }}>Chưa có phát hiện gần đây</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Cửa sổ lịch sử 24 giờ
          </div>
        </div>
      </div>
    );
  }
  
  return (
    <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)', margin: 0 }}>
            Recent Detections
          </h3>
          <span style={{
            fontSize: '0.7rem',
            fontWeight: 600,
            background: 'rgba(239, 68, 68, 0.15)',
            color: 'var(--error, #ef4444)',
            padding: '0.1rem 0.45rem',
            borderRadius: '9999px',
          }}>
            {threats.length}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {onClearAll && (
            <button
              onClick={() => onClearAll(threats)}
              title="Xóa danh sách phát hiện này khỏi database"
              style={{
                fontSize: '0.75rem',
                color: 'var(--error, #ef4444)',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem'
              }}>
              <FiTrash2 size={12} /> Xóa lịch sử
            </button>
          )}
          <button
            onClick={() => navigate('/incidents')}
            style={{ fontSize: '0.75rem', color: 'var(--primary)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>
            Xem tất cả →
          </button>
        </div>
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {threats.map(incident => {
          const score = getScore(incident);
          const severity = score >= 85 ? 'critical' : score >= 50 ? 'high' : 'medium';
          const attackType = extractAttackType(incident);
          
          const bgColor = severity === 'critical' ? 'var(--critical-dim)' :
                         severity === 'high' ? 'var(--error-dim)' : 'rgba(244, 63, 94, 0.15)';
          const borderColor = severity === 'critical' ? 'var(--critical)' :
                             severity === 'high' ? 'var(--error)' : '#f43f5e';
          
          return (
            <div
              key={incident.id}
              onClick={() => {
                if (onSelectIncident) {
                  onSelectIncident(incident);
                } else {
                  navigate(`/incidents/${incident.id}`);
                }
              }}
              style={{
                padding: '0.75rem',
                background: bgColor,
                borderLeft: `4px solid ${borderColor}`,
                borderRadius: '6px',
                cursor: 'pointer',
                transition: 'transform 0.15s, box-shadow 0.15s'
              }}
              onMouseEnter={e => {
                e.currentTarget.style.transform = 'translateX(4px)';
                e.currentTarget.style.boxShadow = '0 2px 4px rgba(0,0,0,0.3)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.transform = 'translateX(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                    {incident.agent_id || incident.agentId || 'Unknown Host'} · {getTimeAgo(incident.created_at || incident.createdAt)}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem', 
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {attackType} · {incident.detection_activity || 'historical'}
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginLeft: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      const proc = incident.culprit_process;
                      const target = proc?.pid && proc.process_start_time ? `&pid=${proc.pid}&started=${proc.process_start_time}` : '';
                      navigate(`/investigate?tab=process&agent=${encodeURIComponent(incident.agent_id)}&incident=${encodeURIComponent(incident.id)}${target}`);
                    }}
                    title="Open in Process Tree"
                    style={{
                      background: 'rgba(255,255,255,0.08)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      color: 'var(--text-primary)',
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      padding: '0.2rem 0.45rem',
                      cursor: 'pointer',
                    }}
                  >
                    🌳 Tree
                  </button>
                  <span style={{
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.5rem',
                    borderRadius: '4px',
                    background: borderColor,
                    color: '#ffffff',
                  }}>
                    {score}
                  </span>
                  {onDeleteIncident && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteIncident(incident, e);
                      }}
                      title="Xóa phát hiện này"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-tertiary)',
                        cursor: 'pointer',
                        padding: '0.2rem',
                        display: 'flex',
                        alignItems: 'center',
                        borderRadius: '4px',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--error, #ef4444)')}
                      onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-tertiary)')}
                    >
                      <FiTrash2 size={13} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
