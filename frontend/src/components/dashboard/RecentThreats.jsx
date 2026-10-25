import React from 'react';
import { useNavigate } from 'react-router-dom';

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
    if (rules.includes('c2_communication') || rules.includes('http_beaconing') || rules.includes('dns_tunneling')) return 'C2 Communication';
    if (rules.includes('ml_behavioral_anomaly')) return 'Behavioral Anomaly';
    if (rules.includes('suspicious_process')) return 'Suspicious Process';
  }
  if (factors.process_chain) {
    const match = String(factors.process_chain).match(/'([^']+)'\s+spawned\s+'([^']+)'/);
    if (match) return `${match[1]} → ${match[2]}`;
  }
  if (factors.living_off_land) return 'LOLBin Abuse';
  if (factors.credential_dumping) return 'Credential Dumping';
  if (factors.c2_communication) return 'C2 Communication';
  if (factors.suspicious_process) return 'Suspicious Process';
  if (factors.ml_behavioral_anomaly) return 'Behavioral Anomaly';
  return incident.title || incident.description || 'Unknown Attack';
}

export default function RecentThreats({ incidents = [] }) {
  const navigate = useNavigate();
  
  const now = Date.now();
  const MAX_THREAT_AGE_MS = 24 * 60 * 60 * 1000;

  const threats = (Array.isArray(incidents) ? incidents : [])
    .filter(i => {
      const score = getScore(i);
      const st = String(i.status || '').toLowerCase();
      const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
      if (score < 30 || isResolved) return false;
      const createdAt = new Date(i.created_at || i.createdAt || i.timestamp).getTime();
      if (!isNaN(createdAt) && (now - createdAt) > MAX_THREAT_AGE_MS) return false;
      return true;
    })
    .sort((a, b) => new Date(b.created_at || b.createdAt) - new Date(a.created_at || a.createdAt))
    .slice(0, 5);
  
  if (threats.length === 0) {
    return (
      <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <h3 style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '1rem' }}>
          🚨 Recent Threats
        </h3>
        <div style={{ textAlign: 'center', padding: '2rem 0', color: '#16a34a' }}>
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>✅</div>
          <div style={{ fontWeight: 600 }}>Không có mối đe dọa</div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
            Hệ thống đang an toàn trong 24h qua
          </div>
        </div>
      </div>
    );
  }
  
  return (
    <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h3 style={{ fontWeight: 700, fontSize: '0.95rem' }}>
          🚨 Recent Threats
        </h3>
        <button
          onClick={() => navigate('/incidents')}
          style={{ fontSize: '0.75rem', color: '#2563eb', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>
          Xem tất cả →
        </button>
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {threats.map(incident => {
          const score = getScore(incident);
          const severity = score >= 85 ? 'critical' : score >= 50 ? 'high' : 'medium';
          const attackType = extractAttackType(incident);
          
          const bgColor = severity === 'critical' ? '#fef2f2' :
                         severity === 'high' ? '#fff7ed' : '#fefce8';
          const borderColor = severity === 'critical' ? '#dc2626' :
                             severity === 'high' ? '#ea580c' : '#ca8a04';
          
          return (
            <div
              key={incident.id}
              onClick={() => navigate(`/incidents/${incident.id}`)}
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
                e.currentTarget.style.boxShadow = '0 2px 4px rgba(0,0,0,0.05)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.transform = 'translateX(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#0f172a' }}>
                    {incident.agent_id} · {getTimeAgo(incident.created_at || incident.createdAt)}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.2rem', 
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {attackType}
                  </div>
                </div>
                <span style={{
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  background: borderColor,
                  color: 'white',
                  marginLeft: '0.5rem'
                }}>
                  {score}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
