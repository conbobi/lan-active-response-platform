import React from 'react';
import { useNavigate } from 'react-router-dom';
import InfoTooltip from '../ui/InfoTooltip';
import { TOOLTIPS } from '../../constants/tooltips';

function getTimeAgo(timestamp) {
  if (!timestamp) return '';
  const mins = Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000);
  if (mins < 1) return 'vừa xong';
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  return `${Math.floor(hours / 24)} ngày trước`;
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
  // Parse từ description hoặc factors
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

export default function HealthScoreGauge({ agents = [], incidents = [], loading = false }) {
  const navigate = useNavigate();

  // 1. Guard null
  const safeAgents = Array.isArray(agents) ? agents : [];
  const safeIncidents = Array.isArray(incidents) ? incidents : [];

  // ===== HELPER: Agent còn sống không? =====
  const ALIVE_STATUSES = [
    'active', 'online', 'ACTIVE',
    'isolated', 'ISOLATED',           // Isolated vẫn là alive
    'quarantine', 'QUARANTINE',       // Quarantine vẫn là alive
  ];

  const isAgentAlive = (agent) => {
    if (!agent) return false;

    // Check status
    const status = String(agent.status || '').toLowerCase();
    if (['dead', 'offline', 'inactive'].includes(status)) {
      return false;
    }
    if (ALIVE_STATUSES.map(s => s.toLowerCase()).includes(status)) {
      return true;
    }

    // Fallback: check last_seen trong 5 phút
    if (agent.last_seen) {
      const age = Date.now() - new Date(agent.last_seen).getTime();
      return age < 5 * 60 * 1000;  // 5 phút
    }

    return false;
  };

  // ===== BUILD MAP: agent_id → alive? =====
  const agentAliveMap = new Map(
    safeAgents.map(a => [a.id, isAgentAlive(a)])
  );

  const isIncidentOnLiveAgent = (incident) => {
    const agentId = incident?.agent_id || incident?.agentId;
    if (!agentId) return false;
    // Nếu không tìm thấy agent trong danh sách → coi như dead (stale data)
    if (!agentAliveMap.has(agentId)) return false;
    return agentAliveMap.get(agentId);
  };

  // 2. Helper getScore (xử lý risk_score ?? score)
  const getScore = (i) => {
    const v = i?.risk_score ?? i?.riskScore ?? i?.score;
    return typeof v === 'number' ? v : 0;
  };

  // 3. Time filter: chỉ tính incident trong 24h
  const now = Date.now();
  const MAX_INCIDENT_AGE_MS = 24 * 60 * 60 * 1000;

  const isRecentIncident = (i) => {
    const createdAt = new Date(i.created_at || i.createdAt || i.timestamp).getTime();
    if (isNaN(createdAt)) return false;
    return (now - createdAt) < MAX_INCIDENT_AGE_MS;
  };

  // ===== FILTER: Critical incidents trên agent alive, trong 24h =====
  const unresolvedCritical = safeIncidents.filter(i => {
    const score = getScore(i);
    const st = String(i.status || '').toLowerCase();
    const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
    if (isResolved) return false;
    if (score < 85) return false;
    if (!isRecentIncident(i)) return false;
    if (!isIncidentOnLiveAgent(i)) return false;   // ← KEY FILTER
    return true;
  });

  // ===== FILTER: Medium incidents tương tự =====
  const unresolvedMedium = safeIncidents.filter(i => {
    const score = getScore(i);
    const st = String(i.status || '').toLowerCase();
    const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
    if (isResolved) return false;
    if (score < 30 || score >= 85) return false;
    if (!isRecentIncident(i)) return false;
    if (!isIncidentOnLiveAgent(i)) return false;   // ← KEY FILTER
    return true;
  });

  // ===== Count agents alive =====
  const aliveAgents = safeAgents.filter(isAgentAlive);
  const offlineAgents = safeAgents.length - aliveAgents.length;

  // 6. Health Score LOGIC: MIN(penalties), KHÔNG phải sum
  let healthScore = 100;
  let level = 'safe';

  // PRIORITY 1: Critical attack = NGUY HIỂM (force đỏ)
  if (unresolvedCritical.length > 0) {
    healthScore = Math.max(0, 40 - unresolvedCritical.length * 15);
    // 1 critical → 25, 2 critical → 10
    level = 'critical';
  }
  // PRIORITY 2: Multiple mediums
  else if (unresolvedMedium.length >= 3) {
    healthScore = Math.min(healthScore, 55);
    level = 'warning';
  }
  // PRIORITY 3: Offline agents
  else if (offlineAgents >= 2) {
    healthScore = Math.min(healthScore, 70);
    level = 'warning';
  }

  // 7. Loading skeleton
  if (loading) {
    return (
      <div className="skeleton" style={{ height: '140px', borderRadius: 'var(--radius-lg)', marginBottom: '1.5rem' }} />
    );
  }

  // 8. Config theo level
  const config = {
    safe: { icon: '🟢', color: 'var(--success)', bg: 'var(--success-dim)', border: 'rgba(63, 185, 80, 0.4)', text: 'HỆ THỐNG AN TOÀN' },
    warning: { icon: '🟡', color: 'var(--warning)', bg: 'var(--warning-dim)', border: 'rgba(210, 153, 34, 0.4)', text: 'CẦN CHÚ Ý' },
    critical: { icon: '🔴', color: 'var(--critical)', bg: 'var(--critical-dim)', border: 'rgba(255, 123, 114, 0.5)', text: 'NGUY HIỂM' },
  }[level];

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: `1px solid ${config.border}`,
      boxShadow: level === 'critical' ? '0 0 16px var(--critical-glow)' : 'var(--shadow-sm)',
      borderRadius: 'var(--radius-lg)',
      padding: '2rem',
      marginBottom: '1.5rem',
      transition: 'all 0.3s ease',
    }}>
      <div className="text-center">
        <div style={{ fontSize: '3rem', marginBottom: '0.75rem' }}>
          {config.icon}
        </div>
        <div style={{ fontSize: '1.75rem', fontWeight: 800, marginBottom: '0.5rem', color: config.color, letterSpacing: '-0.02em' }}>
          {config.text}
        </div>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.95rem' }}>
          <InfoTooltip {...TOOLTIPS.HealthScore}>Health Score</InfoTooltip>: <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '1.25rem' }}>{healthScore}</span>/100
        </div>

        {/* Agents summary */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '1.5rem', fontSize: '0.875rem', marginBottom: '1rem' }}>
          <div>
            <span style={{ fontWeight: 700, color: 'var(--success)' }}>{aliveAgents.length}</span>
            <span style={{ color: 'var(--text-secondary)', marginLeft: '0.25rem' }}>agents alive</span>
          </div>
          {offlineAgents > 0 && (
            <div>
              <span style={{ fontWeight: 700, color: 'var(--text-tertiary)' }}>{offlineAgents}</span>
              <span style={{ color: 'var(--text-secondary)', marginLeft: '0.25rem' }}>offline</span>
            </div>
          )}
        </div>

        {unresolvedCritical.length > 0 && (
          <div style={{
            background: 'var(--critical-dim)',
            border: '1px solid rgba(255, 123, 114, 0.35)',
            borderRadius: 'var(--radius-sm)',
            padding: '0.75rem 1rem',
            marginBottom: '1rem',
          }}>
            <div style={{ color: 'var(--critical)', fontWeight: 600, fontSize: '0.9rem' }}>
              🚨 {unresolvedCritical.length} critical attack{unresolvedCritical.length > 1 ? 's' : ''} chưa xử lý
            </div>
          </div>
        )}

        {/* Critical Incidents Context List */}
        {unresolvedCritical.length > 0 && (
          <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', textAlign: 'left' }}>
            <div style={{ color: 'var(--critical)', fontWeight: 600, marginBottom: '0.25rem', fontSize: '0.875rem' }}>
              ⚠️ Cần xử lý NGAY:
            </div>
            {unresolvedCritical.slice(0, 3).map(incident => {
              const score = getScore(incident);
              const agentId = incident.agent_id || incident.agentId || 'Unknown Host';
              const attackType = extractAttackType(incident);
              const timeAgo = getTimeAgo(incident.created_at || incident.createdAt || incident.timestamp);
              const isIsolated = incident.status === 'contained' ||
                incident.status === 'isolated' ||
                incident.action_taken === 'isolate' ||
                incident.actions_taken?.some?.(a => a.action_type === 'isolate');

              return (
                <div key={incident.id}
                  style={{
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 'var(--radius-md)',
                    padding: '0.75rem 1rem',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--bg-elevated)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'var(--bg-tertiary)'; }}
                  onClick={() => navigate(`/incidents/${incident.id}`)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <span>🚨</span>
                        <span style={{ fontWeight: 700, color: 'var(--critical)', fontSize: '0.875rem' }}>
                          {agentId}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                          · {timeAgo}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--text-primary)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        Attack: {attackType}
                      </div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        Score: <strong style={{ color: 'var(--text-primary)' }}>{score}/100</strong>
                        {isIsolated && <span style={{ marginLeft: '0.5rem', color: 'var(--success)', fontWeight: 600 }}>· 🛡 AUTO-ISOLATED</span>}
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/incidents/${incident.id}`);
                      }}
                      style={{ color: 'var(--primary)', background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                      Xem →
                    </button>
                  </div>
                </div>
              );
            })}
            {unresolvedCritical.length > 3 && (
              <div style={{ textAlign: 'center', fontSize: '0.85rem', color: 'var(--text-secondary)', padding: '0.5rem 0' }}>
                và {unresolvedCritical.length - 3} sự cố khác...
              </div>
            )}
          </div>
        )}

        {/* Helper text */}
        <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '1rem' }}>
          (Chỉ tính agents đang hoạt động + incidents trong 24h)
        </div>
      </div>
    </div>
  );
}
