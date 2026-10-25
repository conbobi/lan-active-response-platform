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
  
  // 2. Helper getScore (xử lý risk_score ?? score)
  const getScore = (i) => {
    const v = i?.risk_score ?? i?.riskScore ?? i?.score;
    return typeof v === 'number' ? v : 0;
  };
  
  // 3. Time filter: chỉ tính incident trong 24h
  const now = Date.now();
  const MAX_INCIDENT_AGE_MS = 24 * 60 * 60 * 1000;

  const unresolvedCritical = safeIncidents.filter(i => {
    const score = getScore(i);
    const st = String(i.status || '').toLowerCase();
    const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
    if (isResolved) return false;
    if (score < 85) return false;
    
    const createdAt = new Date(i.created_at || i.createdAt || i.timestamp).getTime();
    if (isNaN(createdAt)) return false;
    return (now - createdAt) < MAX_INCIDENT_AGE_MS;
  });
  
  // 4. Tìm medium incidents trong 24h
  const unresolvedMedium = safeIncidents.filter(i => {
    const score = getScore(i);
    const st = String(i.status || '').toLowerCase();
    const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
    if (isResolved) return false;
    if (score < 30 || score >= 85) return false;
    
    const createdAt = new Date(i.created_at || i.createdAt || i.timestamp).getTime();
    if (isNaN(createdAt)) return false;
    return (now - createdAt) < MAX_INCIDENT_AGE_MS;
  });
  
  // 5. Agent offline
  const offlineAgents = safeAgents.filter(a => 
    !['active', 'online', 'ACTIVE'].includes(a.status)
  ).length;
  
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
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 mb-6 animate-pulse">
        <div className="h-24 bg-gray-200 rounded mb-4" />
        <div className="h-6 bg-gray-200 rounded w-1/2 mx-auto" />
      </div>
    );
  }
  
  // 8. Config theo level
  const config = {
    safe:     { icon: '🟢', color: 'text-green-600', bg: 'bg-green-50',  text: 'HỆ THỐNG AN TOÀN' },
    warning:  { icon: '🟡', color: 'text-yellow-600', bg: 'bg-yellow-50', text: 'CẦN CHÚ Ý' },
    critical: { icon: '🔴', color: 'text-red-600', bg: 'bg-red-50', text: 'NGUY HIỂM' },
  }[level];
  
  return (
    <div className={`rounded-xl shadow-sm border-2 p-8 mb-6 transition-all duration-500 ${config.bg} ${
      level === 'critical' ? 'border-red-500 animate-pulse' : 'border-gray-200'
    }`}>
      <div className="text-center">
        <div className={`text-6xl mb-4 ${level === 'critical' ? 'animate-bounce' : ''}`}>
          {config.icon}
        </div>
        <div className={`text-3xl font-bold mb-2 ${config.color}`}>
          {config.text}
        </div>
        <div className="text-gray-500 mb-6">
          <InfoTooltip {...TOOLTIPS.HealthScore}>Health Score</InfoTooltip>: <span className="font-semibold text-gray-900 text-xl">{healthScore}</span>/100
          <div className="text-xs text-gray-500 text-center mt-2">
            (Chỉ tính sự cố trong 24h gần nhất)
          </div>
        </div>
        
        {unresolvedCritical.length > 0 && (
          <div className="bg-red-100 border border-red-300 rounded-lg p-3 mb-4">
            <div className="text-red-800 font-semibold">
              🚨 {unresolvedCritical.length} critical attack{unresolvedCritical.length > 1 ? 's' : ''} chưa xử lý
            </div>
          </div>
        )}

        {/* Critical Incidents Context List (Fix #1) */}
        {unresolvedCritical.length > 0 && (
          <div className="mt-4 space-y-2 text-left">
            <div className="text-red-800 font-semibold mb-2 text-sm">
              ⚠️ Cần xử lý NGAY:
            </div>
            {unresolvedCritical.slice(0, 3).map(incident => {
              const score = getScore(incident);
              const attackType = extractAttackType(incident);
              const isIsolated = incident.status === 'contained' || 
                                incident.status === 'isolated' ||
                                incident.action_taken === 'isolate' ||
                                incident.actions_taken?.some?.(a => a.action_type === 'isolate');
              
              return (
                <div key={incident.id}
                     className="bg-white border border-red-300 rounded-lg p-3 
                                hover:bg-red-50 hover:border-red-500 cursor-pointer transition-all shadow-sm"
                     onClick={() => navigate(`/incidents/${incident.id}`)}>
                  <div className="flex justify-between items-start gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xl">🚨</span>
                        <span className="font-bold text-red-900">
                          {incident.agent_id}
                        </span>
                        <span className="text-xs text-gray-500">
                          · {getTimeAgo(incident.created_at || incident.createdAt)}
                        </span>
                      </div>
                      <div className="text-sm text-red-800 font-medium ml-7">
                        Attack: {attackType}
                      </div>
                      <div className="text-xs text-gray-600 ml-7 mt-1">
                        Score: <strong>{score}/100</strong>
                        {isIsolated && <span className="ml-2 text-green-700 font-semibold">· 🛡 AUTO-ISOLATED</span>}
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/incidents/${incident.id}`);
                      }}
                      className="text-blue-600 hover:underline text-sm font-semibold whitespace-nowrap">
                      Xem →
                    </button>
                  </div>
                </div>
              );
            })}
            {unresolvedCritical.length > 3 && (
              <div className="text-center text-sm text-gray-600 py-2">
                và {unresolvedCritical.length - 3} sự cố khác...
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
