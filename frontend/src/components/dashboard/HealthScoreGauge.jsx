import React from 'react';

export default function HealthScoreGauge({ agents = [], incidents = [], loading = false }) {
  // 1. Guard null
  const safeAgents = Array.isArray(agents) ? agents : [];
  const safeIncidents = Array.isArray(incidents) ? incidents : [];
  
  // 2. Helper getScore (xử lý risk_score ?? score)
  const getScore = (i) => {
    const v = i?.risk_score ?? i?.riskScore ?? i?.score;
    return typeof v === 'number' ? v : 0;
  };
  
  // 3. Tìm critical incidents CHƯA resolved
  const unresolvedCritical = safeIncidents.filter(i => {
    const score = getScore(i);
    const isResolved = ['resolved', 'false_positive', 'reverted'].includes(i.status);
    return score >= 85 && !isResolved;
  });
  
  // 4. Tìm medium incidents
  const unresolvedMedium = safeIncidents.filter(i => {
    const score = getScore(i);
    const isResolved = ['resolved', 'false_positive'].includes(i.status);
    return score >= 30 && score < 85 && !isResolved;
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
          Health Score: <span className="font-semibold text-gray-900 text-xl">{healthScore}</span>/100
        </div>
        
        {unresolvedCritical.length > 0 && (
          <div className="bg-red-100 border border-red-300 rounded-lg p-3 mb-4">
            <div className="text-red-800 font-semibold">
              🚨 {unresolvedCritical.length} critical attack{unresolvedCritical.length > 1 ? 's' : ''} chưa xử lý
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
