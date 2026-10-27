import React from 'react';

const RISK = {
  high:   { bg: 'bg-red-50',    border: 'border-red-200',    badge: 'bg-red-600 text-white',    icon: '🔴', label: 'HIGH' },
  medium: { bg: 'bg-orange-50', border: 'border-orange-200', badge: 'bg-orange-600 text-white', icon: '🟠', label: 'MEDIUM' },
  low:    { bg: 'bg-green-50',  border: 'border-green-200',  badge: 'bg-green-600 text-white',  icon: '🟢', label: 'LOW' },
};

function getTimeAgo(ts) {
  if (!ts) return '—';
  const mins = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
  if (mins < 1) return 'vừa xong';
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  return `${Math.floor(hours / 24)} ngày trước`;
}

export default function ConnectionRow({ conn, onClick, isActive }) {
  const risk = RISK[conn.risk_level] || RISK.low;
  
  return (
    <div
      onClick={onClick}
      className={`${risk.bg} ${risk.border} border rounded-lg p-4 cursor-pointer transition-all
        ${isActive ? 'ring-2 ring-blue-500 shadow-md' : 'hover:shadow-md'}`}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <span className="font-mono font-semibold text-gray-900 truncate">
            {conn.process_name}
          </span>
          <span className="text-gray-400">→</span>
          <span className="font-mono text-sm text-gray-700 truncate">
            {conn.dst_ip}:{conn.dst_port}
          </span>
        </div>
        <span className={`${risk.badge} px-2 py-1 rounded text-xs font-semibold flex-shrink-0 ml-2`}>
          {risk.icon} {risk.label}
        </span>
      </div>
      
      <div className="text-sm text-gray-600 mb-2">
        ⚠ {conn.reason}
      </div>
      
      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>
          Agent: <b>{conn.agent_id}</b> · {getTimeAgo(conn.last_seen)}
        </span>
      </div>
    </div>
  );
}
