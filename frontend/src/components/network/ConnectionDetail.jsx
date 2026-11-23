import React from 'react';

const RISK_BADGE = {
  high:   'bg-red-600 text-white',
  medium: 'bg-orange-600 text-white',
  low:    'bg-green-600 text-white',
};

function Section({ title, children }) {
  return (
    <div className="p-4 border-b border-gray-100">
      <h3 className="font-semibold text-sm text-gray-700 mb-3">{title}</h3>
      {children}
    </div>
  );
}

function Field({ label, value, mono, small, highlight }) {
  return (
    <div className="mb-2">
      <div className="text-xs text-gray-500">{label}</div>
      <div className={`text-sm ${mono ? 'font-mono' : ''} ${small ? 'text-xs' : ''} 
        ${highlight ? 'text-red-700 font-semibold' : 'text-gray-900'} break-all`}>
        {value ?? '—'}
      </div>
    </div>
  );
}

export default function ConnectionDetail({ conn, onClose, onInvestigate }) {
  if (!conn) return null;
  
  const socket = conn.socket_evidence;
  const reasons = conn.reasons || (conn.reason ? [conn.reason] : []);
  
  return (
    <aside className="w-[380px] border-l border-gray-200 bg-white h-full overflow-y-auto flex flex-col">
      <div className="p-4 border-b sticky top-0 bg-white z-10">
        <div className="flex justify-between items-start mb-2">
          <div className="min-w-0 flex-1">
            <div className="font-mono font-semibold text-gray-900 truncate">
              {conn.process_name}
            </div>
            <div className="text-sm text-gray-600 truncate">
              → {conn.dst_ip}:{conn.dst_port}
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 ml-2 flex-shrink-0">
            ✕
          </button>
        </div>
        <span className={`${RISK_BADGE[conn.risk_level] || RISK_BADGE.low} px-2 py-1 rounded text-xs font-semibold`}>
          {conn.risk_level?.toUpperCase()} RISK
        </span>
      </div>
      
      <Section title="📦 Process Context">
        <Field label="Name" value={conn.process_name} mono />
        <Field label="PID" value={conn.pid} mono />
        <Field label="Attribution" value={socket?.attribution_reason || socket?.attribution} />
        {socket?.holders?.map((holder) => (
          <Field key={holder.pid} label={`Holder PID ${holder.pid}`} value={holder.process_name} mono />
        ))}
      </Section>
      
      <Section title="Socket">
        <Field label="Local" value={`${conn.src_ip}:${conn.src_port}`} mono />
        <Field label="Remote" value={`${conn.dst_ip}:${conn.dst_port}`} mono />
        <Field label="State" value={[conn.protocol, socket?.status, socket?.direction].filter(Boolean).join(' · ')} />
        {socket?.overlay && <Field label="Overlay" value={socket.overlay} />}
      </Section>

      {reasons.length > 0 && (
        <Section title="📊 Why Flagged">
          <ul className="text-sm space-y-1">
            {reasons.map((r, i) => (
              <li key={i} className="flex gap-2 text-gray-700">
                <span className="text-red-500 flex-shrink-0">✓</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
      
      {onInvestigate && (
        <div className="mt-auto p-4 border-t bg-gray-50">
          <button onClick={onInvestigate} className="w-full border rounded py-2 text-sm">
            View verified process in tree
          </button>
        </div>
      )}
    </aside>
  );
}
