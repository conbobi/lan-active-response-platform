import React from 'react';
import OSILayer from './OSILayer';

const RISK_BADGE = {
  high:   'bg-red-600 text-white',
  medium: 'bg-orange-600 text-white',
  low:    'bg-green-600 text-white',
};

const C2_PORTS = [4444, 4445, 5555, 1337, 31337, 9001, 9002];

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

export default function ConnectionDetail({ conn, onClose, onBlockIP, onKillProcess, onInvestigate }) {
  if (!conn) return null;
  
  const isC2Port = C2_PORTS.includes(conn.dst_port);
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
      </Section>
      
      <Section title="🎯 Destination">
        <Field label="IP" value={conn.dst_ip} mono />
        <Field label="Port" value={conn.dst_port} mono highlight={isC2Port} />
        <Field label="Protocol" value={conn.protocol} mono />
      </Section>
      
      <Section title="🔍 OSI Breakdown">
        <OSILayer layer="L3" label="Network" value={`${conn.dst_ip}/24`} />
        <OSILayer 
          layer="L4" 
          label="Transport" 
          value={`${conn.protocol}:${conn.dst_port}`}
          note={isC2Port ? '⚠ Cổng C2 phổ biến' : null}
          warning={isC2Port}
        />
        <OSILayer 
          layer="L7" 
          label="Application" 
          value={isC2Port ? 'Unknown (raw TCP)' : 'HTTP/TLS'}
        />
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
      
      <div className="mt-auto p-4 border-t space-y-2 bg-gray-50">
        <button
          onClick={onBlockIP}
          className="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded text-sm font-medium"
        >
          🚫 Block IP
        </button>
        <button
          onClick={onKillProcess}
          className="w-full bg-orange-600 hover:bg-orange-700 text-white py-2 rounded text-sm font-medium"
        >
          🛑 Kill Process
        </button>
        <button
          onClick={onInvestigate}
          className="w-full border border-gray-300 hover:bg-gray-100 py-2 rounded text-sm font-medium"
        >
          🔍 Full Investigation
        </button>
      </div>
    </aside>
  );
}
