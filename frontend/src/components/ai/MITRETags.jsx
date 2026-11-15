import React from 'react';

export default function MITRETags({ techniques = [], max = 3, onTagClick }) {
  if (!techniques || techniques.length === 0) {
    return <span style={{ fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic' }}>None</span>;
  }

  const visible = techniques.slice(0, max);
  const remaining = techniques.length - max;

  return (
    <div
      className="flex flex-wrap items-center gap-1.5"
      style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.375rem' }}
    >
      {visible.map((tech) => (
        <span
          key={tech}
          onClick={(e) => {
            if (onTagClick) {
              e.stopPropagation();
              onTagClick(tech);
            }
          }}
          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-red-500/10 text-red-300 border border-red-500/20 ${
            onTagClick ? 'cursor-pointer hover:bg-red-500/20 hover:border-red-500/40' : ''
          }`}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '0.125rem 0.5rem',
            borderRadius: '0.25rem',
            fontSize: '11px',
            fontFamily: 'ui-monospace, monospace',
            fontWeight: 500,
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            color: '#fca5a5',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            cursor: onTagClick ? 'pointer' : 'default',
            whiteSpace: 'nowrap'
          }}
          title={`MITRE ATT&CK: ${tech}`}
        >
          {tech}
        </span>
      ))}
      {remaining > 0 && (
        <span
          className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono text-gray-400 bg-gray-800 border border-gray-700"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '0.125rem 0.375rem',
            borderRadius: '0.25rem',
            fontSize: '10px',
            fontFamily: 'ui-monospace, monospace',
            color: '#94a3b8',
            backgroundColor: '#1f2937',
            border: '1px solid #374151',
            whiteSpace: 'nowrap'
          }}
          title={techniques.slice(max).join(', ')}
        >
          +{remaining}
        </span>
      )}
    </div>
  );
}
