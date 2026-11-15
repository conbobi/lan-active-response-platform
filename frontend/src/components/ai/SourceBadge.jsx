import React from 'react';
import { FiCpu, FiUser } from 'react-icons/fi';

export default function SourceBadge({ source }) {
  const isAI = !source || source.toLowerCase().includes('ai');

  if (isAI) {
    return (
      <span
        className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/30"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.25rem',
          padding: '0.15rem 0.5rem',
          borderRadius: '0.375rem',
          fontSize: '0.75rem',
          fontWeight: 600,
          backgroundColor: 'rgba(168, 85, 247, 0.15)',
          color: '#d8b4fe',
          border: '1px solid rgba(168, 85, 247, 0.3)',
          whiteSpace: 'nowrap'
        }}
      >
        <FiCpu size={11} className="text-purple-400" style={{ color: '#c084fc' }} />
        AI
      </span>
    );
  }

  return (
    <span
      className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-semibold bg-blue-500/15 text-blue-300 border border-blue-500/30"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.25rem',
        padding: '0.15rem 0.5rem',
        borderRadius: '0.375rem',
        fontSize: '0.75rem',
        fontWeight: 600,
        backgroundColor: 'rgba(59, 130, 246, 0.15)',
        color: '#93c5fd',
        border: '1px solid rgba(59, 130, 246, 0.3)',
        whiteSpace: 'nowrap'
      }}
    >
      <FiUser size={11} className="text-blue-400" style={{ color: '#60a5fa' }} />
      Human
    </span>
  );
}
