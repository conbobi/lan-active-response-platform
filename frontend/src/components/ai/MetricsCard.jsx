import React from 'react';
import { FiTrendingUp, FiTrendingDown, FiMinus } from 'react-icons/fi';

const variantColors = {
  blue: {
    border: 'border-blue-500/30',
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    colorHex: '#3b82f6',
    bgHex: 'rgba(59, 130, 246, 0.1)'
  },
  green: {
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-400',
    colorHex: '#10b981',
    bgHex: 'rgba(16, 185, 129, 0.1)'
  },
  yellow: {
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    colorHex: '#f59e0b',
    bgHex: 'rgba(245, 158, 11, 0.1)'
  },
  purple: {
    border: 'border-purple-500/30',
    bg: 'bg-purple-500/10',
    text: 'text-purple-400',
    colorHex: '#a855f7',
    bgHex: 'rgba(168, 85, 247, 0.1)'
  },
  red: {
    border: 'border-rose-500/30',
    bg: 'bg-rose-500/10',
    text: 'text-rose-400',
    colorHex: '#f43f5e',
    bgHex: 'rgba(244, 63, 94, 0.1)'
  }
};

export default function MetricsCard({
  title,
  value,
  delta,
  variant = 'blue',
  subtitle,
  icon
}) {
  const theme = variantColors[variant] || variantColors.blue;

  let deltaIcon = <FiMinus size={13} />;
  let deltaColorClass = 'text-gray-400';
  let deltaColorHex = '#94a3b8';

  if (delta != null) {
    const deltaStr = String(delta);
    if (deltaStr.startsWith('+') || Number(delta) > 0) {
      deltaIcon = <FiTrendingUp size={13} />;
      deltaColorClass = 'text-emerald-400';
      deltaColorHex = '#34d399';
    } else if (deltaStr.startsWith('-') || Number(delta) < 0) {
      deltaIcon = <FiTrendingDown size={13} />;
      deltaColorClass = 'text-rose-400';
      deltaColorHex = '#fb7185';
    }
  }

  return (
    <div
      className={`ai-metric-card variant-${variant} relative overflow-hidden rounded-xl border ${theme.border} bg-[#131722] p-5 shadow-sm transition-all hover:border-opacity-60`}
      style={{
        borderRadius: '0.75rem',
        padding: '1.25rem',
        backgroundColor: '#11161d',
        border: `1px solid ${theme.bgHex.replace('0.1', '0.3')}`,
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.4)',
        minWidth: 0
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span
          className="text-xs font-semibold uppercase tracking-wider text-gray-400"
          style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8' }}
        >
          {title}
        </span>
        {icon && (
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ${theme.bg} ${theme.text}`}
            style={{
              display: 'flex',
              height: '2rem',
              width: '2rem',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '0.5rem',
              backgroundColor: theme.bgHex,
              color: theme.colorHex
            }}
          >
            {icon}
          </div>
        )}
      </div>

      <div
        className="mt-3 flex items-baseline gap-2"
        style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.75rem' }}
      >
        <span
          className="text-3xl font-extrabold tracking-tight text-white"
          style={{ fontSize: '1.875rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.025em' }}
        >
          {value}
        </span>
      </div>

      <div
        className="mt-2 flex items-center justify-between text-xs"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.75rem' }}
      >
        {subtitle && (
          <span className="text-gray-400" style={{ color: '#94a3b8' }}>
            {subtitle}
          </span>
        )}
        {delta && (
          <div
            className={`flex items-center gap-1 font-medium ${deltaColorClass}`}
            style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', fontWeight: 500, color: deltaColorHex }}
          >
            {deltaIcon}
            <span>{delta}</span>
          </div>
        )}
      </div>
    </div>
  );
}
