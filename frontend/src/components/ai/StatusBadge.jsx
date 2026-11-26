import React from 'react';

const statusConfig = {
  pending: {
    label: 'Chờ kiểm định',
    classes: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
    dot: 'bg-gray-400',
    color: '#94a3b8',
    bg: 'rgba(148, 163, 184, 0.12)',
    border: 'rgba(148, 163, 184, 0.25)',
    dotColor: '#94a3b8'
  },
  validating: {
    label: 'Đang kiểm định',
    classes: 'bg-blue-500/10 text-blue-400 border-blue-500/30 animate-pulse',
    dot: 'bg-blue-400',
    color: '#60a5fa',
    bg: 'rgba(96, 165, 250, 0.12)',
    border: 'rgba(96, 165, 250, 0.3)',
    dotColor: '#60a5fa'
  },
  validated: {
    label: 'Đã kiểm định',
    classes: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    dot: 'bg-emerald-400',
    color: '#34d399',
    bg: 'rgba(52, 211, 153, 0.12)',
    border: 'rgba(52, 211, 153, 0.3)',
    dotColor: '#34d399'
  },
  rejected: {
    label: 'Bị từ chối',
    classes: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    dot: 'bg-rose-400',
    color: '#fb7185',
    bg: 'rgba(251, 113, 133, 0.12)',
    border: 'rgba(251, 113, 133, 0.3)',
    dotColor: '#fb7185'
  },
  monitoring: {
    label: 'Đang giám sát',
    classes: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    dot: 'bg-amber-400',
    color: '#fbbf24',
    bg: 'rgba(251, 191, 36, 0.12)',
    border: 'rgba(251, 191, 36, 0.3)',
    dotColor: '#fbbf24'
  },
  active: {
    label: 'Đang chạy',
    classes: 'bg-teal-500/15 text-teal-300 border-teal-500/40 font-semibold',
    dot: 'bg-teal-400',
    color: '#2dd4bf',
    bg: 'rgba(45, 212, 191, 0.15)',
    border: 'rgba(45, 212, 191, 0.4)',
    dotColor: '#2dd4bf'
  },
  disabled: {
    label: 'Đã tắt',
    classes: 'bg-zinc-800/40 text-zinc-500 border-zinc-700/30',
    dot: 'bg-zinc-500',
    color: '#71717a',
    bg: 'rgba(39, 39, 42, 0.4)',
    border: 'rgba(63, 63, 70, 0.3)',
    dotColor: '#71717a'
  }
};

export default function StatusBadge({ status }) {
  const key = (status || 'pending').toLowerCase();
  const cfg = statusConfig[key] || statusConfig.pending;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.classes}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.375rem',
        padding: '0.2rem 0.625rem',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 500,
        color: cfg.color,
        backgroundColor: cfg.bg,
        border: `1px solid ${cfg.border}`,
        whiteSpace: 'nowrap'
      }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`}
        style={{
          width: '0.375rem',
          height: '0.375rem',
          borderRadius: '9999px',
          backgroundColor: cfg.dotColor
        }}
      />
      {cfg.label}
    </span>
  );
}
