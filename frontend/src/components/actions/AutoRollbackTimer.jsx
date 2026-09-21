// src/components/actions/AutoRollbackTimer.jsx
import React, { useState, useEffect } from 'react';
import { FiClock } from 'react-icons/fi';

export default function AutoRollbackTimer({ autoRollbackAt, status }) {
  const [timeLeft, setTimeLeft] = useState(null);

  useEffect(() => {
    if (!autoRollbackAt || status !== 'applied') {
      setTimeLeft(null);
      return;
    }

    const updateTimer = () => {
      const now = Date.now();
      const target = new Date(autoRollbackAt).getTime();
      const diff = target - now;

      if (diff <= 0) {
        setTimeLeft(0);
      } else {
        setTimeLeft(Math.floor(diff / 1000));
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [autoRollbackAt, status]);

  if (status === 'reverted') {
    return (
      <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
        ✓ Rolled back
      </span>
    );
  }

  if (status !== 'applied' || timeLeft === null) {
    return null;
  }

  if (timeLeft <= 0) {
    return (
      <span style={{ fontSize: '0.75rem', color: 'var(--warning)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontWeight: 600 }}>
        <FiClock className="animate-spin" size={12} /> Auto-rolling back...
      </span>
    );
  }

  const minutes = Math.floor(timeLeft / 60);
  const seconds = timeLeft % 60;
  const formatted = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.2rem 0.5rem',
        background: 'rgba(234, 179, 8, 0.12)',
        border: '1px solid rgba(234, 179, 8, 0.3)',
        borderRadius: '9999px',
        color: '#eab308',
        fontSize: '0.75rem',
        fontWeight: 600,
        fontVariantNumeric: 'tabular-nums',
      }}
      title={`Auto rollback scheduled at ${new Date(autoRollbackAt).toLocaleTimeString()}`}
    >
      <FiClock size={12} /> Auto rollback in {formatted}
    </span>
  );
}
