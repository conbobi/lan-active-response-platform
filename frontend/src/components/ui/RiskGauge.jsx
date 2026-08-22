import React, { useEffect, useState } from 'react';

function getColor(v) {
  if (v < 40) return 'var(--success)';
  if (v < 70) return 'var(--warning)';
  return 'var(--error)';
}

function getRiskLabel(v) {
  if (v < 40) return 'Low Risk';
  if (v < 70) return 'Medium Risk';
  return 'High Risk';
}

export default function RiskGauge({ value }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(value), 100);
    return () => clearTimeout(t);
  }, [value]);

  const R = 72, sw = 14;
  const norm = Math.min(Math.max(animated, 0), 100) / 100;
  const circ = Math.PI * R;
  const offset = circ * (1 - norm);
  const color = getColor(animated);

  return (
    <div className="gauge-wrap">
      <svg width={R * 2 + sw} height={R + sw / 2 + 10} style={{ overflow: 'visible' }}>
        <path
          d={`M ${sw / 2} ${R + sw / 2} A ${R} ${R} 0 0 1 ${R * 2 + sw / 2} ${R + sw / 2}`}
          fill="none" stroke="var(--border)" strokeWidth={sw} strokeLinecap="round"
        />
        <path
          d={`M ${sw / 2} ${R + sw / 2} A ${R} ${R} 0 0 1 ${R * 2 + sw / 2} ${R + sw / 2}`}
          fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.5s ease' }}
        />
        <text x={R + sw / 2} y={R - 4} textAnchor="middle" fill={color} fontSize="22" fontWeight="700" fontFamily="Inter,sans-serif">
          {animated}
        </text>
        <text x={R + sw / 2} y={R + 16} textAnchor="middle" fill="var(--text-tertiary)" fontSize="11" fontFamily="Inter,sans-serif">
          / 100
        </text>
      </svg>
      <div className="gauge-label" style={{ color }}>{getRiskLabel(animated)}</div>
    </div>
  );
}
