// src/components/FactorBreakdown.jsx
import React from 'react';
import { parseFactors } from '../types/risk';

export function FactorBreakdown({ factors }) {
  const details = parseFactors(factors);

  if (details.length === 0) {
    return <span style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>Không có factor nào</span>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      {details.map((d) => {
        let badgeBg = 'var(--warning-dim)';
        let badgeColor = 'var(--warning)';
        if (d.points >= 30) {
          badgeBg = 'var(--critical-dim)';
          badgeColor = 'var(--critical)';
        } else if (d.points >= 15) {
          badgeBg = 'var(--error-dim)';
          badgeColor = 'var(--error)';
        }

        return (
          <div key={d.rule_name} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
            <span
              style={{
                backgroundColor: badgeBg,
                color: badgeColor,
                padding: '2px 6px',
                borderRadius: '4px',
                fontFamily: 'monospace',
                fontWeight: 600,
                whiteSpace: 'nowrap',
                border: `1px solid ${badgeBg}`
              }}
            >
              {d.rule_name}: {d.points > 0 ? d.points.toFixed(1) : 'flagged'}
            </span>
            <span
              style={{
                color: 'var(--text-secondary)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                maxWidth: '280px'
              }}
              title={d.reason}
            >
              {d.reason}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default FactorBreakdown;
