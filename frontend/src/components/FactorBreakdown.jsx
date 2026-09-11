// src/components/FactorBreakdown.jsx
import React from 'react';
import { parseFactors } from '../types/risk';

export function FactorBreakdown({ factors }) {
  const details = parseFactors(factors);

  if (details.length === 0) {
    return <span style={{ color: '#94a3b8', fontStyle: 'italic' }}>Không có factor nào</span>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
      {details.map((d) => {
        let badgeBg = '#fef3c7';
        let badgeColor = '#92400e';
        if (d.points >= 30) {
          badgeBg = '#fee2e2';
          badgeColor = '#991b1b';
        } else if (d.points >= 15) {
          badgeBg = '#ffedd5';
          badgeColor = '#9a3412';
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
                whiteSpace: 'nowrap'
              }}
            >
              {d.rule_name}: {d.points > 0 ? d.points.toFixed(1) : 'flagged'}
            </span>
            <span
              style={{
                color: '#64748b',
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
