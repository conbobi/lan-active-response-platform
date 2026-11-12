import React, { useState } from 'react';
import { FiChevronDown, FiChevronRight } from 'react-icons/fi';

export default function CollapsibleSection({
  title,
  desc,
  defaultOpen = false,
  icon: Icon,
  children,
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div
      className="card settings-section"
      style={{
        marginBottom: '1.25rem',
        borderRadius: 'var(--radius-md, 8px)',
        border: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        overflow: 'hidden',
      }}
    >
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '1rem 1.25rem',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          color: 'var(--text-primary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {Icon && <Icon size={18} style={{ color: 'var(--primary)' }} />}
          <div>
            <div style={{ fontSize: '0.95rem', fontWeight: 600 }}>{title}</div>
            {desc && (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                {desc}
              </div>
            )}
          </div>
        </div>
        <div style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center' }}>
          {isOpen ? <FiChevronDown size={18} /> : <FiChevronRight size={18} />}
        </div>
      </button>

      {isOpen && (
        <div
          style={{
            padding: '1rem 1.25rem',
            borderTop: '1px solid var(--border)',
            background: 'var(--bg-primary)',
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

