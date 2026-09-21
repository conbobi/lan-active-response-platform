// src/components/groups/GroupCard.jsx
import React, { useState, useRef, useEffect } from 'react';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import {
  FiUsers,
  FiMoreVertical,
  FiEdit2,
  FiTrash2,
  FiArrowRight,
  FiShield,
} from 'react-icons/fi';

const getGroupEmoji = (name = '') => {
  const lower = name.toLowerCase();
  if (lower.includes('hr') || lower.includes('human')) return '🏢';
  if (lower.includes('it') || lower.includes('tech')) return '💻';
  if (lower.includes('finance') || lower.includes('account')) return '💰';
  if (lower.includes('server') || lower.includes('infra')) return '🖥️';
  return '👥';
};

export default function GroupCard({
  group,
  onClick,
  onManageMembers,
  onEdit,
  onDelete,
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef();

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const emoji = getGroupEmoji(group.name);
  const memberCount = group.member_count ?? 0;

  return (
    <div
      className="card group-card"
      style={{
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '1.25rem',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border)',
        background: 'var(--bg-card)',
        transition: 'all 0.2s ease',
        cursor: 'pointer',
        position: 'relative',
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-2px)';
        e.currentTarget.style.boxShadow = 'var(--shadow-md)';
        e.currentTarget.style.borderColor = 'var(--primary)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'none';
        e.currentTarget.style.boxShadow = 'none';
        e.currentTarget.style.borderColor = 'var(--border)';
      }}
    >
      {/* Top Header */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span style={{ fontSize: '1.75rem', lineHeight: 1 }}>{emoji}</span>
            <div>
              <h3
                style={{
                  fontSize: '1rem',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  margin: 0,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                {group.name}
              </h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                {group.id}
              </span>
            </div>
          </div>

          {/* 3 dots menu */}
          <div
            ref={menuRef}
            style={{ position: 'relative' }}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              style={{ padding: '0.25rem 0.4rem', color: 'var(--text-secondary)' }}
              onClick={() => setMenuOpen((prev) => !prev)}
              title="Group options"
            >
              <FiMoreVertical size={16} />
            </button>

            {menuOpen && (
              <div
                style={{
                  position: 'absolute',
                  right: 0,
                  top: '100%',
                  marginTop: '0.25rem',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  boxShadow: 'var(--shadow-lg)',
                  zIndex: 100,
                  minWidth: '130px',
                  display: 'flex',
                  flexDirection: 'column',
                  padding: '0.25rem',
                }}
              >
                {onEdit && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{
                      justifyContent: 'flex-start',
                      width: '100%',
                      padding: '0.4rem 0.6rem',
                      fontSize: '0.8rem',
                      gap: '0.5rem',
                    }}
                    onClick={() => {
                      setMenuOpen(false);
                      onEdit(group);
                    }}
                  >
                    <FiEdit2 size={13} /> Edit
                  </button>
                )}
                {onDelete && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{
                      justifyContent: 'flex-start',
                      width: '100%',
                      padding: '0.4rem 0.6rem',
                      fontSize: '0.8rem',
                      gap: '0.5rem',
                      color: 'var(--error)',
                    }}
                    onClick={() => {
                      setMenuOpen(false);
                      onDelete(group);
                    }}
                  >
                    <FiTrash2 size={13} /> Delete
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Description */}
        <p
          style={{
            fontSize: '0.825rem',
            color: 'var(--text-secondary)',
            margin: '0 0 1rem 0',
            lineHeight: 1.4,
            minHeight: '2.4em',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden',
          }}
        >
          {group.description || 'No description provided.'}
        </p>

        {/* Status badges & metrics */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.775rem',
              fontWeight: 600,
              padding: '0.2rem 0.6rem',
              borderRadius: 'var(--radius-full)',
              background: 'var(--primary-light)',
              color: 'var(--primary)',
            }}
          >
            <FiUsers size={12} />
            {memberCount} {memberCount === 1 ? 'agent' : 'agents'}
          </span>

          {group.has_isolated_agents ? (
            <Badge status="danger" label="Has Isolated Agents" showDot={true} />
          ) : (
            <Badge status="active" label="Normal" showDot={true} />
          )}
        </div>
      </div>

      {/* Footer Buttons */}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          borderTop: '1px solid var(--border)',
          paddingTop: '0.75rem',
          marginTop: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <Button
          variant="outline"
          size="sm"
          style={{ flex: 1, fontSize: '0.775rem' }}
          onClick={() => {
            if (onManageMembers) onManageMembers(group);
            else if (onClick) onClick(group);
          }}
        >
          <FiUsers size={12} style={{ marginRight: '0.3rem' }} /> Members
        </Button>
        <Button
          variant="secondary"
          size="sm"
          style={{ flex: 1, fontSize: '0.775rem' }}
          onClick={() => onClick && onClick(group)}
        >
          Details <FiArrowRight size={12} style={{ marginLeft: '0.3rem' }} />
        </Button>
      </div>
    </div>
  );
}
