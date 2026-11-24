import React from 'react';
import { useNavigate } from 'react-router-dom';
import { FiGlobe, FiRadio, FiActivity, FiArrowRight, FiLink2, FiTrash2 } from 'react-icons/fi';

function getScore(item) {
  const v = item?.risk_score ?? item?.riskScore ?? item?.score;
  return typeof v === 'number' ? v : 0;
}

function getTimeAgo(timestamp) {
  if (!timestamp) return '';
  const mins = Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000);
  if (mins < 1) return 'vừa xong';
  if (mins < 60) return `${mins}p trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h trước`;
  return `${Math.floor(hours / 24)}d trước`;
}

export default function NetworkFindings({ findings = [], onSelectFinding, onDeleteFinding, onClearAll }) {
  const navigate = useNavigate();
  const rows = findings.slice(0, 5);

  if (rows.length === 0) {
    return (
      <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiGlobe size={16} color="var(--primary)" />
            <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
              Network Findings
            </h3>
          </div>
          <button
            onClick={() => navigate('/incidents?finding=network')}
            style={{ fontSize: '0.75rem', color: 'var(--primary)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            Xem tất cả <FiArrowRight size={12} />
          </button>
        </div>

        <div style={{ textAlign: 'center', padding: '2.5rem 0', color: 'var(--success)' }}>
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🌐</div>
          <div style={{ fontWeight: 600 }}>Không có cảnh báo lưu lượng mạng</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Không phát hiện C2 Beaconing, DNS Tunneling hoặc Port Scan
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiGlobe size={16} color="var(--primary)" />
          <h3 style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)', margin: 0 }}>
            Network Findings
          </h3>
          <span style={{
            fontSize: '0.7rem',
            fontWeight: 600,
            background: 'var(--primary-dim)',
            color: 'var(--primary)',
            padding: '0.1rem 0.45rem',
            borderRadius: '9999px',
          }}>
            {findings.length}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {onClearAll && (
            <button
              onClick={() => onClearAll(rows)}
              title="Xóa danh sách findings này khỏi database"
              style={{
                fontSize: '0.75rem',
                color: 'var(--error, #ef4444)',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.25rem'
              }}>
              <FiTrash2 size={12} /> Xóa lịch sử
            </button>
          )}
          <button
            onClick={() => navigate('/incidents?finding=network')}
            style={{ fontSize: '0.75rem', color: 'var(--primary)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            Xem tất cả <FiArrowRight size={12} />
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
        {rows.map((finding) => {
          const score = getScore(finding);
          const isCritical = score >= 75;
          const isHigh = score >= 50 && score < 75;

          const borderColor = isCritical ? 'var(--error, #ef4444)' : isHigh ? 'var(--warning, #f59e0b)' : 'var(--primary, #38bdf8)';
          const bgColor = isCritical ? 'var(--error-dim, rgba(239, 68, 68, 0.12))' : isHigh ? 'var(--warning-dim, rgba(245, 158, 11, 0.12))' : 'var(--primary-dim, rgba(56, 189, 248, 0.12))';

          const isProcessLinked = Boolean(finding.culprit_process);
          const timeAgo = getTimeAgo(finding.created_at || finding.createdAt || finding.first_seen);

          return (
            <div
              key={finding.id}
              onClick={() => onSelectFinding ? onSelectFinding(finding) : navigate(`/incidents/${finding.id}`)}
              style={{
                padding: '0.75rem 0.875rem',
                background: bgColor,
                borderLeft: `4px solid ${borderColor}`,
                borderRadius: '6px',
                cursor: 'pointer',
                transition: 'transform 0.15s, box-shadow 0.15s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateX(4px)';
                e.currentTarget.style.boxShadow = '0 2px 6px rgba(0,0,0,0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateX(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {finding.title || 'Suspicious Network Flow'}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginTop: '0.25rem', flexWrap: 'wrap', fontSize: '0.72rem' }}>
                    {isProcessLinked ? (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.2rem',
                        background: 'rgba(99, 102, 241, 0.2)',
                        color: '#a5b4fc',
                        padding: '0.1rem 0.35rem',
                        borderRadius: '4px',
                        fontWeight: 600,
                      }}>
                        <FiLink2 size={10} /> Process-linked
                      </span>
                    ) : (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.2rem',
                        background: 'rgba(56, 189, 248, 0.15)',
                        color: 'var(--primary)',
                        padding: '0.1rem 0.35rem',
                        borderRadius: '4px',
                        fontWeight: 600,
                      }}>
                        <FiRadio size={10} /> Network-only
                      </span>
                    )}

                    <span style={{ color: 'var(--text-tertiary)' }}>
                      Host: <span style={{ color: 'var(--text-secondary)' }}>{finding.agent_id || 'Unknown'}</span>
                    </span>

                    {timeAgo && (
                      <span style={{ color: 'var(--text-tertiary)' }}>· {timeAgo}</span>
                    )}
                  </div>
                </div>

                <div style={{ marginLeft: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.45rem',
                    borderRadius: '4px',
                    background: borderColor,
                    color: '#ffffff',
                    minWidth: '24px',
                    textAlign: 'center',
                  }}>
                    {score}
                  </span>
                  {onDeleteFinding && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteFinding(finding, e);
                      }}
                      title="Xóa phát hiện mạng này"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-tertiary)',
                        cursor: 'pointer',
                        padding: '0.2rem',
                        display: 'flex',
                        alignItems: 'center',
                        borderRadius: '4px',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--error, #ef4444)')}
                      onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-tertiary)')}
                    >
                      <FiTrash2 size={13} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

