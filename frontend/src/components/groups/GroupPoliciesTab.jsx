// src/components/groups/GroupPoliciesTab.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { listPolicies } from '../../api/policies';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import {
  FiShield,
  FiArrowRight,
  FiCheckCircle,
  FiLock,
  FiSlash,
  FiLayers,
  FiBell,
  FiAlertCircle,
  FiLoader,
} from 'react-icons/fi';

export default function GroupPoliciesTab({ groupId }) {
  const navigate = useNavigate();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchPolicies = async () => {
      if (!groupId) return;
      setLoading(true);
      try {
        const data = await listPolicies({ group_id: groupId });
        const list = Array.isArray(data) ? data : [];
        // Lọc policies áp dụng cho nhóm: target_group_id trùng với groupId, hoặc policy áp dụng toàn hệ thống (target_group_id === null)
        const matching = list.filter((p) => {
          if (p.target_group_id === groupId) return true;
          if (p.target_group_id === null || p.target_group_id === undefined) return true;
          return false;
        });
        // Sắp xếp theo priority giảm dần (độ ưu tiên cao nhất đứng trước)
        matching.sort((a, b) => (b.priority || 0) - (a.priority || 0));
        setPolicies(matching);
        setError(null);
      } catch (err) {
        console.error(`Failed to fetch policies for group ${groupId}`, err);
        setError(err.message || 'Không thể tải danh sách chính sách');
      } finally {
        setLoading(false);
      }
    };

    fetchPolicies();
  }, [groupId]);

  const getActionBadge = (actionType) => {
    switch (actionType) {
      case 'isolate':
        return <Badge status="danger" label="Isolate" showDot={true} />;
      case 'block_ip':
        return <Badge status="warning" label="Block IP" showDot={true} />;
      case 'quarantine':
        return <Badge status="info" label="Quarantine" showDot={true} />;
      case 'alert':
        return <Badge status="neutral" label="Alert Only" showDot={false} />;
      default:
        return <Badge status="neutral" label={actionType} showDot={false} />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Chính sách phản ứng áp dụng ({policies.length} policies)
          </span>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', margin: '0.15rem 0 0 0' }}>
            Các Response Policies tự động kích hoạt mitigation khi Risk Score của agent hoặc nhóm đạt ngưỡng.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate('/policies')}
          iconRight={<FiArrowRight size={13} />}
        >
          Quản lý Policies
        </Button>
      </div>

      {error && (
        <div
          style={{
            padding: '0.65rem 0.85rem',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid var(--error, #ef4444)',
            borderRadius: 'var(--radius-sm, 4px)',
            color: 'var(--error, #ef4444)',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <FiAlertCircle size={15} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
          <FiLoader size={20} className="animate-spin" style={{ display: 'inline-block', marginBottom: '0.4rem' }} />
          <div>Đang tải chính sách áp dụng cho nhóm...</div>
        </div>
      ) : policies.length === 0 ? (
        <div
          style={{
            padding: '3rem 1.5rem',
            textAlign: 'center',
            background: 'var(--bg-secondary, #f8fafc)',
            borderRadius: 'var(--radius-sm, 6px)',
            border: '1px dashed var(--border)',
          }}
        >
          <FiShield size={36} style={{ color: 'var(--text-tertiary)', opacity: 0.5, marginBottom: '0.5rem' }} />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 0.25rem 0' }}>
            Chưa có policy nào áp dụng cho nhóm này
          </h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: '0 0 1rem 0' }}>
            Tạo policy mới để tự động hóa cách ly hoặc phản ứng khi rủi ro tăng cao.
          </p>
          <Button variant="primary" size="sm" onClick={() => navigate('/policies')}>
            Tạo Policy tại Response Policies
          </Button>
        </div>
      ) : (
        <div
          style={{
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm, 6px)',
            overflow: 'hidden',
          }}
        >
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
            <thead>
              <tr
                style={{
                  background: 'var(--bg-secondary, #f8fafc)',
                  borderBottom: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                  fontWeight: 600,
                  fontSize: '0.75rem',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}
              >
                <th style={{ padding: '0.65rem 0.85rem', width: '70px' }}>Priority</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Policy Name</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Risk Range</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Action</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Scope</th>
                <th style={{ padding: '0.65rem 0.85rem' }}>Status</th>
                <th style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>Chi tiết</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p, idx) => {
                const isGroupScope = p.scope === 'group';
                const isTargetGroup = p.target_group_id === groupId;

                return (
                  <tr
                    key={p.id}
                    style={{
                      borderBottom: idx < policies.length - 1 ? '1px solid var(--border)' : 'none',
                      transition: 'background 0.15s',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'var(--bg-secondary, #f8fafc)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'transparent';
                    }}
                  >
                    <td style={{ padding: '0.65rem 0.85rem', fontWeight: 700, color: 'var(--primary)' }}>
                      #{p.priority}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{p.name}</div>
                      {p.description && (
                        <div style={{ fontSize: '0.725rem', color: 'var(--text-tertiary)', marginTop: '0.1rem' }}>
                          {p.description}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'monospace', fontWeight: 600 }}>
                      <span style={{ color: p.min_score >= 80 ? 'var(--error, #ef4444)' : p.min_score >= 50 ? 'var(--warning, #f59e0b)' : 'var(--primary)' }}>
                        {p.min_score} - {p.max_score}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      {getActionBadge(p.action_type)}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          background: isGroupScope ? 'rgba(168, 85, 247, 0.1)' : 'rgba(59, 130, 246, 0.1)',
                          color: isGroupScope ? '#a855f7' : 'var(--primary)',
                        }}
                      >
                        {p.scope ? p.scope.toUpperCase() : 'ALL'}
                        {isTargetGroup && ' (This Group)'}
                      </span>
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem' }}>
                      <Badge
                        status={p.is_active ? 'active' : 'inactive'}
                        label={p.is_active ? 'Active' : 'Disabled'}
                        showDot={true}
                      />
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/policies?id=${p.id}`)}
                        style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                      >
                        Xem chi tiết
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
