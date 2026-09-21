// src/components/policies/PolicyFormModal.jsx
import React, { useState, useEffect, useMemo } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { listGroups } from '../../api/groups';
import {
  FiShield,
  FiAlertCircle,
  FiSliders,
  FiClock,
  FiUsers,
  FiServer,
  FiLock,
  FiSlash,
  FiLayers,
  FiBell,
  FiCheck,
  FiInfo,
} from 'react-icons/fi';

const ACTION_OPTIONS = [
  { value: 'alert', label: 'Alert Only (Thông báo cảnh báo)', icon: <FiBell /> },
  { value: 'block_ip', label: 'Block IP (Chặn IP nguồn khả nghi)', icon: <FiSlash /> },
  { value: 'isolate', label: 'Network Isolate (Cô lập mạng)', icon: <FiLock /> },
  { value: 'quarantine', label: 'Quarantine (Cách ly file/tiến trình)', icon: <FiLayers /> },
];

export default function PolicyFormModal({
  isOpen,
  onClose,
  onSaved,
  editPolicy = null,
  existingPolicies = [],
}) {
  const [groups, setGroups] = useState([]);
  const [loadingGroups, setLoadingGroups] = useState(false);

  // Form State
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [minScore, setMinScore] = useState(70);
  const [maxScore, setMaxScore] = useState(85);
  const [actionType, setActionType] = useState('isolate');
  const [scope, setScope] = useState('agent');
  const [targetGroupId, setTargetGroupId] = useState('');
  const [autoRollbackSeconds, setAutoRollbackSeconds] = useState(300);
  const [priority, setPriority] = useState(10);
  const [isActive, setIsActive] = useState(true);

  // UI state
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  // Fetch groups for dropdown
  useEffect(() => {
    if (isOpen) {
      setLoadingGroups(true);
      listGroups()
        .then((data) => setGroups(Array.isArray(data) ? data : []))
        .catch((err) => console.error('Failed to load groups for policy form', err))
        .finally(() => setLoadingGroups(false));
    }
  }, [isOpen]);

  // Populate on open / editPolicy change
  useEffect(() => {
    if (!isOpen) return;
    setError('');

    if (editPolicy) {
      setName(editPolicy.name || '');
      setDescription(editPolicy.description || '');
      setMinScore(editPolicy.min_score ?? 70);
      setMaxScore(editPolicy.max_score ?? 85);
      setActionType(editPolicy.action_type || 'isolate');
      setScope(editPolicy.scope || 'agent');
      setTargetGroupId(editPolicy.target_group_id || '');
      setAutoRollbackSeconds(editPolicy.auto_rollback_seconds ?? 300);
      setPriority(editPolicy.priority ?? 10);
      setIsActive(editPolicy.is_active ?? true);
    } else {
      // Default new policy values
      setName('');
      setDescription('');
      setMinScore(70);
      setMaxScore(85);
      setActionType('isolate');
      setScope('agent');
      setTargetGroupId('');
      setAutoRollbackSeconds(300);
      setPriority(10);
      setIsActive(true);
    }
  }, [isOpen, editPolicy]);

  // Validations
  const minVal = Number(minScore);
  const maxVal = Number(maxScore);
  const isScoreValid = minVal >= 0 && maxVal <= 100 && minVal < maxVal;
  const isGroupSelected = scope !== 'group' || !!targetGroupId;
  const isNameFilled = name.trim().length > 0;

  // Check overlap warning
  const overlapWarning = useMemo(() => {
    if (!isScoreValid) return null;
    const others = existingPolicies.filter((p) => !editPolicy || p.id !== editPolicy.id);
    const overlapping = others.filter((p) => {
      // Check same scope and group
      const sameScope = p.scope === scope;
      const sameGroup = scope === 'group' ? p.target_group_id === targetGroupId : true;
      if (!sameScope || !sameGroup) return false;

      // Range overlap: max(minA, minB) <= min(maxA, maxB)
      const overlap = Math.max(minVal, p.min_score) < Math.min(maxVal, p.max_score);
      return overlap;
    });

    if (overlapping.length > 0) {
      return `Dải điểm [${minVal} - ${maxVal}] đang giao thoa với ${overlapping.length} chính sách khác (${overlapping.map((o) => o.name).join(', ')}). Hệ thống sẽ ưu tiên policy có Priority cao hơn.`;
    }
    return null;
  }, [minVal, maxVal, scope, targetGroupId, existingPolicies, editPolicy, isScoreValid]);

  const canSubmit = isNameFilled && isScoreValid && isGroupSelected && !submitting;

  const targetGroupName = useMemo(() => {
    if (!targetGroupId) return 'chưa chọn';
    const found = groups.find((g) => g.id === targetGroupId);
    return found ? found.name : targetGroupId;
  }, [groups, targetGroupId]);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!canSubmit) return;
    setError('');

    if (minVal >= maxVal) {
      setError('Điểm rủi ro tối thiểu (min_score) phải nhỏ hơn điểm tối đa (max_score).');
      return;
    }

    if (scope === 'group' && !targetGroupId) {
      setError('Vui lòng chọn Agent Group áp dụng khi chọn Scope là Group.');
      return;
    }

    const payload = {
      name: name.trim(),
      description: description.trim() || null,
      min_score: minVal,
      max_score: maxVal,
      action_type: actionType,
      scope,
      target_group_id: scope === 'group' ? targetGroupId : null,
      auto_rollback_seconds: actionType === 'alert' ? null : Number(autoRollbackSeconds) || 0,
      priority: Number(priority) || 0,
      is_active: Boolean(isActive),
      action_params: {},
    };

    setSubmitting(true);
    try {
      if (onSaved) {
        await onSaved(payload, editPolicy?.id);
      }
      onClose();
    } catch (err) {
      console.error('Failed to save policy', err);
      setError(err.response?.data?.detail || err.message || 'Không thể lưu chính sách');
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={submitting ? undefined : onClose}
      title={editPolicy ? `Chỉnh sửa Policy: ${editPolicy.name}` : 'Tạo mới Response Policy'}
      maxWidth={680}
    >
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
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

        {/* Real-time Human Readable Preview */}
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: 'var(--radius-sm, 6px)',
            background: 'var(--bg-secondary, #f8fafc)',
            border: '1px solid var(--border)',
            display: 'flex',
            gap: '0.75rem',
            alignItems: 'flex-start',
          }}
        >
          <FiInfo size={18} color="var(--primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ fontSize: '0.825rem', lineHeight: 1.5, color: 'var(--text-secondary)' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.2rem' }}>
              Quy tắc thực thi dự kiến:
            </span>
            Khi risk score từ <strong>{minVal}</strong> đến <strong>{maxVal}</strong>, hệ thống sẽ thực hiện{' '}
            <span
              style={{
                fontWeight: 700,
                color:
                  actionType === 'isolate'
                    ? 'var(--error, #ef4444)'
                    : actionType === 'block_ip'
                    ? 'var(--warning, #f59e0b)'
                    : 'var(--primary, #3b82f6)',
                textTransform: 'uppercase',
              }}
            >
              [{actionType}]
            </span>{' '}
            trên{' '}
            <strong>
              [{scope === 'group' ? `GROUP: ${targetGroupName}` : 'AGENT'}]
            </strong>
            .{actionType !== 'alert' && autoRollbackSeconds > 0 && ` Auto-rollback sau ${autoRollbackSeconds} giây.`}{' '}
            Priority: <strong>{priority}</strong>. Trạng thái:{' '}
            <strong style={{ color: isActive ? 'var(--success, #10b981)' : 'var(--text-tertiary)' }}>
              {isActive ? 'Kích hoạt' : 'Tạm dừng'}
            </strong>.
          </div>
        </div>

        {overlapWarning && (
          <div
            style={{
              padding: '0.65rem 0.85rem',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid var(--warning, #f59e0b)',
              borderRadius: 'var(--radius-sm, 4px)',
              color: 'var(--warning, #f59e0b)',
              fontSize: '0.775rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}
          >
            <FiAlertCircle size={15} style={{ flexShrink: 0 }} />
            <span>{overlapWarning}</span>
          </div>
        )}

        {/* Name & Description */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Tên chính sách <span style={{ color: 'var(--error)' }}>*</span>
            </label>
            <input
              type="text"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Ví dụ: High Risk Host Isolation"
              maxLength={128}
              required
              style={{ width: '100%', fontSize: '0.85rem' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Mô tả chính sách (Tùy chọn)
            </label>
            <textarea
              className="input"
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Mô tả mục đích và bối cảnh kích hoạt của chính sách..."
              maxLength={256}
              style={{ width: '100%', fontSize: '0.85rem', resize: 'vertical' }}
            />
          </div>
        </div>

        {/* Risk Range: Min Score - Max Score */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Min Score (0 - 100) <span style={{ color: 'var(--error)' }}>*</span>
            </label>
            <input
              type="number"
              className="input"
              min="0"
              max="100"
              step="0.1"
              value={minScore}
              onChange={(e) => setMinScore(e.target.value)}
              required
              style={{ width: '100%', fontSize: '0.85rem' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Max Score (0 - 100) <span style={{ color: 'var(--error)' }}>*</span>
            </label>
            <input
              type="number"
              className="input"
              min="0"
              max="100"
              step="0.1"
              value={maxScore}
              onChange={(e) => setMaxScore(e.target.value)}
              required
              style={{ width: '100%', fontSize: '0.85rem' }}
            />
          </div>
        </div>

        {minVal >= maxVal && (
          <span style={{ color: 'var(--error, #ef4444)', fontSize: '0.75rem', marginTop: '-0.75rem' }}>
            Lỗi: Min score ({minVal}) phải nhỏ hơn Max score ({maxVal}).
          </span>
        )}

        {/* Action Type & Scope */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Hành động phản ứng (Action Type)
            </label>
            <select
              className="input"
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
              style={{ width: '100%', fontSize: '0.85rem' }}
            >
              {ACTION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Phạm vi tác động (Scope)
            </label>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="policy_scope"
                  value="agent"
                  checked={scope === 'agent'}
                  onChange={() => setScope('agent')}
                />
                <FiServer size={14} color="var(--primary)" /> Single Agent
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="policy_scope"
                  value="group"
                  checked={scope === 'group'}
                  onChange={() => setScope('group')}
                />
                <FiUsers size={14} color="#a855f7" /> Entire Group
              </label>
            </div>
          </div>
        </div>

        {/* Target Group Dropdown (only if scope === 'group') */}
        {scope === 'group' && (
          <div
            style={{
              padding: '0.85rem',
              borderRadius: 'var(--radius-sm, 6px)',
              background: 'rgba(168, 85, 247, 0.05)',
              border: '1px solid rgba(168, 85, 247, 0.3)',
            }}
          >
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Chọn Agent Group áp dụng <span style={{ color: 'var(--error)' }}>*</span>
            </label>
            <select
              className="input"
              value={targetGroupId}
              onChange={(e) => setTargetGroupId(e.target.value)}
              required={scope === 'group'}
              style={{ width: '100%', fontSize: '0.85rem' }}
            >
              <option value="">-- Chọn một nhóm máy --</option>
              {groups.map((grp) => (
                <option key={grp.id} value={grp.id}>
                  {grp.name} ({grp.id}) — {grp.member_count ?? 0} agents
                </option>
              ))}
            </select>
            {!targetGroupId && (
              <span style={{ color: 'var(--error, #ef4444)', fontSize: '0.725rem', marginTop: '0.25rem', display: 'block' }}>
                Vui lòng chọn nhóm máy cần áp dụng chính sách này.
              </span>
            )}
          </div>
        )}

        {/* Priority, Auto Rollback & Active Toggle */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.85rem', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Độ ưu tiên (Priority)
            </label>
            <input
              type="number"
              className="input"
              min="0"
              max="100"
              value={priority}
              onChange={(e) => setPriority(Math.max(0, parseInt(e.target.value) || 0))}
              style={{ width: '100%', fontSize: '0.85rem' }}
            />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>Số càng cao càng ưu tiên trước</span>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Auto-rollback (giây)
            </label>
            <input
              type="number"
              className="input"
              min="0"
              max="3600"
              step="30"
              value={autoRollbackSeconds}
              disabled={actionType === 'alert'}
              onChange={(e) => setAutoRollbackSeconds(Math.max(0, parseInt(e.target.value) || 0))}
              style={{ width: '100%', fontSize: '0.85rem' }}
            />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>0 để tắt hoàn nguyên</span>
          </div>

          <div style={{ paddingBottom: '0.6rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>
              <input
                type="checkbox"
                checked={isActive}
                onChange={(e) => setIsActive(e.target.checked)}
                style={{ width: '16px', height: '16px' }}
              />
              <span>Kích hoạt (Active)</span>
            </label>
          </div>
        </div>

        {/* Footer Buttons */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.65rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid var(--border)',
          }}
        >
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onClose}
            disabled={submitting}
          >
            Hủy
          </Button>

          <Button
            type="submit"
            variant="primary"
            size="sm"
            disabled={!canSubmit}
            loading={submitting}
            iconLeft={<FiCheck size={14} />}
          >
            {editPolicy ? 'Cập nhật Policy' : 'Lưu Policy'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
