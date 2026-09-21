// src/components/policies/PolicyDryRunModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { useAgents } from '../../hooks/useAgents';
import { evaluatePolicy } from '../../api/policies';
import {
  FiPlay,
  FiServer,
  FiSliders,
  FiCheckCircle,
  FiAlertCircle,
  FiLayers,
  FiLock,
  FiSlash,
  FiUsers,
  FiLoader,
} from 'react-icons/fi';

export default function PolicyDryRunModal({
  isOpen,
  policy,
  onClose,
}) {
  const { agents } = useAgents();
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [testScore, setTestScore] = useState(75);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen) {
      setError('');
      setResult(null);
      if (policy) {
        // Set initial score around middle of policy range
        const mid = ((policy.min_score || 0) + (policy.max_score || 100)) / 2;
        setTestScore(Math.round(mid));
      }
      if (agents.length > 0 && !selectedAgentId) {
        setSelectedAgentId(agents[0].id);
      }
    }
  }, [isOpen, policy, agents]);

  const handleRunEvaluation = async () => {
    if (!selectedAgentId) {
      setError('Vui lòng chọn một agent để kiểm thử.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const res = await evaluatePolicy({
        agent_id: selectedAgentId,
        risk_score: Number(testScore),
        dry_run: true,
      });
      setResult(res);
    } catch (err) {
      console.error('Dry-run evaluation failed', err);
      setError(err.response?.data?.detail || err.message || 'Kiểm thử đánh giá thất bại');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={loading ? undefined : onClose}
      title={`🧪 Kiểm thử chính sách: ${policy?.name || 'Dry-Run Simulation'}`}
      maxWidth={620}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', margin: 0 }}>
          Mô phỏng phản ứng an ninh với điểm rủi ro giả lập (Chế độ <strong>Dry-Run</strong>, không áp dụng thay đổi thật lên máy trạm).
        </p>

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

        {/* Inputs */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.35rem' }}>
              Chọn máy mục tiêu (Target Agent)
            </label>
            <select
              className="input"
              value={selectedAgentId}
              onChange={(e) => setSelectedAgentId(e.target.value)}
              style={{ width: '100%', fontSize: '0.85rem' }}
            >
              {agents.map((ag) => (
                <option key={ag.id} value={ag.id}>
                  {ag.hostname || ag.id} ({ag.id})
                </option>
              ))}
            </select>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                Điểm rủi ro giả định (Score)
              </label>
              <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.85rem', color: 'var(--primary)' }}>
                {testScore}
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              step="1"
              value={testScore}
              onChange={(e) => setTestScore(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>
        </div>

        {/* Run Test Button */}
        <div>
          <Button
            variant="primary"
            size="sm"
            onClick={handleRunEvaluation}
            disabled={loading || !selectedAgentId}
            loading={loading}
            iconLeft={<FiPlay size={13} />}
          >
            Chạy đánh giá Dry-Run
          </Button>
        </div>

        {/* Results Box */}
        {result && (
          <div
            style={{
              padding: '1rem',
              borderRadius: 'var(--radius-sm, 6px)',
              background: 'var(--bg-secondary, #f8fafc)',
              border: '1px solid var(--border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.75rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                Kết quả mô phỏng đánh giá
              </span>
              <Badge
                status={result.matched_policy ? 'active' : 'neutral'}
                label={result.matched_policy ? 'Matched Policy' : 'No Policy Matched'}
                showDot={true}
              />
            </div>

            {result.matched_policy ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
                <div>
                  Chính sách khớp:{' '}
                  <strong style={{ color: 'var(--primary)' }}>{result.matched_policy.name}</strong>{' '}
                  (Priority: #{result.matched_policy.priority})
                </div>
                <div>
                  Hành động sẽ thực thi:{' '}
                  <strong style={{ textTransform: 'uppercase', color: 'var(--error, #ef4444)' }}>
                    [{result.action_type || result.matched_policy.action_type}]
                  </strong>
                </div>
                <div>
                  Phạm vi áp dụng:{' '}
                  <strong>{result.scope ? result.scope.toUpperCase() : 'AGENT'}</strong>
                  {result.affected_groups?.length > 0 && ` (${result.affected_groups.map((g) => g.name).join(', ')})`}
                </div>
                <div>
                  Số lượng máy trạm bị ảnh hưởng: <strong>{result.simulated_actions?.length || 1} máy</strong>
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
                Không có chính sách nào thỏa mãn ngưỡng điểm rủi ro {testScore}. Hệ thống sẽ không kích hoạt phản ứng tự động.
              </div>
            )}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button variant="outline" size="sm" onClick={onClose}>
            Đóng
          </Button>
        </div>
      </div>
    </Modal>
  );
}
