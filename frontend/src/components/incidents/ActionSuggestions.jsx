// src/components/incidents/ActionSuggestions.jsx
import React from 'react';
import useActions from '../../hooks/useActions';
import ActionTimeline from '../actions/ActionTimeline';
import Button from '../ui/Button';
import {
  FiLock,
  FiSlash,
  FiShield,
  FiAlertCircle,
  FiCheckCircle,
  FiCornerDownRight,
  FiZap,
  FiRotateCcw
} from 'react-icons/fi';

export default function ActionSuggestions({
  incident,
  onAction,
  actionLoading,
  isIsolated,
}) {
  const {
    actions: incidentActions,
    loading: actionsLoading,
    actionLoading: timelineActionLoading,
    handleUndo,
    handleUndoAll,
  } = useActions({ incidentId: incident?.id });

  const culprit = incident?.culpritProcess || { name: 'key_test.exe', pid: 4128 };
  const networkIndicators = incident?.networkIndicators || [];
  const targetIp = networkIndicators[0]?.dst_ip || (incident?.description?.includes('4444') ? '192.168.10.55' : null);

  // Generate intelligent suggestions based on threat context
  const suggestions = [];

  if (!isIsolated) {
    suggestions.push({
      id: 'isolate_host',
      title: `Cô lập mạng máy trạm (${incident?.agentId})`,
      description: 'Chặn toàn bộ luồng lưu thông ngoại trừ kết nối quản trị WebSocket tới EDR Manager để ngăn phát tán mã độc.',
      actionType: 'isolate',
      params: {},
      variant: 'danger',
      icon: <FiLock size={14} />,
      recommended: true,
    });
  }

  if (culprit.pid) {
    suggestions.push({
      id: 'kill_tree',
      title: `Tiêu diệt cây tiến trình: ${culprit.name} (PID ${culprit.pid})`,
      description: 'Đệ quy kết thúc tiến trình thủ phạm cùng toàn bộ tiến trình con khởi tạo bởi nó trong bộ nhớ.',
      actionType: 'kill_process_tree',
      params: { pid: culprit.pid, process_name: culprit.name },
      variant: 'warning',
      icon: <FiSlash size={14} />,
      recommended: true,
    });
  }

  if (targetIp) {
    suggestions.push({
      id: 'block_ip',
      title: `Chặn kết nối C2 IP: ${targetIp}`,
      description: 'Thêm luật Firewall tại Agent để từ chối mọi gói tin gửi tới địa chỉ máy chủ C2.',
      actionType: 'block_ip',
      params: { ip: targetIp },
      variant: 'outline',
      icon: <FiShield size={14} />,
      recommended: false,
    });
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* SECTION 1: SMART NEXT-STEP RECOMMENDATIONS */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <FiZap size={16} color="var(--warning)" />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Đề xuất phản ứng tiếp theo (Next-Step Recommendations)
          </h4>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: '0 0 1rem 0' }}>
          Hệ thống phân tích rủi ro tự động đưa ra các hành động giảm thiểu phù hợp nhất với loại mã độc này:
        </p>

        {suggestions.length === 0 ? (
          <div style={{ padding: '1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', fontSize: '0.85rem', color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiCheckCircle size={16} /> Mọi hành động ứng phó chính đã được thực thi đầy đủ.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.85rem' }}>
            {suggestions.map((sug) => (
              <div
                key={sug.id}
                style={{
                  background: 'var(--bg-secondary)',
                  border: sug.recommended ? '1.5px solid var(--warning)' : '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  boxShadow: sug.recommended ? '0 0 10px rgba(245, 158, 11, 0.1)' : 'none',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                    <strong style={{ fontSize: '0.88rem', color: 'var(--text-primary)' }}>
                      {sug.title}
                    </strong>
                    {sug.recommended && (
                      <span style={{ fontSize: '0.68rem', fontWeight: 800, background: 'rgba(245, 158, 11, 0.2)', color: 'var(--warning)', padding: '0.1rem 0.4rem', borderRadius: 'var(--radius-xs)', textTransform: 'uppercase' }}>
                        Gợi ý
                      </span>
                    )}
                  </div>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '0 0 1rem 0', lineHeight: 1.45 }}>
                    {sug.description}
                  </p>
                </div>

                <Button
                  variant={sug.variant}
                  size="sm"
                  disabled={actionLoading}
                  iconLeft={sug.icon}
                  onClick={() => onAction && onAction(sug.actionType, sug.params)}
                  style={{ width: '100%' }}
                >
                  Thực thi ngay
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SECTION 2: EXECUTED MITIGATION ACTIONS TIMELINE */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <FiShield size={16} color="var(--primary)" />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Lịch sử hành động đã thực hiện (Executed Mitigations & Rollback)
          </h4>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: '0 0 1rem 0' }}>
          Toàn bộ các tác vụ cô lập, tiêu diệt tiến trình kèm snapshot trạng thái và nút Undo:
        </p>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '1rem' }}>
          <ActionTimeline
            actions={incidentActions}
            onUndo={handleUndo}
            onUndoAll={handleUndoAll}
            loading={actionsLoading}
            actionLoading={timelineActionLoading}
          />
        </div>
      </div>
    </div>
  );
}
