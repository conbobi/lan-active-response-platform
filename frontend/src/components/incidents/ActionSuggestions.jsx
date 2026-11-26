// src/components/incidents/ActionSuggestions.jsx
import React from 'react';
import useActions from '../../hooks/useActions';
import ActionTimeline from '../actions/ActionTimeline';
import AISuggestionPanel from './AISuggestionPanel';
import Button from '../ui/Button';
import { isKernelOrSystem } from '../../constants/processExclusions';
import {
  FiLock,
  FiSlash,
  FiShield,
  FiAlertCircle,
  FiZap,
} from 'react-icons/fi';

export default function ActionSuggestions({
  incident,
  httpIncident = false,
  onOpenAssist,
  onRefresh,
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

  const culprit = incident?.culpritProcess || incident?.culprit_process || null;

  // Generate intelligent suggestions based on threat context
  const suggestions = [];

  // Host isolation needs verified host evidence; an HTTP observation alone is answered in Response Assist.
  if (!isIsolated && !httpIncident) {
    suggestions.push({
      id: 'isolate_host',
      title: `Cô lập mạng máy trạm (${incident?.agentId || incident?.agent_id || 'Agent'})`,
      description: 'Chặn toàn bộ luồng lưu thông ngoại trừ kết nối quản trị WebSocket tới EDR Manager để ngăn phát tán mã độc.',
      actionType: 'isolate',
      params: {},
      variant: 'danger',
      icon: <FiLock size={14} />,
      recommended: true,
    });
  }

  if (incident?.detection_evidence?.process && incident.process_activity === 'running' && culprit?.pid && !isKernelOrSystem(culprit)) {
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* SECTION 0: AI RESPONSE SUGGESTION PANEL */}
      {httpIncident ? (
        <div style={{ padding: '1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Sự cố HTTP được xử lý bằng đề xuất theo bằng chứng trong <strong>AI Response Assist</strong>
            (thu thập bằng chứng, giám sát, rate limit/chặn tạm thời khi điểm thực thi được xác minh).
          </span>
          <Button size="sm" variant="primary" onClick={() => onOpenAssist && onOpenAssist()}>
            Mở AI Response Assist
          </Button>
        </div>
      ) : (
        <AISuggestionPanel
          incidentId={incident?.id}
          onRefresh={() => onRefresh && onRefresh()}
        />
      )}

      {/* SECTION 1: SMART NEXT-STEP RECOMMENDATIONS */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
          <FiZap size={16} color="var(--warning)" />
          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Đề xuất phản ứng tiếp theo
          </h4>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', margin: '0 0 1rem 0' }}>
          Hệ thống đánh giá bối cảnh sự cố và gợi ý các hành động kiểm soát phù hợp nhất:
        </p>

        {suggestions.length === 0 ? (
          <div style={{ padding: '1rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', fontSize: '0.85rem', color: httpIncident ? '#93c5fd' : 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiAlertCircle size={16} />
            {httpIncident
              ? 'Không có hành động cô lập/diệt tiến trình trực tiếp cho sự cố lớp HTTP này. Vui lòng sử dụng mục Trợ lý ứng phó AI (Response Assist) để thu thập bằng chứng, giám sát hoặc thực thi chặn/rate-limit HTTP tại điểm thực thi.'
              : 'Chưa có thêm đề xuất kiểm soát máy trạm tức thì (máy đã được cô lập hoặc tiến trình mục tiêu đã kết thúc).'}
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
            Lịch sử hành động kiểm soát & Hoàn tác
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
