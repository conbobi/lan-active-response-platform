import React, { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import Modal from '../ui/Modal';
import FilterTabs from '../ui/FilterTabs';
import Button from '../ui/Button';
import HeroBanner from './HeroBanner';
import StoryTimeline from './StoryTimeline';
import ProcessAncestry from './ProcessAncestry';
import NetworkCorrelation from './NetworkCorrelation';
import ActionSuggestions from './ActionSuggestions';
import IncidentNotes from './IncidentNotes';
import { executeIncidentAction, updateIncidentStatus, getIncident, closeIncident } from '../../api/incidents';
import { useAgents } from '../../hooks/useAgents';

import AIAnalysisTab from './AIAnalysisTab';

const STORYBOARD_TABS = [
  { value: 'story', label: '📖 Story' },
  { value: 'process', label: '🌳 Process' },
  { value: 'network', label: '🌐 Network' },
  { value: 'actions', label: '⚡ Actions' },
  { value: 'notes', label: '📝 Notes' },
  { value: 'ai', label: '🤖 AI Analysis' },
];

const LABEL_OPTIONS = [
  { value: 'true_positive', label: 'True Positive (tấn công thật)', color: 'var(--error)', desc: 'Sự cố an ninh xác thực cần xử lý' },
  { value: 'false_positive', label: 'False Positive (báo động giả)', color: 'var(--text-tertiary)', desc: 'Báo động sai do rule quá nhạy hoặc hành vi thông thường' },
  { value: 'benign', label: 'Benign (không phải tấn công)', color: 'var(--success)', desc: 'Hành vi bình thường được phê duyệt của người dùng/hệ thống' },
  { value: 'inconclusive', label: 'Inconclusive', color: 'var(--warning)', desc: 'Không đủ telemetry hoặc bằng chứng để kết luận' },
];

const LABEL_BADGE_CONFIG = {
  true_positive: { label: 'True Positive', bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', color: '#ef4444' },
  false_positive: { label: 'False Positive', bg: 'rgba(156, 163, 175, 0.15)', border: 'rgba(156, 163, 175, 0.4)', color: '#9ca3af' },
  benign: { label: 'Benign', bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', color: '#10b981' },
  inconclusive: { label: 'Inconclusive', bg: 'rgba(245, 158, 11, 0.15)', border: 'rgba(245, 158, 11, 0.4)', color: '#f59e0b' },
};

export default function IncidentDetailModal({
  incident,
  isOpen = true,
  onClose,
  onRefresh,
}) {
  const [tab, setTab] = useState('story');
  const [detailedIncident, setDetailedIncident] = useState(incident);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionToast, setActionToast] = useState(null);

  // Close with AI Label modal states
  const [isCloseModalOpen, setIsCloseModalOpen] = useState(false);
  const [closeLabel, setCloseLabel] = useState('');
  const [closeReason, setCloseReason] = useState('');
  const [isSubmittingClose, setIsSubmittingClose] = useState(false);

  const { agents, refreshAgents } = useAgents();

  // Find agent to check isolation state
  const targetAgent = agents.find((a) => a.id === detailedIncident?.agentId);
  const isIsolated = targetAgent ? (targetAgent.is_isolated || targetAgent.status === 'ISOLATED' || targetAgent.status === 'isolated') : (detailedIncident?.status === 'contained');

  // Fetch full enriched incident details when modal opens
  useEffect(() => {
    if (incident?.id) {
      getIncident(incident.id)
        .then((data) => setDetailedIncident(data))
        .catch(() => setDetailedIncident(incident));
    }
  }, [incident?.id]);

  const showToast = (message, type = 'success') => {
    setActionToast({ message, type });
    setTimeout(() => setActionToast(null), 5000);
  };

  const handleAction = async (actionType, params = {}) => {
    if (!detailedIncident?.id || actionLoading) return;
    setActionLoading(true);
    try {
      const res = await executeIncidentAction(detailedIncident.id, actionType, params);
      const msg = res.message || `Thực thi thành công: ${actionType}`;
      toast.success(msg);
      showToast(msg);

      // Refresh incident & agents
      if (refreshAgents) refreshAgents();
      if (onRefresh) onRefresh();

      // Refresh local incident details
      const updated = await getIncident(detailedIncident.id);
      setDetailedIncident(updated);
    } catch (err) {
      console.error(`Action error ${actionType}:`, err);
      const errMsg = err.message || `Lỗi khi thực hiện ${actionType}`;
      toast.error(errMsg);
      showToast(errMsg, 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!detailedIncident?.id || actionLoading) return;
    setActionLoading(true);
    try {
      await updateIncidentStatus(detailedIncident.id, newStatus);
      const msg = `Đã chuyển trạng thái sự cố sang: ${newStatus.toUpperCase()}`;
      toast.success(msg);
      showToast(msg);
      if (onRefresh) onRefresh();
      const updated = await getIncident(detailedIncident.id);
      setDetailedIncident(updated);
    } catch (err) {
      const errMsg = `Không thể cập nhật trạng thái: ${err.message}`;
      toast.error(errMsg);
      showToast(errMsg, 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleOpenCloseModal = () => {
    setCloseLabel(detailedIncident?.label || '');
    setCloseReason(detailedIncident?.labelReason || detailedIncident?.label_reason || '');
    setIsCloseModalOpen(true);
  };

  const isCloseValid = Boolean(closeLabel && closeReason.trim().length >= 10);

  const handleConfirmClose = async () => {
    if (!isCloseValid || isSubmittingClose) return;
    setIsSubmittingClose(true);
    try {
      await closeIncident(detailedIncident.id, {
        label: closeLabel,
        label_reason: closeReason.trim(),
        labeled_by: 'current_user',
      });
      toast.success('Incident closed. Label saved for AI feedback.');
      showToast('Incident closed. Label saved for AI feedback.');
      setIsCloseModalOpen(false);
      if (onRefresh) onRefresh();
      const updated = await getIncident(detailedIncident.id);
      setDetailedIncident(updated);
    } catch (err) {
      const errMsg = `Lỗi khi đóng incident: ${err.message}`;
      toast.error(errMsg);
      showToast(errMsg, 'error');
    } finally {
      setIsSubmittingClose(false);
    }
  };

  if (!isOpen || !detailedIncident) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Security Investigation Storyboard — ${detailedIncident.id}`}
      maxWidth="1000px"
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', minHeight: '620px' }}>
        {/* Toast Notification */}
        {actionToast && (
          <div
            style={{
              padding: '0.65rem 1rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.85rem',
              background: actionToast.type === 'error' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
              border: `1px solid ${actionToast.type === 'error' ? 'var(--error)' : 'var(--success)'}`,
              color: actionToast.type === 'error' ? 'var(--error)' : 'var(--success)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>{actionToast.message}</span>
            <button
              onClick={() => setActionToast(null)}
              style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '1rem' }}
            >
              ×
            </button>
          </div>
        )}

        {/* 1. HERO NARRATIVE BANNER */}
        <HeroBanner
          incident={detailedIncident}
          onAction={handleAction}
          actionLoading={actionLoading}
          isIsolated={isIsolated}
        />

        {/* 2. FILTER TABS (5 TABS) */}
        <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
          <FilterTabs
            tabs={STORYBOARD_TABS}
            active={tab}
            onChange={setTab}
          />
        </div>

        {/* 3. TAB CONTENT VIEWS */}
        <div style={{ flex: 1, padding: '0.25rem 0' }}>
          {tab === 'story' && (
            <StoryTimeline
              incidentId={detailedIncident.id}
              onAction={handleAction}
              actionLoading={actionLoading}
            />
          )}

          {tab === 'process' && (
            <ProcessAncestry
              incident={detailedIncident}
              onAction={handleAction}
              actionLoading={actionLoading}
            />
          )}

          {tab === 'network' && (
            <NetworkCorrelation
              incident={detailedIncident}
              onAction={handleAction}
              actionLoading={actionLoading}
            />
          )}

          {tab === 'actions' && (
            <ActionSuggestions
              incident={detailedIncident}
              onAction={handleAction}
              actionLoading={actionLoading}
              isIsolated={isIsolated}
            />
          )}

          {tab === 'notes' && (
            <IncidentNotes
              incidentId={detailedIncident.id}
            />
          )}

          {tab === 'ai' && (
            <AIAnalysisTab
              incidentId={detailedIncident.id}
            />
          )}
        </div>

        {/* 4. FOOTER LIFECYCLE BAR */}
        <div
          style={{
            marginTop: '1rem',
            paddingTop: '0.85rem',
            borderTop: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>
              Lifecycle Status:
            </span>
            <Button
              variant={detailedIncident.status === 'contained' ? 'primary' : 'outline'}
              size="sm"
              disabled={actionLoading}
              onClick={() => handleStatusChange('contained')}
            >
              Mark Contained
            </Button>
            <Button
              variant={detailedIncident.status === 'resolved' ? 'primary' : 'outline'}
              size="sm"
              disabled={actionLoading}
              onClick={() => handleStatusChange('resolved')}
            >
              Mark Resolved
            </Button>
            <Button
              variant={detailedIncident.status === 'false_positive' ? 'primary' : 'outline'}
              size="sm"
              disabled={actionLoading}
              onClick={() => handleStatusChange('false_positive')}
            >
              False Positive
            </Button>
            <Button
              variant={detailedIncident.status === 'closed' ? 'primary' : 'outline'}
              size="sm"
              disabled={actionLoading || isSubmittingClose}
              onClick={handleOpenCloseModal}
              title="Đóng incident và ghi nhận AI ground truth"
            >
              Close Incident
            </Button>

            {detailedIncident.label && LABEL_BADGE_CONFIG[detailedIncident.label] && (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  padding: '3px 8px',
                  borderRadius: '4px',
                  fontSize: '0.78rem',
                  fontWeight: 600,
                  background: LABEL_BADGE_CONFIG[detailedIncident.label].bg,
                  border: `1px solid ${LABEL_BADGE_CONFIG[detailedIncident.label].border}`,
                  color: LABEL_BADGE_CONFIG[detailedIncident.label].color,
                }}
                title={`Gán nhãn bởi: ${detailedIncident.labeledBy || 'N/A'}${detailedIncident.labelReason ? `\nLý do: ${detailedIncident.labelReason}` : ''}`}
              >
                AI Label: {LABEL_BADGE_CONFIG[detailedIncident.label].label}
              </span>
            )}
          </div>

          <Button variant="outline" size="sm" onClick={onClose}>
            Close Window
          </Button>
        </div>
      </div>

      {/* Sub-modal: Close Incident with AI Ground Truth */}
      <Modal
        isOpen={isCloseModalOpen}
        onClose={() => !isSubmittingClose && setIsCloseModalOpen(false)}
        title={`Đóng Incident ${detailedIncident.id}`}
        maxWidth={520}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
              Kết luận: <span style={{ color: 'var(--error)' }}>*</span>
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {LABEL_OPTIONS.map((opt) => {
                const selected = closeLabel === opt.value;
                return (
                  <label
                    key={opt.value}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.65rem',
                      padding: '0.6rem 0.8rem',
                      borderRadius: 'var(--radius-sm)',
                      border: selected ? '1px solid var(--primary)' : '1px solid var(--border)',
                      background: selected ? 'rgba(59, 130, 246, 0.1)' : 'var(--bg-secondary)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <input
                      type="radio"
                      name="incident_label"
                      value={opt.value}
                      checked={selected}
                      onChange={() => setCloseLabel(opt.value)}
                      style={{ marginTop: '0.2rem' }}
                    />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                      <span style={{ fontSize: '0.85rem', fontWeight: 600, color: opt.color }}>
                        {opt.label}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {opt.desc}
                      </span>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
              <label style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Lý do: <span style={{ color: 'var(--error)' }}>*</span>
              </label>
              <span
                style={{
                  fontSize: '0.75rem',
                  color: closeReason.trim().length >= 10 ? 'var(--success)' : 'var(--text-tertiary)',
                  fontWeight: 600,
                }}
              >
                {closeReason.trim().length}/10 ký tự tối thiểu
              </span>
            </div>
            <textarea
              rows={3}
              value={closeReason}
              onChange={(e) => setCloseReason(e.target.value)}
              placeholder="Nhập chi tiết nhận định / bằng chứng để lưu ground truth cho AI..."
              style={{
                width: '100%',
                padding: '0.6rem 0.75rem',
                fontSize: '0.85rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                outline: 'none',
                resize: 'vertical',
                fontFamily: 'inherit',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
            <Button
              variant="outline"
              size="sm"
              disabled={isSubmittingClose}
              onClick={() => setIsCloseModalOpen(false)}
            >
              Hủy
            </Button>
            <Button
              variant="primary"
              size="sm"
              disabled={!isCloseValid || isSubmittingClose}
              onClick={handleConfirmClose}
            >
              {isSubmittingClose ? 'Đang lưu...' : 'Đóng Incident'}
            </Button>
          </div>
        </div>
      </Modal>
    </Modal>
  );
}
