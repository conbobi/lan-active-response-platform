// src/components/incidents/IncidentDetailModal.jsx
import React, { useState, useEffect } from 'react';
import Modal from '../ui/Modal';
import FilterTabs from '../ui/FilterTabs';
import Button from '../ui/Button';
import HeroBanner from './HeroBanner';
import StoryTimeline from './StoryTimeline';
import ProcessAncestry from './ProcessAncestry';
import NetworkCorrelation from './NetworkCorrelation';
import ActionSuggestions from './ActionSuggestions';
import IncidentNotes from './IncidentNotes';
import { executeIncidentAction, updateIncidentStatus, getIncident } from '../../api/incidents';
import { useAgents } from '../../hooks/useAgents';

const STORYBOARD_TABS = [
  { value: 'story', label: '📖 Story' },
  { value: 'process', label: '🌳 Process' },
  { value: 'network', label: '🌐 Network' },
  { value: 'actions', label: '⚡ Actions' },
  { value: 'notes', label: '📝 Notes' },
];

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
      showToast(res.message || `Thực thi thành công: ${actionType}`);

      // Refresh incident & agents
      if (refreshAgents) refreshAgents();
      if (onRefresh) onRefresh();

      // Refresh local incident details
      const updated = await getIncident(detailedIncident.id);
      setDetailedIncident(updated);
    } catch (err) {
      console.error(`Action error ${actionType}:`, err);
      showToast(err.message || `Lỗi khi thực hiện ${actionType}`, 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!detailedIncident?.id || actionLoading) return;
    setActionLoading(true);
    try {
      await updateIncidentStatus(detailedIncident.id, newStatus);
      showToast(`Đã chuyển trạng thái sự cố sang: ${newStatus.toUpperCase()}`);
      if (onRefresh) onRefresh();
      const updated = await getIncident(detailedIncident.id);
      setDetailedIncident(updated);
    } catch (err) {
      showToast(`Không thể cập nhật trạng thái: ${err.message}`, 'error');
    } finally {
      setActionLoading(false);
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
              disabled={actionLoading}
              onClick={() => handleStatusChange('closed')}
            >
              Close
            </Button>
          </div>

          <Button variant="outline" size="sm" onClick={onClose}>
            Close Window
          </Button>
        </div>
      </div>
    </Modal>
  );
}
