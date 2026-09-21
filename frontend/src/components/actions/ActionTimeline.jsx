// src/components/actions/ActionTimeline.jsx
import React, { useState } from 'react';
import Button from '../ui/Button';
import UndoButton from './UndoButton';
import AutoRollbackTimer from './AutoRollbackTimer';
import RollbackConfirmModal from './RollbackConfirmModal';
import AuditLogModal from './AuditLogModal';
import {
  FiShield,
  FiLock,
  FiLayers,
  FiSlash,
  FiActivity,
  FiRotateCcw,
  FiChevronDown,
  FiChevronUp,
  FiInfo,
} from 'react-icons/fi';

export default function ActionTimeline({
  actions = [],
  onUndo,
  onUndoAll,
  loading = false,
  actionLoading = false,
}) {
  const [batchModalOpen, setBatchModalOpen] = useState(false);
  const [selectedAuditActionId, setSelectedAuditActionId] = useState(null);
  const [expandedSnapshots, setExpandedSnapshots] = useState({});

  const toggleSnapshot = (id) => {
    setExpandedSnapshots((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const appliedActions = actions.filter((a) => a.status === 'applied');

  const getActionIcon = (type) => {
    switch (type) {
      case 'isolate':
      case 'auto_isolate':
        return <FiLock size={15} color="var(--error)" />;
      case 'kill':
      case 'kill_process':
      case 'kill_process_tree':
        return <FiLayers size={15} color="var(--warning)" />;
      case 'block_ip':
        return <FiSlash size={15} color="#ef4444" />;
      case 'quarantine':
        return <FiShield size={15} color="#a855f7" />;
      default:
        return <FiActivity size={15} color="var(--primary)" />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
        <div>
          <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <FiShield size={16} color="var(--primary)" /> Response Actions & Stateful Rollback
          </h4>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)' }}>
            {appliedActions.length} active mitigation(s) applied • {actions.length} total recorded
          </span>
        </div>

        {appliedActions.length > 0 && (
          <Button
            variant="danger"
            size="sm"
            disabled={actionLoading || loading}
            onClick={() => setBatchModalOpen(true)}
            iconLeft={<FiRotateCcw size={13} />}
          >
            Rollback All ({appliedActions.length})
          </Button>
        )}
      </div>

      {/* Loading state */}
      {loading && (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>
          Loading mitigation actions...
        </div>
      )}

      {/* Empty state */}
      {!loading && actions.length === 0 && (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.85rem', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          No response actions have been recorded yet. Use mitigation buttons above to execute actions.
        </div>
      )}

      {/* Action list */}
      {!loading && actions.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {actions.map((act) => {
            const isExpanded = !!expandedSnapshots[act.id];
            const isApplied = act.status === 'applied';

            return (
              <div
                key={act.id}
                style={{
                  background: 'var(--bg-secondary)',
                  border: isApplied ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.6rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: '6px',
                        background: 'var(--bg-primary)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: '1px solid var(--border)',
                      }}
                    >
                      {getActionIcon(act.action_type)}
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                          {act.action_type.replace('_', ' ')}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                          (Host: <strong style={{ color: 'var(--primary)' }}>{act.agent_id}</strong>)
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.1rem' }}>
                        Applied: {new Date(act.applied_at || act.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    {/* Live Auto Rollback Timer */}
                    <AutoRollbackTimer autoRollbackAt={act.auto_rollback_at} status={act.status} />

                    {/* Single Undo Button */}
                    <UndoButton
                      action={act}
                      onUndo={onUndo}
                      disabled={actionLoading}
                      size="sm"
                    />

                    {/* Audit Trail Button */}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setSelectedAuditActionId(act.id)}
                      iconLeft={<FiActivity size={12} />}
                      title="View Action Audit Trail"
                    >
                      Audit
                    </Button>
                  </div>
                </div>

                {/* Pre-Mitigation Snapshot Drawer */}
                {act.snapshot && (
                  <div style={{ borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                    <button
                      onClick={() => toggleSnapshot(act.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-secondary)',
                        fontSize: '0.76rem',
                        cursor: 'pointer',
                        padding: 0,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        fontWeight: 600,
                      }}
                    >
                      {isExpanded ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}
                      {isExpanded ? 'Hide Pre-Mitigation Snapshot' : 'View Pre-Mitigation Snapshot'}
                    </button>

                    {isExpanded && (
                      <div
                        style={{
                          marginTop: '0.5rem',
                          background: 'var(--bg-primary)',
                          border: '1px solid var(--border)',
                          borderRadius: '4px',
                          padding: '0.6rem 0.75rem',
                          fontSize: '0.75rem',
                          fontFamily: 'monospace',
                          color: 'var(--text-secondary)',
                          maxHeight: 180,
                          overflowY: 'auto',
                        }}
                      >
                        <pre style={{ margin: 0 }}>{JSON.stringify(act.snapshot, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Batch Undo Confirmation Modal */}
      <RollbackConfirmModal
        isOpen={batchModalOpen}
        onClose={() => setBatchModalOpen(false)}
        onConfirm={onUndoAll}
        isBatch={true}
        title="Confirm Batch Rollback"
      />

      {/* Audit Log Modal */}
      <AuditLogModal
        isOpen={!!selectedAuditActionId}
        onClose={() => setSelectedAuditActionId(null)}
        actionId={selectedAuditActionId}
      />
    </div>
  );
}
