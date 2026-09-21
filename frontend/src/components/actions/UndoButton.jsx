// src/components/actions/UndoButton.jsx
import React, { useState } from 'react';
import Button from '../ui/Button';
import RollbackConfirmModal from './RollbackConfirmModal';
import { FiRotateCcw, FiCheck } from 'react-icons/fi';

export default function UndoButton({ action, onUndo, disabled = false, size = 'sm' }) {
  const [modalOpen, setModalOpen] = useState(false);

  if (!action) return null;

  const isReverted = action.status === 'reverted';
  const isReverting = action.status === 'reverting';

  if (isReverted) {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.3rem',
          fontSize: '0.78rem',
          color: 'var(--text-tertiary)',
          padding: '0.25rem 0.5rem',
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border)',
        }}
        title={`Reverted at ${action.undone_at || ''} by ${action.undone_by || ''}`}
      >
        <FiCheck size={12} color="var(--success)" /> Undone
      </span>
    );
  }

  return (
    <>
      <Button
        variant="warning"
        size={size}
        disabled={disabled || isReverting}
        onClick={() => setModalOpen(true)}
        iconLeft={<FiRotateCcw size={13} />}
        title="Revert this mitigation action and restore host state"
      >
        {isReverting ? 'Reverting...' : 'Undo Action'}
      </Button>

      <RollbackConfirmModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        action={action}
        onConfirm={(reason) => onUndo(action.id, reason)}
      />
    </>
  );
}
