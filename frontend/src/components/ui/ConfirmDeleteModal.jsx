import React from 'react';
import { FiAlertTriangle, FiTrash2 } from 'react-icons/fi';
import Modal from './Modal';
import Button from './Button';

export default function ConfirmDeleteModal({
  isOpen,
  onClose,
  onConfirm,
  title = 'Xác nhận xóa vĩnh viễn',
  message = 'Hành động này sẽ xóa vĩnh viễn dữ liệu đã chọn khỏi cơ sở dữ liệu PostgreSQL. Dữ liệu sau khi xóa sẽ không thể khôi phục!',
  itemCount = 1,
  itemDescription,
  loading = false,
}) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} maxWidth={520}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{
          display: 'flex',
          gap: '1rem',
          alignItems: 'flex-start',
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid var(--error, #ef4444)',
          borderRadius: '8px',
          padding: '1rem',
        }}>
          <div style={{
            background: 'var(--error, #ef4444)',
            color: '#fff',
            borderRadius: '50%',
            width: '36px',
            height: '36px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            <FiAlertTriangle size={20} />
          </div>
          <div>
            <div style={{ fontWeight: 700, color: 'var(--error, #ef4444)', fontSize: '0.95rem', marginBottom: '0.25rem' }}>
              CẢNH BÁO AN TOÀN DỮ LIỆU
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              {message}
            </div>
          </div>
        </div>

        {itemDescription && (
          <div style={{
            background: 'var(--bg-tertiary, #1e293b)',
            padding: '0.75rem 1rem',
            borderRadius: '6px',
            fontSize: '0.85rem',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
          }}>
            <strong style={{ color: 'var(--text-secondary)' }}>Mục bị xóa ({itemCount}): </strong>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{itemDescription}</span>
          </div>
        )}

        <div style={{
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '0.75rem',
          marginTop: '0.5rem',
        }}>
          <Button variant="ghost" onClick={onClose} disabled={loading}>
            Hủy bỏ
          </Button>
          <Button
            variant="danger"
            iconLeft={<FiTrash2 size={14} />}
            onClick={onConfirm}
            loading={loading}
          >
            Xác nhận xóa vĩnh viễn
          </Button>
        </div>
      </div>
    </Modal>
  );
}

