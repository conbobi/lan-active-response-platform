// src/pages/Policies.jsx
import React from 'react';
import { FiShield, FiClock } from 'react-icons/fi';
import Button from '../components/ui/Button';
import { useNavigate } from 'react-router-dom';

export default function Policies() {
  const navigate = useNavigate();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '2rem' }}>
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiShield className="text-primary" /> Response Policies
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Cấu hình tự động hóa phản ứng an ninh theo dải điểm rủi ro và phạm vi tác động (Agent / Group)
        </p>
      </div>

      <div
        className="card"
        style={{
          padding: '4rem 2rem',
          textAlign: 'center',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-card)',
        }}
      >
        <div
          style={{
            width: '64px',
            height: '64px',
            borderRadius: 'var(--radius-full)',
            background: 'var(--primary-light)',
            color: 'var(--primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem auto',
          }}
        >
          <FiShield size={32} />
        </div>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
          Response Policies Engine
        </h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '480px', margin: '0 auto 1.5rem auto', fontSize: '0.9rem', lineHeight: 1.5 }}>
          Giao diện cấu hình chính sách phản ứng động, bảng ngưỡng điểm rủi ro và bảng mô phỏng Dry-Run sẽ sẵn sàng trong <strong>Phase 3</strong>.
        </p>
        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
          <Button variant="outline" onClick={() => navigate('/groups')}>
            Quản lý Agent Groups
          </Button>
          <Button variant="primary" onClick={() => navigate('/risk')}>
            Xem Risk Monitor
          </Button>
        </div>
      </div>
    </div>
  );
}
