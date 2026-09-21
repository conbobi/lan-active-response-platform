// src/pages/ActionsHistory.jsx
import React from 'react';
import { FiClock, FiRotateCcw, FiLayers } from 'react-icons/fi';
import Button from '../components/ui/Button';
import { useNavigate } from 'react-router-dom';

export default function ActionsHistory() {
  const navigate = useNavigate();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '2rem' }}>
      <div className="page-header">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <FiClock className="text-primary" /> Response Actions History
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Nhật ký toàn diện các hành động cô lập, diệt process, chặn IP và trạng thái hoàn nguyên (Undo/Rollback)
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
            background: 'rgba(59, 130, 246, 0.1)',
            color: 'var(--info)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem auto',
          }}
        >
          <FiRotateCcw size={32} />
        </div>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
          Response Actions & Rollback Center
        </h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '480px', margin: '0 auto 1.5rem auto', fontSize: '0.9rem', lineHeight: 1.5 }}>
          Bảng tổng hợp tất cả các hành động can thiệp (Agent đơn & Group), bộ lọc đa tiêu chí và tính năng hoàn nguyên hàng loạt sẽ sẵn sàng trong <strong>Phase 4</strong>.
        </p>
        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
          <Button variant="outline" onClick={() => navigate('/groups')}>
            Xem Agent Groups
          </Button>
          <Button variant="primary" onClick={() => navigate('/incidents')}>
            Xem Incidents
          </Button>
        </div>
      </div>
    </div>
  );
}
