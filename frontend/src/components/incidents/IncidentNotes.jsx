// src/components/incidents/IncidentNotes.jsx
import React, { useState, useEffect } from 'react';
import { getIncidentNotes, addIncidentNote } from '../../api/incidents';
import Button from '../ui/Button';
import { FiSend, FiFileText, FiClock, FiUser, FiRefreshCw } from 'react-icons/fi';

export default function IncidentNotes({ incidentId }) {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newContent, setNewContent] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const fetchNotes = async () => {
    if (!incidentId) return;
    setLoading(true);
    try {
      const items = await getIncidentNotes(incidentId);
      setNotes(Array.isArray(items) ? items : []);
    } catch (err) {
      console.warn('Failed to load incident notes:', err);
      setNotes([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotes();
  }, [incidentId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!newContent.trim() || submitting) return;

    setSubmitting(true);
    try {
      await addIncidentNote(incidentId, newContent.trim(), 'analyst');
      setNewContent('');
      await fetchNotes();
    } catch (err) {
      console.error('Error adding note:', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div>
        <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          Nhật ký điều tra & Ghi chú Analyst (Investigation Audit Log)
        </h4>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
          Lưu vết toàn bộ tiến trình điều tra của SOC Analyst và các cảnh báo hệ thống
        </span>
      </div>

      {/* Notes Stream */}
      <div
        style={{
          maxHeight: '340px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem',
          paddingRight: '0.4rem',
        }}
      >
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
            <FiRefreshCw className="animate-spin" size={20} style={{ margin: '0 auto 0.5rem' }} />
            <p>Đang tải nhật ký điều tra...</p>
          </div>
        ) : notes.length === 0 ? (
          <div
            style={{
              padding: '2rem',
              textAlign: 'center',
              color: 'var(--text-tertiary)',
              background: 'var(--bg-secondary)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
            }}
          >
            Chưa có ghi chú nào được ghi lại cho sự cố này.
          </div>
        ) : (
          notes.map((note) => {
            const isSystem = note.user === 'system';
            return (
              <div
                key={note.id || Math.random()}
                style={{
                  padding: '0.75rem 1rem',
                  background: isSystem ? 'rgba(255, 255, 255, 0.02)' : 'var(--bg-secondary)',
                  borderLeft: isSystem ? '3px solid var(--text-tertiary)' : '3px solid var(--primary)',
                  borderTop: '1px solid var(--border)',
                  borderRight: '1px solid var(--border)',
                  borderBottom: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.85rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                  <span
                    style={{
                      fontWeight: 700,
                      color: isSystem ? 'var(--text-secondary)' : 'var(--primary)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                    }}
                  >
                    <FiUser size={13} />
                    {isSystem ? 'Hệ thống tự động' : note.user}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <FiClock size={11} />
                    {note.created_at ? new Date(note.created_at).toLocaleString() : ''}
                  </span>
                </div>
                <div style={{ color: 'var(--text-primary)', whiteSpace: 'pre-wrap', lineHeight: 1.45 }}>
                  {note.content}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Add Note Form */}
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
        <input
          type="text"
          placeholder="Nhập ghi chú điều tra hoặc nhận định phân tích..."
          value={newContent}
          onChange={(e) => setNewContent(e.target.value)}
          style={{
            flex: 1,
            padding: '0.65rem 0.9rem',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--text-primary)',
            fontSize: '0.875rem',
          }}
          disabled={submitting}
        />
        <Button
          type="submit"
          variant="primary"
          disabled={submitting || !newContent.trim()}
          iconLeft={<FiSend size={14} />}
        >
          Thêm ghi chú
        </Button>
      </form>
    </div>
  );
}
