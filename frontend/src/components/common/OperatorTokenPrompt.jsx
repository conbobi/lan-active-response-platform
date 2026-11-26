import { useEffect, useRef, useState } from 'react';
import Button from '../ui/Button';

import api from '../../api/api';
import { saveSession } from '../../api/operatorSession';

export default function OperatorTokenPrompt({ reason, onSaved, onClose }) {
  const dialog = useRef(null);
  useEffect(() => {
    const node = dialog.current;
    node.showModal();
    return () => node.close();
  }, []);
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const save = async (event) => {
    event.preventDefault();
    const token = value.trim();
    if (!token) return;
    setBusy(true);
    try {
      const session = await api.post('/auth/session', {}, { headers: { Authorization: `Bearer ${token}` } });
      saveSession(session.access_token);
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
      setValue('');
    }
  };
  return (
    <dialog ref={dialog} aria-label="Đăng nhập Dashboard" onCancel={onClose}>
    <form
      onSubmit={save}
      style={{
        padding: '0.75rem 1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.5rem',
        backgroundColor: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.3)',
      }}
    >
      <strong style={{ fontSize: '0.85rem' }}>Đăng nhập Dashboard</strong>
      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
        {reason || 'Manager yêu cầu token của operator được cấp quyền cho Agent này.'} Phiên có hiệu lực một giờ trong tab này.
      </span>
      {error && <span role="alert">{error}</span>}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Bearer token"
          aria-label="Operator token"
          style={{ flex: 1, padding: '0.4rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
        />
        <Button size="sm" variant="primary" type="submit" disabled={busy || !value.trim()}>Đăng nhập</Button>
        <Button size="sm" onClick={onClose}>Đóng</Button>
      </div>
    </form>
    </dialog>
  );
}
