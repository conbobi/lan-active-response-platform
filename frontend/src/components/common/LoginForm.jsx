import { useEffect, useRef, useState } from 'react';
import Button from '../ui/Button';
import { loginWithPassword } from '../../api/api';

export default function LoginForm({ reason, onSaved, onClose }) {
  const dialog = useRef(null);
  useEffect(() => {
    const node = dialog.current;
    node.showModal();
    return () => {
      if (node.open) node.close();
    };
  }, []);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    const cleanUser = username.trim();
    if (!cleanUser || !password) return;
    setBusy(true);
    setError('');
    try {
      await loginWithPassword(cleanUser, password);
      onSaved();
    } catch (err) {
      setError(err.message || 'Đăng nhập thất bại');
    } finally {
      setBusy(false);
      setPassword('');
    }
  };

  return (
    <dialog ref={dialog} aria-label="Đăng nhập Dashboard" onCancel={onClose}>
      <form
        onSubmit={submit}
        style={{
          padding: '1rem 1.25rem',
          borderRadius: '8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.65rem',
          minWidth: '340px',
          backgroundColor: 'var(--bg-elevated, #0f172a)',
          color: 'var(--text-primary, #f8fafc)',
          border: '1px solid rgba(59, 130, 246, 0.35)',
        }}
      >
        <strong style={{ fontSize: '0.95rem' }}>Đăng nhập LARP SOC Dashboard</strong>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          {reason || 'Đăng nhập bằng tài khoản SOC để thao tác và phê duyệt phản ứng.'} Phiên tự động gia hạn an toàn qua HttpOnly cookie.
        </span>
        {error && (
          <span role="alert" style={{ color: '#ef4444', fontSize: '0.8rem' }}>
            {error}
          </span>
        )}
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.8rem' }}>
          Tên đăng nhập
          <input
            type="text"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="soc-admin"
            aria-label="Tên đăng nhập"
            style={{
              padding: '0.45rem 0.65rem',
              borderRadius: '6px',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
            }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.8rem' }}>
          Mật khẩu
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            aria-label="Mật khẩu"
            style={{
              padding: '0.45rem 0.65rem',
              borderRadius: '6px',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
            }}
          />
        </label>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.25rem' }}>
          <Button size="sm" type="button" onClick={onClose}>
            Đóng
          </Button>
          <Button
            size="sm"
            variant="primary"
            type="submit"
            disabled={busy || !username.trim() || !password}
          >
            {busy ? 'Đang xác thực…' : 'Đăng nhập'}
          </Button>
        </div>
      </form>
    </dialog>
  );
}

