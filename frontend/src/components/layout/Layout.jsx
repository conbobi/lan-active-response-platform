import { useEffect, useState, useSyncExternalStore } from 'react';
import LoginForm from '../common/LoginForm';
import { bootstrapAuth, logoutSession } from '../../api/api';
import { readSession, readUser, subscribeSession } from '../../api/operatorSession';
import { Outlet, useLocation } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';

export default function Layout() {
  const { pathname } = useLocation();
  const token = useSyncExternalStore(subscribeSession, readSession);
  const user = useSyncExternalStore(subscribeSession, readUser);
  const [reason, setReason] = useState('');
  const [authReady, setAuthReady] = useState(() => Boolean(readSession()));

  useEffect(() => {
    let mounted = true;
    bootstrapAuth().finally(() => {
      if (mounted) setAuthReady(true);
    });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    const show = (event) =>
      setReason((previous) => (previous === 'Phiên đã hết hạn.' ? previous : event.detail));
    window.addEventListener('larp-sign-in', show);
    return () => window.removeEventListener('larp-sign-in', show);
  }, []);

  const sessionControl = (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      {user?.username && (
        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <strong>{user.username}</strong> ({user.role})
        </span>
      )}
      <button
        className="btn btn-secondary"
        onClick={async () => {
          if (token) {
            await logoutSession();
            setReason('');
          } else {
            setReason('Đăng nhập bằng tài khoản SOC được cấp.');
          }
        }}
      >
        {token ? 'Đăng xuất' : 'Đăng nhập'}
      </button>
    </div>
  );

  return (
    <div className="app">
      <Header sessionControl={sessionControl} />
      {reason && (
        <LoginForm
          reason={reason}
          onClose={() => setReason('')}
          onSaved={() => setReason('')}
        />
      )}
      <div className="main-container">
        <Sidebar />
        <main className="content" key={pathname}>
          <div className="page-motion">
            {authReady ? <Outlet /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
