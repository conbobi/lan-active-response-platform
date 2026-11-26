import { useEffect, useState, useSyncExternalStore } from 'react';
import OperatorTokenPrompt from '../common/OperatorTokenPrompt';
import { readSession, saveSession, subscribeSession } from '../../api/operatorSession';
import { Outlet, useLocation } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';

export default function Layout() {
  const { pathname } = useLocation();
  const token = useSyncExternalStore(subscribeSession, readSession);
  const [reason, setReason] = useState('');
  useEffect(() => {
    const show = event => setReason(previous => previous === 'Phiên đã hết hạn.' ? previous : event.detail);
    window.addEventListener('larp-sign-in', show);
    return () => window.removeEventListener('larp-sign-in', show);
  }, []);
  return (
    <div className="app">
      <Header sessionControl={<button className="btn btn-secondary" onClick={() => {
        if (token) saveSession('');
        setReason(token ? '' : 'Nhập credential do quản trị viên cấp.');
      }}>{token ? 'Đăng xuất' : 'Đăng nhập'}</button>} />
      {reason && <OperatorTokenPrompt reason={reason} onClose={() => setReason('')} onSaved={() => setReason('')} />}
      <div className="main-container">
        <Sidebar />
        <main className="content" key={pathname}>
          <div className="page-motion">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}