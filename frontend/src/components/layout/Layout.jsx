import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';

export default function Layout() {
  const { pathname } = useLocation();
  return (
    <div className="app">
      <Header />
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