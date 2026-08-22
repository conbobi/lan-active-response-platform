import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Agents from './pages/Agents';
import Alerts from './pages/Alerts';
import Network from './pages/Network';
import Incidents from './pages/Incidents';
import Commands from './pages/Commands';
import Rules from './pages/Rules';
import Attack from './pages/Attack';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/network" element={<Network />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/commands" element={<Commands />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/attack" element={<Attack />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}