// src/App.jsx
import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Agents from './pages/Agents';
import Alerts from './pages/Alerts';
import Network from './pages/Network';
import Incidents from './pages/Incidents';
import Commands from './pages/Commands';
import RiskAssessment from './pages/RiskAssessment';
import DetectionRules from './pages/DetectionRules';
import ThreatIntel from './pages/ThreatIntel';
import ProcessTree from './pages/ProcessTree';
import Reports from './pages/Reports';
import Whitelist from './pages/Whitelist';
import Notifications from './pages/Notifications';
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
          <Route path="/risk" element={<RiskAssessment />} />
          <Route path="/rules/detection" element={<DetectionRules />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/process" element={<ProcessTree />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/whitelist" element={<Whitelist />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/attack" element={<Attack />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/rules/process-chains" element={<DetectionRules initialTab="process-chains" />} />

        </Route>
      </Routes>
    </BrowserRouter>
  );
}