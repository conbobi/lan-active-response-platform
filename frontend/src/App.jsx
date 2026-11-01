import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Agents from './pages/Agents';
import Incidents from './pages/Incidents';
import ActionsHistory from './pages/ActionsHistory';
import Policies from './pages/Policies';
import DetectionRules from './pages/DetectionRules';
import Settings from './pages/Settings';
import Investigate from './pages/Investigate';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        {/* Operations Hub */}
        <Route path="/" element={<Dashboard />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<Incidents />} />
        <Route path="/investigate" element={<Investigate />} />

        {/* Response Actions & Automation */}
        <Route path="/actions" element={<ActionsHistory />} />
        <Route path="/policies" element={<Policies />} />

        {/* Management & Administration */}
        <Route path="/agents" element={<Agents />} />
        <Route path="/detection" element={<DetectionRules />} />
        <Route path="/rules/detection" element={<DetectionRules />} />
        <Route path="/rules/process-chains" element={<DetectionRules initialTab="process-chains" />} />
        <Route path="/rules/yara" element={<DetectionRules initialTab="yara" />} />
        <Route path="/settings" element={<Settings />} />

        {/* Backward Compatibility Routes (Consolidated into 7 Core Hubs) */}
        <Route path="/alerts" element={<Navigate to="/incidents?tab=alerts" replace />} />
        <Route path="/process" element={<Navigate to="/investigate?tab=process" replace />} />
        <Route path="/network" element={<Navigate to="/investigate?tab=network" replace />} />
        <Route path="/threat-intel" element={<Navigate to="/investigate?tab=threat-intel" replace />} />
        <Route path="/groups" element={<Navigate to="/agents?tab=groups" replace />} />
        <Route path="/commands" element={<Navigate to="/actions?tab=commands" replace />} />
        <Route path="/whitelist" element={<Navigate to="/settings?tab=whitelist" replace />} />
        <Route path="/notifications" element={<Navigate to="/settings?tab=notifications" replace />} />
        <Route path="/reports" element={<Navigate to="/settings?tab=reports" replace />} />
        <Route path="/rules" element={<Navigate to="/detection" replace />} />

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}