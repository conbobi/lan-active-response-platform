// src/routes/index.jsx
import React from 'react';
import Dashboard from '../pages/Dashboard';
import Agents from '../pages/Agents';
import Alerts from '../pages/Alerts';
import Network from '../pages/Network';
import Incidents from '../pages/Incidents';
import Commands from '../pages/Commands';
import RiskAssessment from '../pages/RiskAssessment';
import DetectionRules from '../pages/DetectionRules';
import ThreatIntel from '../pages/ThreatIntel';
import ProcessTree from '../pages/ProcessTree';
import Reports from '../pages/Reports';
import Whitelist from '../pages/Whitelist';
import Notifications from '../pages/Notifications';
import Rules from '../pages/Rules';
import Attack from '../pages/Attack';
import Settings from '../pages/Settings';

export const routes = [
  { path: '/', element: <Dashboard /> },
  { path: '/agents', element: <Agents /> },
  { path: '/alerts', element: <Alerts /> },
  { path: '/network', element: <Network /> },
  { path: '/incidents', element: <Incidents /> },
  { path: '/commands', element: <Commands /> },
  { path: '/risk', element: <RiskAssessment /> },
  { path: '/rules/detection', element: <DetectionRules defaultTab="detection" /> },
  { path: '/rules/process-chains', element: <DetectionRules defaultTab="process-chains" /> },
  { path: '/threat-intel', element: <ThreatIntel /> },
  { path: '/process', element: <ProcessTree /> },

  { path: '/reports', element: <Reports /> },
  { path: '/whitelist', element: <Whitelist /> },
  { path: '/notifications', element: <Notifications /> },
  { path: '/rules', element: <Rules /> },
  { path: '/attack', element: <Attack /> },
  { path: '/settings', element: <Settings /> },
];

export default routes;