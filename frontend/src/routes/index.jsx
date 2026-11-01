// src/routes/index.jsx
import React from 'react';
import { Navigate } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';
import Agents from '../pages/Agents';
import Incidents from '../pages/Incidents';
import ActionsHistory from '../pages/ActionsHistory';
import Policies from '../pages/Policies';
import DetectionRules from '../pages/DetectionRules';
import Settings from '../pages/Settings';
import Investigate from '../pages/Investigate';

export const routes = [
  { path: '/', element: <Dashboard /> },
  { path: '/incidents', element: <Incidents /> },
  { path: '/incidents/:id', element: <Incidents /> },
  { path: '/investigate', element: <Investigate /> },

  { path: '/actions', element: <ActionsHistory /> },
  { path: '/policies', element: <Policies /> },

  { path: '/agents', element: <Agents /> },
  { path: '/detection', element: <DetectionRules /> },
  { path: '/rules/detection', element: <DetectionRules /> },
  { path: '/rules/process-chains', element: <DetectionRules initialTab="process-chains" /> },
  { path: '/rules/yara', element: <DetectionRules initialTab="yara" /> },
  { path: '/settings', element: <Settings /> },

  // Backward compatibility redirects
  { path: '/alerts', element: <Navigate to="/incidents?tab=alerts" replace /> },
  { path: '/process', element: <Navigate to="/investigate?tab=process" replace /> },
  { path: '/network', element: <Navigate to="/investigate?tab=network" replace /> },
  { path: '/threat-intel', element: <Navigate to="/investigate?tab=threat-intel" replace /> },
  { path: '/groups', element: <Navigate to="/agents?tab=groups" replace /> },
  { path: '/commands', element: <Navigate to="/actions?tab=commands" replace /> },
  { path: '/whitelist', element: <Navigate to="/settings?tab=whitelist" replace /> },
  { path: '/notifications', element: <Navigate to="/settings?tab=notifications" replace /> },
  { path: '/reports', element: <Navigate to="/settings?tab=reports" replace /> },
  { path: '/rules', element: <Navigate to="/detection" replace /> },
];

export default routes;