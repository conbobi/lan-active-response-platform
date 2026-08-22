import React from 'react';
import { Route } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';
import Agents from '../pages/Agents';
import Alerts from '../pages/Alerts';
import Network from '../pages/Network';
import Rules from '../pages/Rules';
import Attack from '../pages/Attack';
import Settings from '../pages/Settings';

export const routes = [
  { path: '/', element: <Dashboard /> },
  { path: '/agents', element: <Agents /> },
  { path: '/alerts', element: <Alerts /> },
  { path: '/network', element: <Network /> },
  { path: '/rules', element: <Rules /> },
  { path: '/attack', element: <Attack /> },
  { path: '/settings', element: <Settings /> },
];

export default routes;