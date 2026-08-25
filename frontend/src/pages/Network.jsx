// src/pages/Network.jsx
import React, { useRef } from 'react';
import useTopology from '../hooks/useTopology';
import NetworkToolbar from '../components/network/NetworkToolbar';
const NetworkTopology3D = React.lazy(() => import('../components/network/NetworkTopology3D'));

import { FiActivity, FiGlobe, FiRadio, FiAlertTriangle, FiXCircle, FiCheckCircle } from 'react-icons/fi';

export default function Network() {
  const {
    topology,
    loading,
    selectedFrom,
    setSelectedFrom,
    selectedTo,
    setSelectedTo,
    requiredBandwidth,
    setRequiredBandwidth,
    pathData,
    toasts,
    removeToast,
    handleFindPath,
    handleReleasePath,
    handleSimulateFailure,
  } = useTopology();

  const fgRef = useRef();

  const handleResetCameraView = () => {
    if (fgRef.current) {
      fgRef.current.cameraPosition(
        { x: 0, y: 0, z: 220 }, // Camera position
        { x: 0, y: 0, z: 0 },   // Look at point
        1200                    // Transition duration ms
      );
    }
  };

  const handleNodeClick = (node) => {
    if (!selectedFrom) {
      setSelectedFrom(node.id);
    } else if (!selectedTo && selectedFrom !== node.id) {
      setSelectedTo(node.id);
    } else {
      setSelectedFrom(node.id);
    }

    // Focus camera on clicked node
    if (fgRef.current && node.x !== undefined) {
      const distance = 80;
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
      fgRef.current.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        { x: node.x, y: node.y, z: node.z },
        1000
      );
    }
  };

  const handleLinkClick = (link) => {
    // Simulate failure on clicked link
    handleSimulateFailure(link.id);
  };

  const totalAgents = topology.agents.length;
  const activeAgents = topology.agents.filter((a) => a.status === 'online').length;
  const activeLinks = topology.links.filter((l) => l.isActive).length;
  const totalLinks = topology.links.length;

  const avgLatency =
    activeLinks > 0
      ? Math.round(topology.links.filter((l) => l.isActive).reduce((sum, l) => sum + (l.latency || 0), 0) / activeLinks)
      : 0;

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">3D Network Topology</h1>
        </div>
        <div className="card skeleton" style={{ height: '560px' }} />
      </div>
    );
  }

  return (
    <div>
      {/* Toast Notification Container */}
      <div
        style={{
          position: 'fixed',
          top: 80,
          right: 24,
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem',
          maxWidth: 380,
        }}
      >
        {toasts.map((toast) => {
          const bgMap = {
            error: 'rgba(239,68,68,0.92)',
            success: 'rgba(0,192,123,0.92)',
            info: 'rgba(97,0,255,0.92)',
            warning: 'rgba(245,158,11,0.92)',
          };
          return (
            <div
              key={toast.id}
              onClick={() => removeToast(toast.id)}
              style={{
                background: bgMap[toast.type] || bgMap.info,
                color: '#ffffff',
                padding: '0.75rem 1rem',
                borderRadius: 'var(--radius-md)',
                boxShadow: 'var(--shadow-lg)',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                animation: 'fadeSlideIn 0.3s ease both',
              }}
            >
              {toast.type === 'error' && <FiXCircle size={18} />}
              {toast.type === 'success' && <FiCheckCircle size={18} />}
              {toast.type === 'info' && <FiGlobe size={18} />}
              {toast.type === 'warning' && <FiAlertTriangle size={18} />}
              <span>{toast.message}</span>
            </div>
          );
        })}
      </div>

      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">3D Network Topology</h1>
          <p className="page-subtitle">Interactive 3D graph visualization, Dijkstra routing analysis, and link failure simulations</p>
        </div>
      </div>

      {/* KPI Cards Header */}
      <div className="net-kpi-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="net-kpi">
          <div className="net-kpi-label">Active Agents</div>
          <div className="net-kpi-value" style={{ color: 'var(--primary)' }}>
            {activeAgents} / {totalAgents}
          </div>
          <div className="net-kpi-unit">Registered nodes</div>
        </div>

        <div className="net-kpi">
          <div className="net-kpi-label">Active Links</div>
          <div className="net-kpi-value" style={{ color: 'var(--success)' }}>
            {activeLinks} / {totalLinks}
          </div>
          <div className="net-kpi-unit">Network connections</div>
        </div>

        <div className="net-kpi">
          <div className="net-kpi-label">Average Latency</div>
          <div className="net-kpi-value" style={{ color: 'var(--warning)' }}>
            {avgLatency} <span style={{ fontSize: '0.9rem' }}>ms</span>
          </div>
          <div className="net-kpi-unit">Across active links</div>
        </div>

        <div className="net-kpi">
          <div className="net-kpi-label">Selected Route</div>
          <div className="net-kpi-value" style={{ fontSize: '1.2rem', color: pathData?.found ? 'var(--primary)' : 'var(--text-tertiary)' }}>
            {pathData?.found ? `${pathData.totalLatency || pathData.total_latency} ms` : 'None'}
          </div>
          <div className="net-kpi-unit">
            {pathData?.found ? `${pathData.allocatedBandwidth || pathData.avgBandwidth || pathData.allocated_bandwidth} Mbps Allocated` : 'No path calculated'}
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <NetworkToolbar
        agents={topology.agents}
        links={topology.links}
        selectedFrom={selectedFrom}
        setSelectedFrom={setSelectedFrom}
        selectedTo={selectedTo}
        setSelectedTo={setSelectedTo}
        requiredBandwidth={requiredBandwidth}
        setRequiredBandwidth={setRequiredBandwidth}
        onFindPath={() => handleFindPath(selectedFrom, selectedTo, requiredBandwidth)}
        onReleasePath={handleReleasePath}
        onSimulateFailure={handleSimulateFailure}
        onResetView={handleResetCameraView}
        pathData={pathData}
      />

      {/* 3D Graph Scene */}
      <NetworkTopology3D
        agents={topology.agents}
        links={topology.links}
        pathData={pathData}
        onNodeClick={handleNodeClick}
        onLinkClick={handleLinkClick}
        fgRef={fgRef}
      />
    </div>
  );
}
