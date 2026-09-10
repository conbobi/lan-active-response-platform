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

      {/* Network Security Analytics: DNS Tunneling & HTTP Beaconing */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginTop: '1.5rem' }}>
        {/* DNS Tunneling Monitor */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiRadio color="var(--primary)" /> DNS Tunneling & Entropy Inspector
            </h3>
            <span className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>Shannon Entropy H(X) &gt; 3.8</span>
          </div>

          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
            Monitors high-randomness subdomains, TXT/NULL record spikes, and encoded data exfiltration payloads.
          </div>

          <div className="table-container" style={{ maxHeight: '200px', overflowY: 'auto' }}>
            <table className="table" style={{ fontSize: '0.8rem' }}>
              <thead>
                <tr>
                  <th>Query Domain</th>
                  <th>Type</th>
                  <th>Length</th>
                  <th>Entropy</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontFamily: 'monospace' }}>a9f8b7c6d5e4.tunnel.evil-c2.net</td>
                  <td>TXT</td>
                  <td>32</td>
                  <td style={{ color: 'var(--danger)', fontWeight: 600 }}>4.12</td>
                  <td><span className="badge badge-critical">Tunneling Suspect</span></td>
                </tr>
                <tr>
                  <td style={{ fontFamily: 'monospace' }}>api.github.com</td>
                  <td>A</td>
                  <td>14</td>
                  <td style={{ color: 'var(--success)' }}>2.34</td>
                  <td><span className="badge badge-online">Normal</span></td>
                </tr>
                <tr>
                  <td style={{ fontFamily: 'monospace' }}>update.microsoft.com</td>
                  <td>A</td>
                  <td>20</td>
                  <td style={{ color: 'var(--success)' }}>2.18</td>
                  <td><span className="badge badge-online">Normal</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* HTTP/TCP Beaconing Monitor */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FiActivity color="var(--warning)" /> C2 HTTP Beaconing Analysis
            </h3>
            <span className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>CV &lt; 0.25 Regular Rhythm</span>
          </div>

          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
            Detects persistent periodic outbound heartbeats with regular intervals (&sigma; / &mu; &lt; 25% jitter).
          </div>

          <div className="table-container" style={{ maxHeight: '200px', overflowY: 'auto' }}>
            <table className="table" style={{ fontSize: '0.8rem' }}>
              <thead>
                <tr>
                  <th>Destination Host</th>
                  <th>Port</th>
                  <th>Interval</th>
                  <th>Jitter (CV)</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>185.220.101.5</td>
                  <td>443</td>
                  <td>30.0s</td>
                  <td style={{ color: 'var(--danger)', fontWeight: 600 }}>0.08</td>
                  <td><span className="badge badge-critical">C2 Beacon (92%)</span></td>
                </tr>
                <tr>
                  <td style={{ fontFamily: 'monospace' }}>192.168.10.1</td>
                  <td>80</td>
                  <td>5.2s</td>
                  <td>0.65</td>
                  <td><span className="badge badge-online">Random Egress</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
