// src/pages/RiskAssessment.jsx
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useAgents } from '../hooks/useAgents';
import { getRiskHistory } from '../api/risk';
import Badge from '../components/ui/Badge';
import SearchBar from '../components/ui/SearchBar';
import Dropdown from '../components/ui/Dropdown';
import Pagination from '../components/ui/Pagination';
import Button from '../components/ui/Button';
import Modal from '../components/ui/Modal';
import LineChart from '../components/charts/LineChart';
import RiskGauge from '../components/ui/RiskGauge';
import { FiActivity, FiShield, FiRotateCw, FiTrendingUp, FiClock } from 'react-icons/fi';

const ITEMS_PER_PAGE = 8;

const STATUS_OPTS = [
  { value: 'all', label: 'All Statuses' },
  { value: 'active', label: 'Active' },
  { value: 'isolated', label: 'Isolated' },
  { value: 'dead', label: 'Dead / Offline' },
];

const RISK_OPTS = [
  { value: 'all', label: 'All Risk Levels' },
  { value: 'critical', label: 'Critical (>80)' },
  { value: 'high', label: 'High (60–80)' },
  { value: 'medium', label: 'Medium (30–60)' },
  { value: 'low', label: 'Low (<30)' },
];

export default function RiskAssessment() {
  const { agents, loading: agentsLoading, refreshAgents, handleIsolate, handleUnisolate } = useAgents();

  const [riskMap, setRiskMap] = useState({});
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  // Filter & Search States
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);

  // Modal State for Agent Risk History
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentHistory, setAgentHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Fetch Risk Scores for all Agents
  const fetchAllRiskScores = useCallback(async () => {
    if (!agents || agents.length === 0) {
      setLoading(false);
      return;
    }
    setLoading(true);

    const newRiskMap = {};
    await Promise.all(
      agents.map(async (agent) => {
        try {
          const res = await getRiskHistory(agent.id, 1);
          if (Array.isArray(res) && res.length > 0) {
            const latest = res[0];
            newRiskMap[agent.id] = {
              latestScore: latest.score,
              latestTimestamp: latest.timestamp,
              latestFactors: latest.factors || {},
              history: res,
            };
          } else {
            newRiskMap[agent.id] = {
              latestScore: null,
              latestTimestamp: null,
              latestFactors: {},
              history: [],
            };
          }
        } catch (err) {
          newRiskMap[agent.id] = {
            latestScore: null,
            latestTimestamp: null,
            latestFactors: {},
            history: [],
          };
        }
      })
    );

    setRiskMap(newRiskMap);
    setLastRefreshed(new Date());
    setLoading(false);
  }, [agents]);

  // Initial Fetch & Auto Polling every 10 seconds
  useEffect(() => {
    fetchAllRiskScores();
    const interval = setInterval(() => {
      fetchAllRiskScores();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchAllRiskScores]);

  // Filtered Agents List
  const filteredAgents = useMemo(() => {
    return agents.filter((agent) => {
      const matchSearch =
        (agent.hostname && agent.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (agent.ip && agent.ip.includes(searchTerm)) ||
        (agent.ip_address && agent.ip_address.includes(searchTerm)) ||
        (agent.id && agent.id.toLowerCase().includes(searchTerm.toLowerCase()));

      const agentStatus = agent.status || (agent.is_isolated ? 'isolated' : 'active');
      const matchStatus = statusFilter === 'all' || agentStatus === statusFilter;

      const riskData = riskMap[agent.id];
      const score = riskData ? riskData.latestScore : null;

      let matchRisk = true;
      if (riskFilter === 'critical') matchRisk = score !== null && score >= 80;
      else if (riskFilter === 'high') matchRisk = score !== null && score >= 60 && score < 80;
      else if (riskFilter === 'medium') matchRisk = score !== null && score >= 30 && score < 60;
      else if (riskFilter === 'low') matchRisk = score !== null && score < 30;

      return matchSearch && matchStatus && matchRisk;
    });
  }, [agents, searchTerm, statusFilter, riskFilter, riskMap]);

  // Pagination calculation
  const totalPages = Math.ceil(filteredAgents.length / ITEMS_PER_PAGE) || 1;
  const paginatedAgents = useMemo(() => {
    return filteredAgents.slice(
      (currentPage - 1) * ITEMS_PER_PAGE,
      currentPage * ITEMS_PER_PAGE
    );
  }, [filteredAgents, currentPage]);

  // Reset page when filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter, riskFilter]);

  // Open Modal & Fetch detailed history (limit = 50)
  const handleOpenDetailModal = async (agent) => {
    setSelectedAgent(agent);
    setHistoryLoading(true);
    try {
      const historyRes = await getRiskHistory(agent.id, 50);
      if (Array.isArray(historyRes) && historyRes.length > 0) {
        setAgentHistory([...historyRes].reverse());
      } else {
        setAgentHistory([]);
      }
    } catch (err) {
      setAgentHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const getRiskBadge = (score) => {
    if (score === null || score === undefined || isNaN(score)) {
      return <Badge status="offline" label="N/A" showDot={false} />;
    }
    const s = Math.round(score);
    if (s >= 80) return <Badge status="critical" label={`CRITICAL (${s})`} />;
    if (s >= 60) return <Badge status="warning" label={`HIGH (${s})`} />;
    if (s >= 30) return <Badge status="warning" label={`MEDIUM (${s})`} />;
    return <Badge status="online" label={`LOW (${s})`} />;
  };

  // Chart preparation
  const chartData = useMemo(() => {
    if (!agentHistory || agentHistory.length === 0) return null;
    return {
      labels: agentHistory.map((item) => new Date(item.timestamp).toLocaleTimeString()),
      datasets: [
        {
          label: 'Risk Score',
          data: agentHistory.map((item) => Math.round(item.score)),
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          tension: 0.35,
          fill: true,
          pointRadius: 4,
          pointHoverRadius: 6,
          borderWidth: 2,
        },
      ],
    };
  }, [agentHistory]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        min: 0,
        max: 100,
        ticks: { color: '#94a3b8', font: { size: 11 } },
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
      },
      x: {
        ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 8 },
        grid: { display: false },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: (ctx) => `Risk Score: ${ctx.parsed.y} / 100`,
        },
      },
    },
  };

  const currentModalRisk = selectedAgent && riskMap[selectedAgent.id];
  const modalLatestScore = currentModalRisk && currentModalRisk.latestScore !== null ? Math.round(currentModalRisk.latestScore) : null;
  const rawFactors = currentModalRisk?.latestFactors || {};
  const factorEntries = Array.isArray(rawFactors)
    ? rawFactors
    : Object.entries(rawFactors).map(([key, val]) => ({
        name: key,
        weight: typeof val === 'object' ? val.weight || val.score || 20 : val,
        description: typeof val === 'object' ? val.reason || val.description || 'Threshold triggered' : 'Risk factor triggered',
      }));

  if (agentsLoading && agents.length === 0) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Risk Monitor</h1>
        </div>
        <div className="card skeleton" style={{ height: '400px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Risk Monitor</h1>
          <p className="page-subtitle">Real-time risk scoring, behavioral metrics, and historical trend monitoring across all agents</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <FiClock size={13} /> Polling (10s) — Updated {lastRefreshed.toLocaleTimeString()}
          </span>
          <Button
            variant="outline"
            iconLeft={<FiRotateCw size={15} />}
            onClick={() => {
              refreshAgents();
              fetchAllRiskScores();
            }}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Main Risk Table Card */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            padding: '1rem 1.25rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiActivity size={18} color="var(--primary)" />
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Agent Risk Monitoring</span>
            <span className="badge badge-info">{filteredAgents.length} Agents</span>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <SearchBar
              value={searchTerm}
              onChange={setSearchTerm}
              placeholder="Search hostname or IP…"
              style={{ width: 220 }}
            />
            <Dropdown
              label="Status"
              options={STATUS_OPTS}
              value={statusFilter}
              onChange={setStatusFilter}
            />
            <Dropdown
              label="Risk Level"
              options={RISK_OPTS}
              value={riskFilter}
              onChange={setRiskFilter}
            />
          </div>
        </div>

        {/* Table */}
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Current Risk Score</th>
                <th>Status</th>
                <th>Last Assessment Time</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAgents.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No matching agents found
                  </td>
                </tr>
              ) : (
                paginatedAgents.map((agent) => {
                  const riskData = riskMap[agent.id];
                  const score = riskData ? riskData.latestScore : null;
                  const timestamp = riskData ? riskData.latestTimestamp : null;
                  const agentStatus = agent.status || (agent.is_isolated ? 'isolated' : 'active');

                  return (
                    <tr key={agent.id} style={{ cursor: 'pointer' }} onClick={() => handleOpenDetailModal(agent)}>
                      <td style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--primary)' }}>
                        {agent.id}
                      </td>
                      <td style={{ fontWeight: 600 }}>{agent.hostname || agent.name}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{agent.ip || agent.ip_address}</td>
                      <td>{getRiskBadge(score)}</td>
                      <td>
                        <Badge status={agentStatus === 'active' ? 'online' : agentStatus === 'isolated' ? 'critical' : 'offline'} label={agentStatus.toUpperCase()} />
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
                        {timestamp ? new Date(timestamp).toLocaleString() : 'N/A'}
                      </td>
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <Button
                          variant="ghost"
                          size="sm"
                          iconLeft={<FiTrendingUp size={14} />}
                          onClick={() => handleOpenDetailModal(agent)}
                        >
                          History
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div
          style={{
            padding: '1rem 1.25rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            borderTop: '1px solid var(--border)',
          }}
        >
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Showing {Math.min((currentPage - 1) * ITEMS_PER_PAGE + 1, filteredAgents.length)}–
            {Math.min(currentPage * ITEMS_PER_PAGE, filteredAgents.length)} of {filteredAgents.length}
          </span>
          <Pagination current={currentPage} total={totalPages} onChange={setCurrentPage} />
        </div>
      </div>

      {/* Risk History Modal */}
      {selectedAgent && (
        <Modal
          isOpen={!!selectedAgent}
          onClose={() => setSelectedAgent(null)}
          title={`Risk Analytics — ${selectedAgent.hostname || selectedAgent.name} (${selectedAgent.ip || selectedAgent.ip_address})`}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Header KPI Row */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justify: 'space-around',
                background: 'var(--bg-secondary)',
                padding: '1rem',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border)',
              }}
            >
              <RiskGauge value={modalLatestScore !== null ? modalLatestScore : 0} size={110} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Current Risk Level:</span>
                {getRiskBadge(modalLatestScore)}
                <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }}>
                  Agent Status: <strong>{(selectedAgent.status || 'ACTIVE').toUpperCase()}</strong>
                </span>
              </div>
            </div>

            {/* Historical Line Chart */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.9rem', fontWeight: 700, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <FiTrendingUp color="var(--primary)" /> Risk Score Trend (Last 50 Evaluations)
              </h4>
              <div style={{ height: 220 }}>
                {historyLoading ? (
                  <div className="skeleton" style={{ height: '100%' }} />
                ) : chartData ? (
                  <LineChart data={chartData} options={chartOptions} />
                ) : (
                  <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)' }}>
                    No historical telemetry recorded.
                  </div>
                )}
              </div>
            </div>

            {/* Triggered Factors */}
            <div>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Triggered Risk Factors ({factorEntries.length})
              </h4>
              {factorEntries.length === 0 ? (
                <div style={{ fontSize: '0.85rem', color: 'var(--success)', background: 'rgba(0,192,123,0.08)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                  ✓ No active risk factors triggered in latest evaluation.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: 180, overflowY: 'auto' }}>
                  {factorEntries.map((factor, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.65rem 0.85rem',
                        background: 'rgba(239,68,68,0.06)',
                        border: '1px solid rgba(239,68,68,0.2)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        justify: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--error)' }}>
                          {factor.name || factor.rule_name || `Factor #${idx + 1}`}
                        </div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {factor.description || factor.reason || 'Threshold triggered'}
                        </div>
                      </div>
                      <Badge status="critical" label={`+${factor.weight || 20}`} showDot={false} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Action footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              {selectedAgent.status !== 'isolated' && !selectedAgent.is_isolated ? (
                <Button variant="danger" size="sm" onClick={() => handleIsolate(selectedAgent.id)}>
                  Isolate Agent
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={() => handleUnisolate(selectedAgent.id)}>
                  Release Agent
                </Button>
              )}
              <Button variant="ghost" size="sm" onClick={() => setSelectedAgent(null)}>
                Close
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}