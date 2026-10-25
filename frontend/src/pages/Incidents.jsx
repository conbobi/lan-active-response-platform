import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import useIncidents from '../hooks/useIncidents';
import { useAgents } from '../hooks/useAgents';
import IncidentDetailModal from '../components/incidents/IncidentDetailModal';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import FilterTabs from '../components/ui/FilterTabs';
import Dropdown from '../components/ui/Dropdown';
import ErrorState from '../components/ui/ErrorState';
import EmptyState from '../components/ui/EmptyState';
import InfoTooltip from '../components/ui/InfoTooltip';
import { SkeletonTable } from '../components/ui/Skeleton';
import { TOOLTIPS } from '../constants/tooltips';
import {
  FiAlertTriangle,
  FiCheckCircle,
  FiShield,
  FiClock,
  FiUser,
  FiSearch,
  FiFilter,
  FiEye,
  FiUserPlus,
  FiLayers,
  FiRotateCw,
  FiLock,
  FiUnlock,
  FiSlash,
  FiFileText,
  FiActivity,
  FiBarChart2,
  FiPieChart,
  FiXCircle,
  FiCornerDownRight,
  FiSend,
  FiGlobe,
  FiTrendingUp
} from 'react-icons/fi';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function Incidents() {
  const {
    incidents,
    loading,
    error,
    actionLoading,
    refreshIncidents,
    handleAssign,
    handleUpdateStatus,
    handleAddNote,
    handleExecuteAction,
  } = useIncidents();

  const { agents } = useAgents();

  // Filter States
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [agentFilter, setAgentFilter] = useState('all');
  const [timeFilter, setTimeFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Modals
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [assignModalInc, setAssignModalInc] = useState(null);
  const [assigneeInput, setAssigneeInput] = useState('');

  const [searchParams] = useSearchParams();
  const { id: paramId } = useParams();
  const targetId = paramId || searchParams.get('id');

  useEffect(() => {
    if (targetId && incidents.length > 0) {
      const found = incidents.find((i) => String(i.id) === String(targetId));
      if (found) {
        setSelectedIncident(found);
      }
    }
  }, [targetId, incidents]);



  // KPI Calculations
  const kpis = useMemo(() => {
    const total = incidents.length;
    const openCount = incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length;
    const containedCount = incidents.filter((i) => i.status === 'contained').length;
    const resolvedCount = incidents.filter((i) => i.status === 'resolved').length;
    const falsePositiveCount = incidents.filter((i) => i.status === 'false_positive').length;
    const closedCount = incidents.filter((i) => i.status === 'closed').length;

    return { total, openCount, containedCount, resolvedCount, falsePositiveCount, closedCount };
  }, [incidents]);

  // LineChart Data & Aggregation
  const chartData = useMemo(() => {
    const dates = [];
    const dateMap = {};

    // Generate last 7 days window
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      const dateStr = d.toISOString().split('T')[0];
      dates.push(dateStr);
      dateMap[dateStr] = {
        open: 0,
        contained: 0,
        resolved: 0,
        false_positive: 0,
        closed: 0,
      };
    }

    incidents.forEach((inc) => {
      if (!inc.createdAt) return;
      const dStr = new Date(inc.createdAt).toISOString().split('T')[0];
      if (!dateMap[dStr]) {
        dateMap[dStr] = { open: 0, contained: 0, resolved: 0, false_positive: 0, closed: 0 };
        if (!dates.includes(dStr)) dates.push(dStr);
      }
      let st = inc.status;
      if (st === 'investigating') st = 'open';
      if (dateMap[dStr] && dateMap[dStr][st] !== undefined) {
        dateMap[dStr][st] += 1;
      }
    });

    dates.sort();

    const labels = dates.map((d) => {
      const parts = d.split('-');
      return `${parts[1]}/${parts[2]}`;
    });

    const colorConfig = {
      open: { label: 'Open / Active', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)' },
      contained: { label: 'Contained', color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)' },
      resolved: { label: 'Resolved', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.15)' },
      false_positive: { label: 'False Positive', color: '#a855f7', bg: 'rgba(168, 85, 247, 0.15)' },
      closed: { label: 'Closed', color: '#6b7280', bg: 'rgba(107, 114, 128, 0.15)' },
    };

    const datasets = [];

    if (statusFilter === 'all') {
      Object.keys(colorConfig).forEach((key) => {
        datasets.push({
          label: colorConfig[key].label,
          data: dates.map((d) => dateMap[d][key] || 0),
          borderColor: colorConfig[key].color,
          backgroundColor: colorConfig[key].bg,
          borderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
          tension: 0.3,
          fill: true,
        });
      });
    } else {
      const key = statusFilter === 'investigating' ? 'open' : statusFilter;
      const cfg = colorConfig[key] || { label: statusFilter, color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.15)' };
      datasets.push({
        label: cfg.label,
        data: dates.map((d) => dateMap[d][key] || 0),
        borderColor: cfg.color,
        backgroundColor: cfg.bg,
        borderWidth: 2.5,
        pointRadius: 5,
        pointHoverRadius: 7,
        tension: 0.35,
        fill: true,
      });
    }

    return { labels, datasets };
  }, [incidents, statusFilter]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: {
          color: 'var(--text-secondary)',
          font: { size: 12, weight: '500' },
          usePointStyle: true,
          padding: 15,
        },
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: 'var(--bg-secondary)',
        titleColor: 'var(--text-primary)',
        bodyColor: 'var(--text-secondary)',
        borderColor: 'var(--border)',
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: 'var(--text-tertiary)' },
      },
      y: {
        grid: { color: 'rgba(255, 255, 255, 0.05)' },
        ticks: { color: 'var(--text-tertiary)', precision: 0 },
        beginAtZero: true,
      },
    },
  };

  // Filter Tab Definitions
  const statusTabs = [
    { id: 'all', label: `All (${incidents.length})` },
    { id: 'open', label: `Open / Active (${kpis.openCount})` },
    { id: 'contained', label: `Contained (${kpis.containedCount})` },
    { id: 'resolved', label: `Resolved (${kpis.resolvedCount})` },
    { id: 'false_positive', label: `False Positive (${kpis.falsePositiveCount})` },
    { id: 'closed', label: `Closed (${kpis.closedCount})` },
  ];

  // Agent Dropdown Options
  const agentOptions = useMemo(() => {
    const opts = [{ value: 'all', label: 'All Agents' }];
    agents.forEach((a) => {
      opts.push({ value: a.id, label: `${a.name || a.hostname} (${a.id})` });
    });
    return opts;
  }, [agents]);

  const severityOptions = [
    { value: 'all', label: 'All Severities' },
    { value: 'critical', label: 'Critical Severity' },
    { value: 'high', label: 'High Severity' },
    { value: 'medium', label: 'Medium Severity' },
    { value: 'low', label: 'Low Severity' },
  ];

  const timeOptions = [
    { value: 'all', label: 'All Time' },
    { value: 'today', label: 'Today' },
    { value: '7days', label: 'Last 7 Days' },
    { value: '30days', label: 'Last 30 Days' },
  ];

  // Filtering Logic
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      // Search
      const search = searchTerm.toLowerCase();
      const matchSearch =
        !search ||
        (inc.id && inc.id.toLowerCase().includes(search)) ||
        (inc.title && inc.title.toLowerCase().includes(search)) ||
        (inc.agentId && inc.agentId.toLowerCase().includes(search)) ||
        (inc.description && inc.description.toLowerCase().includes(search));

      // Status
      let matchStatus = true;
      if (statusFilter === 'open') {
        matchStatus = inc.status === 'open' || inc.status === 'investigating';
      } else if (statusFilter !== 'all') {
        matchStatus = inc.status === statusFilter;
      }

      // Severity
      const matchSeverity = severityFilter === 'all' || inc.severity === severityFilter;

      // Agent
      const matchAgent = agentFilter === 'all' || inc.agentId === agentFilter;

      // Time Range
      let matchTime = true;
      if (timeFilter !== 'all') {
        const createdMs = new Date(inc.createdAt).getTime();
        const nowMs = Date.now();
        if (timeFilter === 'today') {
          matchTime = nowMs - createdMs <= 86400000;
        } else if (timeFilter === '7days') {
          matchTime = nowMs - createdMs <= 7 * 86400000;
        } else if (timeFilter === '30days') {
          matchTime = nowMs - createdMs <= 30 * 86400000;
        }
      }

      return matchSearch && matchStatus && matchSeverity && matchAgent && matchTime;
    });
  }, [incidents, searchTerm, statusFilter, severityFilter, agentFilter, timeFilter]);

  // Pagination
  const totalPages = Math.ceil(filteredIncidents.length / itemsPerPage) || 1;
  const paginatedIncidents = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredIncidents.slice(start, start + itemsPerPage);
  }, [filteredIncidents, currentPage]);

  // Handlers
  const openAssignModal = (inc, e) => {
    if (e) e.stopPropagation();
    setAssignModalInc(inc);
    setAssigneeInput(inc.assignedTo !== 'Unassigned' ? inc.assignedTo : '');
  };

  const submitAssign = async (e) => {
    e.preventDefault();
    if (!assignModalInc || !assigneeInput.trim()) return;
    try {
      await handleAssign(assignModalInc.id, assigneeInput.trim());
      toast.success(`Đã phân công incident cho ${assigneeInput.trim()}`);
      setAssignModalInc(null);
    } catch (err) {
      toast.error(`Phân công thất bại: ${err.message}`);
    }
  };

  const onQuickStatusChange = async (incId, newStatus, e) => {
    if (e) e.stopPropagation();
    try {
      await handleUpdateStatus(incId, newStatus);
      toast.success(`Đã cập nhật trạng thái thành ${newStatus}`);
      if (selectedIncident && selectedIncident.id === incId) {
        setSelectedIncident((prev) => (prev ? { ...prev, status: newStatus } : null));
      }
    } catch (err) {
      toast.error(`Cập nhật trạng thái thất bại: ${err.message}`);
    }
  };

  const renderStatusBadge = (status) => {
    switch (status) {
      case 'open':
        return <InfoTooltip {...TOOLTIPS.StatusOpen}><Badge status="danger" label="Open" /></InfoTooltip>;
      case 'investigating':
        return <InfoTooltip {...TOOLTIPS.StatusInvestigating}><Badge status="warning" label="Investigating" /></InfoTooltip>;
      case 'contained':
        return <InfoTooltip {...TOOLTIPS.StatusContained}><Badge status="info" label="Contained" /></InfoTooltip>;
      case 'resolved':
        return <InfoTooltip {...TOOLTIPS.StatusResolved}><Badge status="success" label="Resolved" /></InfoTooltip>;
      case 'false_positive':
        return <InfoTooltip {...TOOLTIPS.StatusFalsePositive}><Badge status="neutral" label="False Positive" /></InfoTooltip>;
      case 'closed':
        return <InfoTooltip {...TOOLTIPS.StatusClosed}><Badge status="neutral" label="Closed" /></InfoTooltip>;
      default:
        return <Badge status="neutral" label={status} />;
    }
  };

  const renderSeverityBadge = (sev) => {
    const s = sev ? sev.toLowerCase() : 'medium';
    if (s === 'critical') return <Badge status="critical" label="CRITICAL" />;
    if (s === 'high') return <Badge status="danger" label="HIGH" />;
    if (s === 'medium') return <Badge status="warning" label="MEDIUM" />;
    return <Badge status="info" label="LOW" />;
  };

  if (error && incidents.length === 0) {
    return (
      <ErrorState
        title="Không thể tải danh sách sự cố"
        message={`${error}. Vui lòng kiểm tra kết nối với Manager backend tại http://localhost:8005`}
        onRetry={refreshIncidents}
      />
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Incident Management & SOC Response</h1>
          <p className="page-subtitle">Track, triage, investigate, and orchestrate automated response actions across security incidents</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshIncidents} disabled={loading}>
            Refresh
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="stats-grid" style={{ marginBottom: '1.5rem', gridTemplateColumns: 'repeat(6, 1fr)' }}>
        <div className="stat-card">
          <div className="stat-label">Total Incidents</div>
          <div className="stat-value">{kpis.total}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--error)' }}>
          <div className="stat-label" style={{ color: 'var(--error)' }}>Active / Open</div>
          <div className="stat-value" style={{ color: 'var(--error)' }}>{kpis.openCount}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--info)' }}>
          <div className="stat-label" style={{ color: 'var(--info)' }}>Contained</div>
          <div className="stat-value" style={{ color: 'var(--info)' }}>{kpis.containedCount}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--success)' }}>
          <div className="stat-label" style={{ color: 'var(--success)' }}>Resolved</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{kpis.resolvedCount}</div>
        </div>
        <div className="stat-card" style={{ borderLeft: '3px solid var(--warning)' }}>
          <div className="stat-label">False Positive</div>
          <div className="stat-value">{kpis.falsePositiveCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Closed</div>
          <div className="stat-value">{kpis.closedCount}</div>
        </div>
      </div>

      {/* Incident Analytics Line Chart */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiTrendingUp size={18} color="var(--primary)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Incident Timeline & Trends ({statusFilter.toUpperCase()})
            </h3>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>Updated in real-time</span>
        </div>
        <div style={{ height: 220, position: 'relative' }}>
          <Line data={chartData} options={chartOptions} />
        </div>
      </div>

      {/* Filter Tabs & Advanced Filters */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem' }}>
        <div style={{ marginBottom: '1rem' }}>
          <FilterTabs tabs={statusTabs} activeTab={statusFilter} onChange={(tab) => { setStatusFilter(tab); setCurrentPage(1); }} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: '0.75rem', alignItems: 'center' }}>
          {/* Search Input */}
          <div style={{ position: 'relative' }}>
            <FiSearch style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-tertiary)' }} />
            <input
              type="text"
              placeholder="Search by ID, title, agent, or details..."
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              style={{
                width: '100%',
                paddingLeft: '2.4rem',
                paddingRight: '0.75rem',
                paddingTop: '0.55rem',
                paddingBottom: '0.55rem',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: '0.875rem',
              }}
            />
          </div>

          {/* Severity Dropdown */}
          <Dropdown
            options={severityOptions}
            value={severityFilter}
            onChange={(val) => { setSeverityFilter(val); setCurrentPage(1); }}
          />

          {/* Agent Dropdown */}
          <Dropdown
            options={agentOptions}
            value={agentFilter}
            onChange={(val) => { setAgentFilter(val); setCurrentPage(1); }}
          />

          {/* Timeframe Dropdown */}
          <Dropdown
            options={timeOptions}
            value={timeFilter}
            onChange={(val) => { setTimeFilter(val); setCurrentPage(1); }}
          />
        </div>
      </div>

      {/* Incidents Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Incident ID</th>
              <th>Title & Telemetry Summary</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Assigned To</th>
              <th>Risk Score</th>
              <th>Created At</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="8" style={{ padding: '1rem' }}>
                  <SkeletonTable rows={5} />
                </td>
              </tr>
            ) : paginatedIncidents.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '1rem' }}>
                  <EmptyState
                    icon="📭"
                    title="Chưa có sự cố"
                    description="Hệ thống đang an toàn. Sự cố sẽ xuất hiện khi có mối đe dọa."
                  />
                </td>
              </tr>
            ) : (
              paginatedIncidents.map((inc) => (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  style={{ cursor: 'pointer', transition: 'background 0.2s' }}
                >
                  <td style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--primary)' }}>
                    {inc.id}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
                        {inc.title}
                      </span>
                      {(inc.title?.includes('MSBuild') || inc.id?.includes('1127')) && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '2px', fontSize: '0.72rem', background: 'rgba(59, 130, 246, 0.1)', padding: '1px 6px', borderRadius: '4px' }}>
                          🎯 <InfoTooltip {...TOOLTIPS["T1127.001"]}>T1127.001</InfoTooltip>
                        </span>
                      )}
                      {(inc.title?.toLowerCase().includes('c2') || inc.title?.toLowerCase().includes('beacon')) && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '2px', fontSize: '0.72rem', background: 'rgba(59, 130, 246, 0.1)', padding: '1px 6px', borderRadius: '4px' }}>
                          🎯 <InfoTooltip {...TOOLTIPS["T1071"]}>T1071</InfoTooltip>
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', gap: '0.75rem', alignItems: 'center', marginTop: '0.2rem' }}>
                      <span>Agent: <strong>{inc.agentId}</strong></span>
                      <span style={{ color: 'var(--error, #ef4444)' }}>
                        <InfoTooltip term="Detection Rules" definition="Có các rule phát hiện hành vi bất thường kích hoạt trên agent.">
                          ⚡ {inc.rules_count || inc.rules?.length || 3} rules triggered
                        </InfoTooltip>
                      </span>
                    </div>
                  </td>
                  <td>{renderSeverityBadge(inc.severity)}</td>
                  <td>{renderStatusBadge(inc.status)}</td>
                  <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {inc.assignedTo !== 'Unassigned' ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--primary)', fontWeight: 600 }}>
                        <FiUser size={13} /> {inc.assignedTo}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>Unassigned</span>
                    )}
                  </td>
                  <td>
                    <InfoTooltip {...TOOLTIPS.RiskScore}>
                      <span
                        style={{
                          fontWeight: 700,
                          fontFamily: 'monospace',
                          color: inc.riskScore >= 80 ? 'var(--error)' : inc.riskScore >= 50 ? 'var(--warning)' : 'var(--success)',
                        }}
                      >
                        {inc.riskScore} / 100
                      </span>
                    </InfoTooltip>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }}>
                    {new Date(inc.createdAt).toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        iconLeft={<FiEye size={13} />}
                        onClick={() => setSelectedIncident(inc)}
                        title="View Details"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        iconLeft={<FiUserPlus size={13} />}
                        onClick={(e) => openAssignModal(inc, e)}
                        title="Assign Analyst"
                      >
                        Assign
                      </Button>
                      {inc.status !== 'contained' && inc.status !== 'resolved' && (
                        <Button
                          variant="danger"
                          size="sm"
                          iconLeft={<FiLock size={13} />}
                          onClick={(e) => onQuickStatusChange(inc.id, 'contained', e)}
                          title="Quick Contain"
                        >
                          Contain
                        </Button>
                      )}
                      {inc.status !== 'resolved' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          iconLeft={<FiCheckCircle size={13} color="var(--success)" />}
                          onClick={(e) => onQuickStatusChange(inc.id, 'resolved', e)}
                          title="Quick Resolve"
                        >
                          Resolve
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination Footer */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.75rem 1rem', borderTop: '1px solid var(--border)' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)' }}>
              Showing {paginatedIncidents.length} of {filteredIncidents.length} incidents (Page {currentPage} of {totalPages})
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <Button variant="ghost" size="sm" disabled={currentPage === 1} onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}>
                Previous
              </Button>
              <Button variant="ghost" size="sm" disabled={currentPage === totalPages} onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}>
                Next
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* 5-Tab Storyboard Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onRefresh={refreshIncidents}
        />
      )}

      {/* Assign Analyst Modal */}
      <Modal
        isOpen={!!assignModalInc}
        onClose={() => setAssignModalInc(null)}
        title="Assign Incident Analyst"
      >
        {assignModalInc && (
          <form onSubmit={submitAssign} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Assign incident <strong>{assignModalInc.id}</strong> ({assignModalInc.title}) to an operator or SOC analyst:
            </p>
            <input
              type="text"
              placeholder="Analyst Name or Operator ID (e.g. Analyst 1, SOC Lead)..."
              value={assigneeInput}
              onChange={(e) => setAssigneeInput(e.target.value)}
              style={{
                width: '100%',
                padding: '0.65rem 0.8rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontSize: '0.9rem',
              }}
              required
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <Button variant="ghost" onClick={() => setAssignModalInc(null)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit" disabled={actionLoading}>
                Confirm Assign
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}
