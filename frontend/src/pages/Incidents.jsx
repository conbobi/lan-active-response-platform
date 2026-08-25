// src/pages/Incidents.jsx
import React, { useState, useMemo, useEffect } from 'react';
import useIncidents from '../hooks/useIncidents';
import { useAgents } from '../hooks/useAgents';
import { getIncidentNotes } from '../api/incidents';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import FilterTabs from '../components/ui/FilterTabs';
import Dropdown from '../components/ui/Dropdown';
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
  FiGlobe
} from 'react-icons/fi';

export default function Incidents() {
  const {
    incidents,
    loading,
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

  // Incident Notes & Quick Action State within Detail Modal
  const [detailTab, setDetailTab] = useState('overview'); // 'overview', 'notes', 'actions'
  const [incidentNotes, setIncidentNotes] = useState([]);
  const [loadingNotes, setLoadingNotes] = useState(false);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [quickActionPID, setQuickActionPID] = useState('');
  const [quickActionIP, setQuickActionIP] = useState('');
  const [actionSuccessMsg, setActionSuccessMsg] = useState('');

  // Load Notes when selectedIncident opens or changes
  useEffect(() => {
    if (selectedIncident) {
      setLoadingNotes(true);
      setActionSuccessMsg('');
      getIncidentNotes(selectedIncident.id)
        .then((notes) => setIncidentNotes(notes))

        .catch(() => setIncidentNotes([]))
        .finally(() => setLoadingNotes(false));
    }
  }, [selectedIncident]);

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
    await handleAssign(assignModalInc.id, assigneeInput.trim());
    setAssignModalInc(null);
  };

  const onQuickStatusChange = async (incId, newStatus, e) => {
    if (e) e.stopPropagation();
    await handleUpdateStatus(incId, newStatus);
    if (selectedIncident && selectedIncident.id === incId) {
      setSelectedIncident((prev) => (prev ? { ...prev, status: newStatus } : null));
    }
  };

  const onAddNoteSubmit = async (e) => {
    e.preventDefault();
    if (!selectedIncident || !newNoteContent.trim()) return;
    try {
      await handleAddNote(selectedIncident.id, newNoteContent.trim(), 'SOC Analyst');
      setNewNoteContent('');
      const updatedNotes = await getIncidentNotes(selectedIncident.id);
      setIncidentNotes(updatedNotes);
    } catch (err) {
      console.error(err);
    }
  };

  const onRunAction = async (actionType, params = {}) => {
    if (!selectedIncident) return;
    try {
      const res = await handleExecuteAction(selectedIncident.id, actionType, params, 'SOC Lead');
      setActionSuccessMsg(res.message || `Action ${actionType} executed successfully.`);
      const updatedNotes = await getIncidentNotes(selectedIncident.id);
      setIncidentNotes(updatedNotes);
    } catch (err) {
      setActionSuccessMsg(`Action failed: ${err.message || 'Execution error'}`);
    }
  };

  const renderStatusBadge = (status) => {
    switch (status) {
      case 'open':
        return <Badge status="danger" label="Open" />;
      case 'investigating':
        return <Badge status="warning" label="Investigating" />;
      case 'contained':
        return <Badge status="info" label="Contained" />;
      case 'resolved':
        return <Badge status="success" label="Resolved" />;
      case 'false_positive':
        return <Badge status="neutral" label="False Positive" />;
      case 'closed':
        return <Badge status="neutral" label="Closed" />;
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
                <td colSpan="8" style={{ textAlign: 'center', padding: '2rem' }}>
                  <div className="skeleton" style={{ height: '120px' }} />
                </td>
              </tr>
            ) : paginatedIncidents.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-tertiary)' }}>
                  No security incidents match the selected filter criteria.
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
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
                      {inc.title}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', gap: '0.5rem', marginTop: '0.2rem' }}>
                      <span>Agent: <strong>{inc.agentId}</strong></span>
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
                    <span
                      style={{
                        fontWeight: 700,
                        fontFamily: 'monospace',
                        color: inc.riskScore >= 80 ? 'var(--error)' : inc.riskScore >= 50 ? 'var(--warning)' : 'var(--success)',
                      }}
                    >
                      {inc.riskScore} / 100
                    </span>
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

      {/* Comprehensive Incident Detail & SOC Action Modal */}
      <Modal
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        title={selectedIncident ? `Incident Investigation: ${selectedIncident.id}` : ''}
      >
        {selectedIncident && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', width: '100%', maxWidth: 780 }}>
            {/* Modal Sub-Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', background: 'var(--bg-secondary)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.3rem' }}>
                  {selectedIncident.title}
                </h3>
                <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.82rem', color: 'var(--text-tertiary)' }}>
                  <span>Agent ID: <strong style={{ color: 'var(--primary)' }}>{selectedIncident.agentId}</strong></span>
                  <span>Assigned: <strong>{selectedIncident.assignedTo}</strong></span>
                  <span>Created: <strong>{new Date(selectedIncident.createdAt).toLocaleString()}</strong></span>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                {renderSeverityBadge(selectedIncident.severity)}
                {renderStatusBadge(selectedIncident.status)}
              </div>
            </div>

            {/* Modal Tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', gap: '1rem' }}>
              <button
                onClick={() => setDetailTab('overview')}
                style={{
                  padding: '0.5rem 0.85rem',
                  background: 'none',
                  border: 'none',
                  borderBottom: detailTab === 'overview' ? '2px solid var(--primary)' : 'none',
                  color: detailTab === 'overview' ? 'var(--primary)' : 'var(--text-secondary)',
                  fontWeight: detailTab === 'overview' ? 700 : 500,
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                <FiFileText size={14} /> Overview & Telemetry
              </button>
              <button
                onClick={() => setDetailTab('notes')}
                style={{
                  padding: '0.5rem 0.85rem',
                  background: 'none',
                  border: 'none',
                  borderBottom: detailTab === 'notes' ? '2px solid var(--primary)' : 'none',
                  color: detailTab === 'notes' ? 'var(--primary)' : 'var(--text-secondary)',
                  fontWeight: detailTab === 'notes' ? 700 : 500,
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                <FiActivity size={14} /> Audit Trail & Notes ({incidentNotes.length})
              </button>
              <button
                onClick={() => setDetailTab('actions')}
                style={{
                  padding: '0.5rem 0.85rem',
                  background: 'none',
                  border: 'none',
                  borderBottom: detailTab === 'actions' ? '2px solid var(--primary)' : 'none',
                  color: detailTab === 'actions' ? 'var(--primary)' : 'var(--text-secondary)',
                  fontWeight: detailTab === 'actions' ? 700 : 500,
                  cursor: 'pointer',
                  fontSize: '0.875rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                <FiShield size={14} color="var(--error)" /> Quick Mitigation Response
              </button>
            </div>

            {/* TAB 1: OVERVIEW */}
            {detailTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '0.4rem' }}>
                    Detailed Incident Description
                  </h4>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', background: 'var(--bg-secondary)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', whiteSpace: 'pre-wrap' }}>
                    {selectedIncident.description}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>Risk Score Assessment</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, color: selectedIncident.riskScore >= 80 ? 'var(--error)' : 'var(--primary)', marginTop: '0.2rem' }}>
                      {selectedIncident.riskScore} / 100
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-secondary)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>Target Host Agent</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--primary)', marginTop: '0.2rem' }}>
                      {selectedIncident.agentId}
                    </div>
                  </div>
                </div>

                {/* Status Transition Quick Bar */}
                <div style={{ marginTop: '0.5rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-tertiary)', marginBottom: '0.5rem' }}>
                    Change Incident Lifecycle Status:
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <Button variant={selectedIncident.status === 'contained' ? 'primary' : 'outline'} size="sm" onClick={() => onQuickStatusChange(selectedIncident.id, 'contained')}>
                      Mark Contained
                    </Button>
                    <Button variant={selectedIncident.status === 'resolved' ? 'primary' : 'outline'} size="sm" onClick={() => onQuickStatusChange(selectedIncident.id, 'resolved')}>
                      Mark Resolved
                    </Button>
                    <Button variant={selectedIncident.status === 'false_positive' ? 'primary' : 'outline'} size="sm" onClick={() => onQuickStatusChange(selectedIncident.id, 'false_positive')}>
                      Mark False Positive
                    </Button>
                    <Button variant={selectedIncident.status === 'closed' ? 'primary' : 'outline'} size="sm" onClick={() => onQuickStatusChange(selectedIncident.id, 'closed')}>
                      Close Incident
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: AUDIT TRAIL & NOTES */}
            {detailTab === 'notes' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.6rem', paddingRight: '0.3rem' }}>
                  {loadingNotes ? (
                    <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>Loading audit trail...</div>
                  ) : incidentNotes.length === 0 ? (
                    <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
                      No analyst notes or audit logs recorded yet.
                    </div>
                  ) : (
                    incidentNotes.map((note) => (
                      <div
                        key={note.id || Math.random()}
                        style={{
                          padding: '0.65rem 0.85rem',
                          background: 'var(--bg-secondary)',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border)',
                          fontSize: '0.85rem',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                          <span style={{ fontWeight: 700, color: 'var(--primary)' }}>[{note.user || 'system'}]</span>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                            {note.created_at ? new Date(note.created_at).toLocaleString() : ''}
                          </span>
                        </div>
                        <div style={{ color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>{note.content}</div>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form onSubmit={onAddNoteSubmit} style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                  <input
                    type="text"
                    placeholder="Type an analyst note or investigation log comment..."
                    value={newNoteContent}
                    onChange={(e) => setNewNoteContent(e.target.value)}
                    style={{
                      flex: 1,
                      padding: '0.55rem 0.8rem',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontSize: '0.875rem',
                    }}
                  />
                  <Button type="submit" variant="primary" iconLeft={<FiSend size={14} />}>
                    Add Note
                  </Button>
                </form>
              </div>
            )}

            {/* TAB 3: QUICK MITIGATION RESPONSE */}
            {detailTab === 'actions' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {actionSuccessMsg && (
                  <div style={{ padding: '0.6rem 0.85rem', background: 'rgba(34,197,94,0.1)', border: '1px solid var(--success)', borderRadius: 'var(--radius-sm)', color: 'var(--success)', fontSize: '0.85rem' }}>
                    {actionSuccessMsg}
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  {/* Action 1: Isolate Agent */}
                  <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <div>
                      <h4 style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.3rem' }}>
                        <FiLock size={16} /> Isolate Host Network
                      </h4>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
                        Immediately isolate agent <strong>{selectedIncident.agentId}</strong> from network communications to prevent lateral movement.
                      </p>
                    </div>
                    <Button variant="danger" size="sm" style={{ marginTop: '0.75rem' }} disabled={actionLoading} onClick={() => onRunAction('isolate')}>
                      Isolate Host ({selectedIncident.agentId})
                    </Button>
                  </div>

                  {/* Action 2: Kill Process Tree */}
                  <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <div>
                      <h4 style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.3rem' }}>
                        <FiLayers size={16} /> Terminate Process Tree
                      </h4>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', marginBottom: '0.5rem' }}>
                        Dispatch kill_process_tree command to recursively kill malicious process and its children.
                      </p>
                      <input
                        type="number"
                        placeholder="Enter Target PID (e.g. 4444)..."
                        value={quickActionPID}
                        onChange={(e) => setQuickActionPID(e.target.value)}
                        style={{
                          width: '100%',
                          padding: '0.45rem 0.6rem',
                          background: 'var(--bg-primary)',
                          border: '1px solid var(--border)',
                          borderRadius: 'var(--radius-sm)',
                          color: 'var(--text-primary)',
                          fontSize: '0.8rem',
                        }}
                      />
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      style={{ marginTop: '0.75rem' }}
                      disabled={actionLoading || !quickActionPID}
                      onClick={() => onRunAction('kill_process_tree', { pid: quickActionPID })}
                    >
                      Kill Process Tree (PID {quickActionPID || '...'})
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

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
