// src/pages/Incidents.jsx
import React, { useState, useMemo } from 'react';
import useIncidents from '../hooks/useIncidents';
import Badge from '../components/ui/Badge';
import FilterTabs from '../components/ui/FilterTabs';
import SearchBar from '../components/ui/SearchBar';
import Pagination from '../components/ui/Pagination';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import { FiAlertTriangle, FiCheckCircle, FiUserCheck, FiEye, FiClock } from 'react-icons/fi';

const PAGE_SIZE = 8;

const STATUS_TABS = [
  { value: 'all', label: 'All' },
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'resolved', label: 'Resolved' },
];

export default function Incidents() {
  const { incidents, loading, handleAssign, handleResolve, refreshIncidents } = useIncidents();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [assignModalIncident, setAssignModalIncident] = useState(null);
  const [assigneeInput, setAssigneeInput] = useState('');

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchStatus = statusFilter === 'all' || inc.status === statusFilter;
      const matchSearch =
        !search ||
        inc.id.toLowerCase().includes(search.toLowerCase()) ||
        inc.title.toLowerCase().includes(search.toLowerCase()) ||
        inc.agentId.toLowerCase().includes(search.toLowerCase()) ||
        inc.description.toLowerCase().includes(search.toLowerCase());
      return matchStatus && matchSearch;
    });
  }, [incidents, search, statusFilter]);

  const totalPages = Math.ceil(filteredIncidents.length / PAGE_SIZE) || 1;
  const paginated = filteredIncidents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const tabsWithCount = STATUS_TABS.map((t) => ({
    ...t,
    count: t.value === 'all' ? incidents.length : incidents.filter((i) => i.status === t.value).length,
  }));

  const openCount = incidents.filter((i) => i.status === 'open').length;
  const inProgressCount = incidents.filter((i) => i.status === 'in_progress').length;
  const resolvedCount = incidents.filter((i) => i.status === 'resolved').length;

  const onAssignSubmit = async (e) => {
    e.preventDefault();
    if (!assignModalIncident || !assigneeInput.trim()) return;
    await handleAssign(assignModalIncident.id, assigneeInput.trim());
    setAssignModalIncident(null);
    setAssigneeInput('');
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Incidents Management</h1>
        </div>
        <div className="card skeleton" style={{ height: '400px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Incidents Management</h1>
          <p className="page-subtitle">Track, assign, and resolve active security incidents across agents</p>
        </div>
        <Button variant="outline" iconLeft={<FiClock size={15} />} onClick={refreshIncidents}>
          Refresh
        </Button>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Total Incidents</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
            {incidents.length}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Open</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--error)', marginTop: '0.2rem' }}>
            {openCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>In Progress</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--warning)', marginTop: '0.2rem' }}>
            {inProgressCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Resolved</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--success)', marginTop: '0.2rem' }}>
            {resolvedCount}
          </div>
        </div>
      </div>

      {/* Main Table Card */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <FilterTabs tabs={tabsWithCount} active={statusFilter} onChange={(v) => { setStatusFilter(v); setPage(1); }} />
          <div style={{ marginLeft: 'auto' }}>
            <SearchBar value={search} onChange={(v) => { setSearch(v); setPage(1); }} placeholder="Search incidents..." style={{ width: 240 }} />
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.85rem 1.25rem' }}>Incident ID</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Title & Agent</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Severity</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Status</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Assigned To</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Created At</th>
                <th style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No incidents match criteria
                  </td>
                </tr>
              ) : (
                paginated.map((inc) => (
                  <tr key={inc.id} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s ease' }}>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600, color: 'var(--primary)' }}>
                      {inc.id}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inc.title}</div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)' }}>Agent: {inc.agentId}</div>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <Badge status={inc.severity.toLowerCase()} label={inc.severity} />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <Badge
                        status={inc.status === 'open' ? 'critical' : inc.status === 'in_progress' ? 'warning' : 'online'}
                        label={inc.status.replace('_', ' ').toUpperCase()}
                      />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-secondary)' }}>
                      {inc.assignedTo}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                      {new Date(inc.createdAt).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                        <Button variant="ghost" size="sm" iconLeft={<FiEye size={14} />} onClick={() => setSelectedIncident(inc)}>
                          View
                        </Button>
                        {inc.status !== 'resolved' && (
                          <>
                            <Button variant="outline" size="sm" iconLeft={<FiUserCheck size={14} />} onClick={() => { setAssignModalIncident(inc); setAssigneeInput(inc.assignedTo !== 'Unassigned' ? inc.assignedTo : ''); }}>
                              Assign
                            </Button>
                            <Button variant="success" size="sm" iconLeft={<FiCheckCircle size={14} />} onClick={() => handleResolve(inc.id)}>
                              Resolve
                            </Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div style={{ padding: '1rem 1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Showing {Math.min((page - 1) * PAGE_SIZE + 1, filteredIncidents.length)}–{Math.min(page * PAGE_SIZE, filteredIncidents.length)} of {filteredIncidents.length}
          </span>
          <Pagination current={page} total={totalPages} onChange={setPage} />
        </div>
      </div>

      {/* View Detail Modal */}
      <Modal isOpen={!!selectedIncident} onClose={() => setSelectedIncident(null)} title="Incident Detail">
        {selectedIncident && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {[
              ['Incident ID', selectedIncident.id],
              ['Title', selectedIncident.title],
              ['Description', selectedIncident.description],
              ['Agent ID', selectedIncident.agentId],
              ['Severity', selectedIncident.severity],
              ['Status', selectedIncident.status],
              ['Assigned To', selectedIncident.assignedTo],
              ['Created At', new Date(selectedIncident.createdAt).toLocaleString()],
              ['Updated At', new Date(selectedIncident.updatedAt).toLocaleString()],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{k}</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)', maxWidth: '60%', textAlign: 'right' }}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </Modal>

      {/* Assign Modal */}
      <Modal isOpen={!!assignModalIncident} onClose={() => setAssignModalIncident(null)} title="Assign Incident">
        {assignModalIncident && (
          <form onSubmit={onAssignSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                Assigning <strong>{assignModalIncident.id}</strong>: {assignModalIncident.title}
              </p>
              <input
                type="text"
                placeholder="Enter Analyst Name or ID..."
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
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <Button variant="ghost" onClick={() => setAssignModalIncident(null)}>
                Cancel
              </Button>
              <Button variant="primary" type="submit">
                Confirm Assign
              </Button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
}
