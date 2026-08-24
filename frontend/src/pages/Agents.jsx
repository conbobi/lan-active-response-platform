import React, { useState, useMemo, useEffect } from 'react';
import { useAgents } from '../hooks/useAgents';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import Badge from '../components/ui/Badge';
import SearchBar from '../components/ui/SearchBar';
import Dropdown from '../components/ui/Dropdown';
import Pagination from '../components/ui/Pagination';
import Button from '../components/ui/Button';
import { FiEye, FiLock, FiUnlock, FiCpu, FiRefreshCw } from 'react-icons/fi';

const ITEMS_PER_PAGE = 8;

const STATUS_OPTS = [
  { value: 'all', label: 'All Status' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'isolated', label: 'Isolated' },
];

export default function Agents() {
  const { agents, loading, handleIsolate, handleUnisolate, refreshAgents } = useAgents();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [blockIpInput, setBlockIpInput] = useState({});

  // Lọc và tìm kiếm
  const filteredAgents = useMemo(() => {
    return agents.filter((agent) => {
      const matchSearch =
        (agent.hostname && agent.hostname.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (agent.ip && agent.ip.includes(searchTerm)) ||
        (agent.ip_address && agent.ip_address.includes(searchTerm)) ||
        (agent.id && agent.id.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchStatus = statusFilter === 'all' || agent.status === statusFilter;
      return matchSearch && matchStatus;
    });
  }, [agents, searchTerm, statusFilter]);

  const totalPages = Math.ceil(filteredAgents.length / ITEMS_PER_PAGE) || 1;
  const paginatedAgents = filteredAgents.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  // Reset trang về 1 khi thay đổi filter/search
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter]);

  const handleBlockIp = async (agentId) => {
    const ip = blockIpInput[agentId] || '';
    if (!ip) {
      alert('Please enter an IP address.');
      return;
    }
    // TODO: Gọi API block IP tương ứng (nếu có)
    alert(`Blocking IP ${ip} on agent ${agentId}`);
    setBlockIpInput({ ...blockIpInput, [agentId]: '' });
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div className="page-header">
          <h1 className="page-title">Agents</h1>
        </div>
        <div className="card skeleton" style={{ height: '300px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Agents Management</h1>
          <p className="page-subtitle">Monitor and control system agents</p>
        </div>
        <Button variant="outline" iconLeft={<FiRefreshCw size={15} />} onClick={refreshAgents}>
          Refresh
        </Button>
      </div>

      {/* Thanh công cụ */}
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
            <FiCpu size={16} color="var(--primary)" />
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>All Agents</span>
            <span className="badge badge-info">{filteredAgents.length}</span>
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
          </div>
        </div>

        {/* Bảng danh sách */}
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>CPU</th>
                <th>RAM</th>
                <th>Firewall</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAgents.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No agents found
                  </td>
                </tr>
              ) : (
                paginatedAgents.map((agent) => (
                  <tr key={agent.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {agent.id}
                    </td>
                    <td style={{ fontWeight: 600 }}>{agent.hostname}</td>
                    <td>{agent.ip}</td>
                    <td>
                      <Badge status={agent.status} />
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', minWidth: 80 }}>
                        <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                          <div
                            style={{
                              height: '100%',
                              width: `${agent.cpu}%`,
                              background:
                                agent.cpu > 80
                                  ? 'var(--error)'
                                  : agent.cpu > 60
                                    ? 'var(--warning)'
                                    : 'var(--success)',
                              borderRadius: 99,
                            }}
                          />
                        </div>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{agent.cpu}%</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', minWidth: 80 }}>
                        <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                          <div
                            style={{
                              height: '100%',
                              width: `${agent.ram}%`,
                              background:
                                agent.ram > 80
                                  ? 'var(--error)'
                                  : agent.ram > 60
                                    ? 'var(--warning)'
                                    : 'var(--primary)',
                              borderRadius: 99,
                            }}
                          />
                        </div>
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{agent.ram}%</span>
                      </div>
                    </td>
                    <td>
                      {agent.firewall ? (
                        <span style={{ color: 'var(--success)', fontWeight: 600, fontSize: '0.8rem' }}>Active</span>
                      ) : (
                        <span style={{ color: 'var(--error)', fontSize: '0.8rem' }}>Off</span>
                      )}
                    </td>
                    <td>
                      <div className="table-actions" style={{ flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                        <button className="action-btn" onClick={() => setSelectedAgent(agent)} title="View Details">
                          <FiEye size={13} />
                        </button>

                        {agent.status !== 'isolated' ? (
                          <button className="action-btn" onClick={() => handleIsolate(agent.id)} title="Isolate Agent">
                            <FiLock size={13} />
                          </button>
                        ) : (
                          <button className="action-btn" onClick={() => handleUnisolate(agent.id)} title="Release Agent">
                            <FiUnlock size={13} />
                          </button>
                        )}

                        {/* Block IP input & button (nếu cần) */}
                        {/*
                        <div style={{ display: 'flex', alignItems: 'center', gap: '2px', marginLeft: '4px' }}>
                          <input
                            type="text"
                            placeholder="IP to block"
                            value={blockIpInput[agent.id] || ''}
                            onChange={(e) => setBlockIpInput({ ...blockIpInput, [agent.id]: e.target.value })}
                            style={{
                              width: '90px',
                              padding: '3px 8px',
                              background: 'var(--bg)',
                              border: '1px solid var(--border)',
                              borderRadius: 'var(--radius-sm)',
                              color: 'var(--text-primary)',
                              fontSize: '0.75rem',
                              outline: 'none',
                            }}
                          />
                          <button className="action-btn danger" onClick={() => handleBlockIp(agent.id)} title="Block IP">
                            <FiSlash size={13} />
                          </button>
                        </div>
                        */}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Phân trang */}
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

      {/* Modal chi tiết */}
      {selectedAgent && <AgentDetailModal agent={selectedAgent} onClose={() => setSelectedAgent(null)} />}
    </div>
  );
}