import React, { useState, useMemo, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAgents } from '../hooks/useAgents';
import useGroups from '../hooks/useGroups';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import GroupCard from '../components/groups/GroupCard';
import CreateGroupModal from '../components/groups/CreateGroupModal';
import GroupDetailModal from '../components/groups/GroupDetailModal';
import Badge from '../components/ui/Badge';
import SearchBar from '../components/ui/SearchBar';
import Dropdown from '../components/ui/Dropdown';
import Pagination from '../components/ui/Pagination';
import Button from '../components/ui/Button';
import KpiCard from '../components/ui/KpiCard';
import FilterTabs from '../components/ui/FilterTabs';
import ErrorState from '../components/ui/ErrorState';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonTable, SkeletonCard } from '../components/ui/Skeleton';
import {
  FiEye,
  FiLock,
  FiUnlock,
  FiCpu,
  FiRefreshCw,
  FiUsers,
  FiServer,
  FiShield,
  FiLayers,
  FiPlus,
  FiCornerDownRight,
} from 'react-icons/fi';

const ITEMS_PER_PAGE = 8;

const STATUS_OPTS = [
  { value: 'all', label: 'All Status' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'isolated', label: 'Isolated' },
];

const GROUP_TABS = [
  { value: 'all', label: 'All Groups' },
  { value: 'with_agents', label: 'With Agents' },
  { value: 'empty', label: 'Empty Groups' },
];

export default function Agents({ initialTab }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const queryTab = searchParams.get('tab') || initialTab || 'inventory';
  const [activeMainTab, setActiveMainTab] = useState(queryTab);

  // Sync with URL params
  useEffect(() => {
    if (queryTab && queryTab !== activeMainTab) {
      setActiveMainTab(queryTab);
    }
  }, [queryTab]);

  const switchTab = (tab) => {
    setActiveMainTab(tab);
    setSearchParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('tab', tab);
      return p;
    });
  };

  // Agents logic
  const { agents, loading: agentsLoading, handleIsolate, handleUnisolate, refreshAgents } = useAgents();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedAgent, setSelectedAgent] = useState(null);

  // Groups logic
  const {
    groups,
    loading: groupsLoading,
    error: groupsError,
    selectedGroup,
    fetchGroups,
    fetchGroupDetail,
    setSelectedGroup,
    createGroup,
    updateGroup,
    deleteGroup,
  } = useGroups();

  const [groupSearch, setGroupSearch] = useState('');
  const [groupFilterTab, setGroupFilterTab] = useState('all');
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState(null);
  const [detailModalOpen, setDetailModalOpen] = useState(false);

  // Filter Agents
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

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter]);

  // Filter Groups
  const filteredGroups = useMemo(() => {
    return groups.filter((grp) => {
      const matchSearch =
        grp.name.toLowerCase().includes(groupSearch.toLowerCase()) ||
        grp.id.toLowerCase().includes(groupSearch.toLowerCase()) ||
        (grp.description && grp.description.toLowerCase().includes(groupSearch.toLowerCase()));

      let matchTab = true;
      if (groupFilterTab === 'with_agents') {
        matchTab = (grp.member_count ?? 0) > 0;
      } else if (groupFilterTab === 'empty') {
        matchTab = (grp.member_count ?? 0) === 0;
      }
      return matchSearch && matchTab;
    });
  }, [groups, groupSearch, groupFilterTab]);

  const totalGroups = groups.length;
  const totalAgentsGrouped = groups.reduce((acc, g) => acc + (g.member_count || 0), 0);
  const groupsWithAgents = groups.filter((g) => (g.member_count || 0) > 0).length;

  const handleOpenDetail = (grp) => {
    setSelectedGroup(grp);
    setDetailModalOpen(true);
    fetchGroupDetail(grp.id);
  };

  const handleOpenEdit = (grp) => {
    setEditingGroup(grp);
    setCreateModalOpen(true);
  };

  const handleOpenCreate = () => {
    setEditingGroup(null);
    setCreateModalOpen(true);
  };

  const handleSaveGroup = async (payload, editId) => {
    try {
      if (editId) {
        await updateGroup(editId, payload);
        toast.success(`Đã cập nhật nhóm ${payload.name || ''}`);
      } else {
        await createGroup(payload);
        toast.success(`Đã tạo nhóm ${payload.name || ''}`);
      }
    } catch (err) {
      toast.error(`Lỗi khi lưu nhóm: ${err.message}`);
      throw err;
    }
  };

  const handleDeleteGroup = async (grp) => {
    if (!confirm(`Are you sure you want to delete group '${grp.name}' (${grp.id})?`)) {
      return;
    }
    try {
      await deleteGroup(grp.id);
      toast.success(`Đã xóa nhóm ${grp.name}`);
    } catch (err) {
      toast.error(`Xóa nhóm thất bại: ${err.message}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', paddingBottom: '2rem' }}>
      {/* Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FiServer className="text-primary" /> Endpoints & Host Inventory
          </h1>
          <p className="page-subtitle">
            Centralized endpoint lifecycle, host grouping, network isolation, and process telemetry
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button
            variant="outline"
            iconLeft={<FiRefreshCw size={14} className={agentsLoading || groupsLoading ? 'spin' : ''} />}
            onClick={() => {
              refreshAgents();
              fetchGroups();
            }}
          >
            Refresh
          </Button>
          {activeMainTab === 'groups' && (
            <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={handleOpenCreate}>
              Create Group
            </Button>
          )}
        </div>
      </div>

      {/* Main Tabs: Inventory vs Groups */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
        <button
          type="button"
          onClick={() => switchTab('inventory')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.55rem 1.1rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: 'none',
            background: activeMainTab === 'inventory' ? 'var(--primary)' : 'transparent',
            color: activeMainTab === 'inventory' ? '#fff' : 'var(--text-secondary)',
            transition: 'all 0.15s ease',
          }}
        >
          <FiCpu size={15} />
          Endpoints Inventory
          <span style={{
            padding: '0.1rem 0.45rem',
            borderRadius: '999px',
            fontSize: '0.75rem',
            background: activeMainTab === 'inventory' ? 'rgba(255,255,255,0.2)' : 'var(--bg-secondary)',
            color: activeMainTab === 'inventory' ? '#fff' : 'var(--text-tertiary)',
          }}>
            {agents.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => switchTab('groups')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.55rem 1.1rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: 'none',
            background: activeMainTab === 'groups' ? 'var(--primary)' : 'transparent',
            color: activeMainTab === 'groups' ? '#fff' : 'var(--text-secondary)',
            transition: 'all 0.15s ease',
          }}
        >
          <FiUsers size={15} />
          Host Groups
          <span style={{
            padding: '0.1rem 0.45rem',
            borderRadius: '999px',
            fontSize: '0.75rem',
            background: activeMainTab === 'groups' ? 'rgba(255,255,255,0.2)' : 'var(--bg-secondary)',
            color: activeMainTab === 'groups' ? '#fff' : 'var(--text-tertiary)',
          }}>
            {groups.length}
          </span>
        </button>
      </div>

      {activeMainTab === 'inventory' ? (
        /* Endpoints Table */
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
              <FiServer size={16} color="var(--primary)" />
              <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Active Endpoints</span>
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

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Hostname</th>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>CPU / RAM</th>
                  <th>Isolation</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {agentsLoading ? (
                  <tr>
                    <td colSpan="7" style={{ padding: '1rem' }}>
                      <SkeletonTable rows={5} />
                    </td>
                  </tr>
                ) : filteredAgents.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ textAlign: 'center', padding: '2rem' }}>
                      <EmptyState
                        icon="💻"
                        title="Không có agent phù hợp"
                        description="Không tìm thấy agent nào với tiêu chí tìm kiếm hiện tại."
                      />
                    </td>
                  </tr>
                ) : (
                  paginatedAgents.map((agent) => (
                    <tr key={agent.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedAgent(agent)}>
                      <td>
                        <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--primary)' }}>
                          {agent.id}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                          {agent.hostname || '—'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {agent.ip_address || agent.ip || '—'}
                      </td>
                      <td>
                        <Badge
                          variant={
                            agent.status === 'online'
                              ? 'success'
                              : agent.status === 'isolated'
                              ? 'error'
                              : 'neutral'
                          }
                        >
                          {(agent.status || 'OFFLINE').toUpperCase()}
                        </Badge>
                      </td>
                      <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {agent.cpu != null ? `${Math.round(agent.cpu)}%` : '—'} /{' '}
                        {agent.ram != null ? `${Math.round(agent.ram)}%` : '—'}
                      </td>
                      <td>
                        {agent.is_isolated ? (
                          <span style={{ color: 'var(--error)', fontWeight: 600, fontSize: '0.8rem' }}>Isolated</span>
                        ) : (
                          <span style={{ color: 'var(--success)', fontWeight: 600, fontSize: '0.8rem' }}>Online</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.4rem' }}>
                          <Button
                            variant="ghost"
                            size="sm"
                            iconLeft={<FiEye size={13} />}
                            onClick={() => setSelectedAgent(agent)}
                            title="View Details"
                          >
                            Details
                          </Button>

                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              navigate(`/investigate?tab=process&agent=${encodeURIComponent(agent.id)}`);
                            }}
                            title="Open Process Tree for this Endpoint"
                          >
                            🌳 Tree
                          </Button>

                          {agent.status !== 'isolated' ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              iconLeft={<FiLock size={13} color="var(--error)" />}
                              onClick={async () => {
                                if (window.confirm(`Isolate endpoint ${agent.hostname || agent.id} immediately?`)) {
                                  await handleIsolate(agent.id);
                                }
                              }}
                              title="Isolate Host"
                            >
                              Isolate
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              iconLeft={<FiUnlock size={13} color="var(--success)" />}
                              onClick={async () => {
                                if (window.confirm(`Restore network access for ${agent.hostname || agent.id}?`)) {
                                  await handleUnisolate(agent.id);
                                }
                              }}
                              title="Unisolate Host"
                            >
                              Unisolate
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
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
          )}
        </div>
      ) : (
        /* Host Groups Management */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* KPI Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
            <KpiCard
              title="Total Groups"
              value={totalGroups}
              subtitle="Department & Network zones"
              icon={<FiLayers size={20} color="var(--primary)" />}
            />
            <KpiCard
              title="Total Agents Grouped"
              value={totalAgentsGrouped}
              subtitle="Assigned to at least 1 group"
              icon={<FiUsers size={20} color="var(--info)" />}
            />
            <KpiCard
              title="Active Groups"
              value={groupsWithAgents}
              subtitle="Groups with active agents"
              icon={<FiServer size={20} color="var(--success)" />}
            />
            <div
              onClick={() => navigate('/policies')}
              style={{ cursor: 'pointer' }}
              title="Click to view Response Policies"
            >
              <KpiCard
                title="Response Policies"
                value="Configured"
                subtitle="Manage automated response rules →"
                icon={<FiShield size={20} color="var(--warning)" />}
              />
            </div>
          </div>

          {/* Filter Tabs & Search */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}
          >
            <FilterTabs
              tabs={GROUP_TABS.map((t) => {
                let count = totalGroups;
                if (t.value === 'with_agents') count = groupsWithAgents;
                if (t.value === 'empty') count = totalGroups - groupsWithAgents;
                return { ...t, count };
              })}
              active={groupFilterTab}
              onChange={setGroupFilterTab}
            />

            <div style={{ width: '280px' }}>
              <SearchBar
                value={groupSearch}
                onChange={setGroupSearch}
                placeholder="Search group name, ID..."
              />
            </div>
          </div>

          {/* Error Banner */}
          {groupsError && (
            <div
              style={{
                padding: '0.75rem 1rem',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--error)',
                color: 'var(--error)',
                fontSize: '0.85rem',
              }}
            >
              {groupsError}
            </div>
          )}

          {/* Groups Grid */}
          {groupsLoading && groups.length === 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1.25rem' }}>
              {[1, 2, 3, 4].map((i) => (
                <SkeletonCard key={i} />
              ))}
            </div>
          ) : filteredGroups.length === 0 ? (
            <div className="card" style={{ padding: '2rem 1rem' }}>
              <EmptyState
                icon="👥"
                title="Chưa có nhóm nào"
                description="Tạo nhóm để quản lý agents theo phòng ban hoặc vùng mạng."
                actionLabel="Tạo nhóm"
                onAction={handleOpenCreate}
              />
            </div>
          ) : (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(310px, 1fr))',
                gap: '1.25rem',
              }}
            >
              {filteredGroups.map((grp) => (
                <GroupCard
                  key={grp.id}
                  group={grp}
                  onClick={() => handleOpenDetail(grp)}
                  onManageMembers={() => handleOpenDetail(grp)}
                  onEdit={handleOpenEdit}
                  onDelete={handleDeleteGroup}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Modals */}
      {selectedAgent && (
        <AgentDetailModal agent={selectedAgent} onClose={() => setSelectedAgent(null)} />
      )}

      <CreateGroupModal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        onCreated={handleSaveGroup}
        editGroup={editingGroup}
      />

      <GroupDetailModal
        isOpen={detailModalOpen}
        onClose={() => setDetailModalOpen(false)}
        group={selectedGroup}
        onRefresh={fetchGroups}
      />
    </div>
  );
}