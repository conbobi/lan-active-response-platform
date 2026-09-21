// src/pages/Groups.jsx
import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import useGroups from '../hooks/useGroups';
import GroupCard from '../components/groups/GroupCard';
import CreateGroupModal from '../components/groups/CreateGroupModal';
import GroupDetailModal from '../components/groups/GroupDetailModal';
import Button from '../components/ui/Button';
import SearchBar from '../components/ui/SearchBar';
import FilterTabs from '../components/ui/FilterTabs';
import KpiCard from '../components/ui/KpiCard';
import {
  FiUsers,
  FiPlus,
  FiServer,
  FiShield,
  FiActivity,
  FiLayers,
  FiRefreshCw,
} from 'react-icons/fi';

const TABS = [
  { value: 'all', label: 'All Groups' },
  { value: 'with_agents', label: 'With Agents' },
  { value: 'empty', label: 'Empty Groups' },
];

export default function Groups() {
  const navigate = useNavigate();
  const {
    groups,
    loading,
    error,
    selectedGroup,
    detailLoading,
    fetchGroups,
    fetchGroupDetail,
    setSelectedGroup,
    createGroup,
    updateGroup,
    deleteGroup,
    addMember,
    removeMember,
  } = useGroups();

  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState(null);
  const [detailModalOpen, setDetailModalOpen] = useState(false);

  // Filter & Search
  const filteredGroups = useMemo(() => {
    return groups.filter((grp) => {
      const matchSearch =
        grp.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        grp.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (grp.description && grp.description.toLowerCase().includes(searchTerm.toLowerCase()));

      let matchTab = true;
      if (activeTab === 'with_agents') {
        matchTab = (grp.member_count ?? 0) > 0;
      } else if (activeTab === 'empty') {
        matchTab = (grp.member_count ?? 0) === 0;
      }

      return matchSearch && matchTab;
    });
  }, [groups, searchTerm, activeTab]);

  // KPI calculations
  const totalGroups = groups.length;
  const totalAgentsGrouped = groups.reduce((acc, g) => acc + (g.member_count || 0), 0);
  const groupsWithAgents = groups.filter((g) => (g.member_count || 0) > 0).length;

  const handleOpenDetail = async (grp) => {
    setDetailModalOpen(true);
    await fetchGroupDetail(grp.id);
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
    if (editId) {
      await updateGroup(editId, payload);
    } else {
      await createGroup(payload);
    }
  };

  const handleDelete = async (grp) => {
    if (!confirm(`Are you sure you want to delete group '${grp.name}' (${grp.id})?`)) {
      return;
    }
    try {
      await deleteGroup(grp.id);
    } catch (err) {
      alert(err.message || 'Failed to delete group');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '2rem' }}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FiUsers className="text-primary" /> Agent Groups
          </h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Gom nhóm máy trạm theo phòng ban / vùng mạng để kiểm soát và phản ứng theo quy mô
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button variant="outline" size="md" onClick={() => fetchGroups()} disabled={loading} title="Refresh groups">
            <FiRefreshCw size={14} className={loading ? 'spin' : ''} />
          </Button>
          <Button variant="primary" size="md" onClick={handleOpenCreate}>
            <FiPlus size={15} style={{ marginRight: '0.35rem' }} /> Create Group
          </Button>
        </div>
      </div>

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
            title="Active Policies"
            value="4 Policies"
            subtitle="Click to configure response policies →"
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
          tabs={TABS.map((t) => {
            let count = totalGroups;
            if (t.value === 'with_agents') count = groupsWithAgents;
            if (t.value === 'empty') count = totalGroups - groupsWithAgents;
            return { ...t, count };
          })}
          active={activeTab}
          onChange={setActiveTab}
        />

        <div style={{ width: '280px' }}>
          <SearchBar
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Search group name, ID..."
          />
        </div>
      </div>

      {/* Error Banner */}
      {error && (
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
          {error}
        </div>
      )}

      {/* Groups Grid */}
      {loading && groups.length === 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1.25rem' }}>
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card skeleton" style={{ height: '220px', borderRadius: 'var(--radius-md)' }} />
          ))}
        </div>
      ) : filteredGroups.length === 0 ? (
        <div
          className="card"
          style={{
            padding: '3.5rem 1rem',
            textAlign: 'center',
            color: 'var(--text-secondary)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <FiUsers size={44} style={{ marginBottom: '0.75rem', opacity: 0.4 }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
            No agent groups found
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)', maxWidth: '400px', margin: '0 auto 1.25rem auto' }}>
            {searchTerm
              ? `No groups matched your query "${searchTerm}". Try resetting search or tab filters.`
              : 'Create groups like HR, IT, Finance or Server to manage batch response actions.'}
          </p>
          <Button variant="primary" size="sm" onClick={handleOpenCreate}>
            <FiPlus size={14} style={{ marginRight: '0.3rem' }} /> Create First Group
          </Button>
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
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {/* Modals */}
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
        detail={selectedGroup}
        loading={detailLoading}
        onAddMember={addMember}
        onRemoveMember={removeMember}
      />
    </div>
  );
}
