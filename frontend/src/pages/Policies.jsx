// src/pages/Policies.jsx
import React, { useState, useEffect, useMemo } from 'react';
import usePolicies from '../hooks/usePolicies';
import { listGroups } from '../api/groups';
import PolicyTable from '../components/policies/PolicyTable';
import PolicyFormModal from '../components/policies/PolicyFormModal';
import PolicyDryRunPanel from '../components/policies/PolicyDryRunPanel';
import Button from '../components/ui/Button';
import SearchBar from '../components/ui/SearchBar';
import FilterTabs from '../components/ui/FilterTabs';
import KpiCard from '../components/ui/KpiCard';
import {
  FiShield,
  FiPlus,
  FiCheckCircle,
  FiUsers,
  FiPercent,
  FiRefreshCw,
  FiSliders,
  FiPlay,
  FiAlertCircle,
} from 'react-icons/fi';

const TABS = [
  { value: 'all', label: 'All Policies' },
  { value: 'active', label: 'Active' },
  { value: 'inactive', label: 'Inactive' },
  { value: 'agent', label: 'Agent Scope' },
  { value: 'group', label: 'Group Scope' },
];

export default function Policies() {
  const {
    policies,
    loading,
    error,
    fetchPolicies,
    createPolicy,
    updatePolicy,
    deletePolicy,
    toggleActive,
  } = usePolicies();

  const [groups, setGroups] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('all');

  // Modals
  const [formModalOpen, setFormModalOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [testingPolicy, setTestingPolicy] = useState(null);
  const [dryRunModalOpen, setDryRunModalOpen] = useState(false);

  // Fetch groups to map target_group_id to group name
  useEffect(() => {
    listGroups()
      .then((data) => setGroups(Array.isArray(data) ? data : []))
      .catch((err) => console.error('Failed to load groups in Policies page', err));
  }, []);

  const groupsMap = useMemo(() => {
    const map = {};
    groups.forEach((g) => {
      map[g.id] = g.name;
    });
    return map;
  }, [groups]);

  // Filter and Search
  const filteredPolicies = useMemo(() => {
    return policies.filter((p) => {
      const matchSearch =
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (p.description && p.description.toLowerCase().includes(searchTerm.toLowerCase())) ||
        p.action_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (p.target_group_name && p.target_group_name.toLowerCase().includes(searchTerm.toLowerCase()));

      let matchTab = true;
      if (activeTab === 'active') {
        matchTab = p.is_active === true;
      } else if (activeTab === 'inactive') {
        matchTab = p.is_active === false;
      } else if (activeTab === 'agent') {
        matchTab = p.scope === 'agent';
      } else if (activeTab === 'group') {
        matchTab = p.scope === 'group';
      }

      return matchSearch && matchTab;
    });
  }, [policies, searchTerm, activeTab]);

  // KPI Calculations
  const totalPolicies = policies.length;
  const activePolicies = policies.filter((p) => p.is_active).length;
  const groupScopePolicies = policies.filter((p) => p.scope === 'group').length;
  const agentScopePolicies = policies.filter((p) => p.scope === 'agent').length;

  // Calculate risk coverage: span of unique risk scores covered by active policies
  const coveragePercent = useMemo(() => {
    if (policies.length === 0) return 0;
    // Check coverage across 0-100 scale
    const activeOnes = policies.filter((p) => p.is_active);
    if (activeOnes.length === 0) return 0;
    let coveredPoints = 0;
    for (let s = 0; s <= 100; s++) {
      if (activeOnes.some((p) => s >= p.min_score && s <= p.max_score)) {
        coveredPoints++;
      }
    }
    return Math.round((coveredPoints / 101) * 100);
  }, [policies]);

  const handleOpenCreate = () => {
    setEditingPolicy(null);
    setFormModalOpen(true);
  };

  const handleOpenEdit = (p) => {
    setEditingPolicy(p);
    setFormModalOpen(true);
  };

  const handleOpenTest = (p) => {
    setTestingPolicy(p);
    setDryRunModalOpen(true);
  };

  const handleSavePolicy = async (payload, editId) => {
    if (editId) {
      await updatePolicy(editId, payload);
    } else {
      await createPolicy(payload);
    }
  };

  const handleDelete = async (p) => {
    if (!confirm(`Bạn có chắc muốn xóa chính sách phản ứng "${p.name}"? Hành động này không thể hoàn tác.`)) {
      return;
    }
    try {
      await deletePolicy(p.id);
    } catch (err) {
      alert(err.response?.data?.detail || err.message || 'Không thể xóa chính sách');
    }
  };

  const handleToggle = async (id, isCurrentActive) => {
    try {
      await toggleActive(id, isCurrentActive);
    } catch (err) {
      alert(err.response?.data?.detail || err.message || 'Không thể đổi trạng thái chính sách');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '2.5rem' }}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FiShield className="text-primary" /> Response Policies
          </h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Cấu hình tự động hóa phản ứng an ninh (Alert, Block IP, Isolate) theo dải điểm rủi ro và phạm vi (Agent / Group).
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem' }}>
          <Button
            variant="outline"
            size="sm"
            onClick={fetchPolicies}
            disabled={loading}
            iconLeft={<FiRefreshCw size={13} className={loading ? 'animate-spin' : ''} />}
          >
            Làm mới
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={handleOpenCreate}
            iconLeft={<FiPlus size={14} />}
          >
            Create Policy
          </Button>
        </div>
      </div>

      {/* KPI Cards Row (4 Cards) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
        <KpiCard
          title="Total Policies"
          value={totalPolicies}
          subtitle="Chính sách được đăng ký"
          icon={<FiShield />}
          color="primary"
        />
        <KpiCard
          title="Active Policies"
          value={activePolicies}
          subtitle={`${Math.round((activePolicies / (totalPolicies || 1)) * 100)}% đang kích hoạt`}
          icon={<FiCheckCircle />}
          color="success"
        />
        <KpiCard
          title="Group Scope Policies"
          value={groupScopePolicies}
          subtitle={`${agentScopePolicies} policies phạm vi agent`}
          icon={<FiUsers />}
          color="warning"
        />
        <KpiCard
          title="Coverage"
          value={`${coveragePercent}%`}
          subtitle="Bao phủ thang điểm rủi ro (0-100)"
          icon={<FiPercent />}
          color="info"
        />
      </div>

      {/* Filter Tabs & Search Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <FilterTabs
          tabs={TABS.map((t) => {
            let count = totalPolicies;
            if (t.value === 'active') count = activePolicies;
            if (t.value === 'inactive') count = totalPolicies - activePolicies;
            if (t.value === 'agent') count = agentScopePolicies;
            if (t.value === 'group') count = groupScopePolicies;
            return { ...t, count };
          })}
          active={activeTab}
          onChange={setActiveTab}
        />

        <div style={{ width: '300px' }}>
          <SearchBar
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Search policy name, action, group..."
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
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <FiAlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Policies Table */}
      <PolicyTable
        policies={filteredPolicies}
        loading={loading}
        groupsMap={groupsMap}
        onEdit={handleOpenEdit}
        onDelete={handleDelete}
        onToggleActive={handleToggle}
        onTest={handleOpenTest}
      />

      {/* Modal 1: Create / Edit Policy */}
      <PolicyFormModal
        isOpen={formModalOpen}
        onClose={() => setFormModalOpen(false)}
        onSaved={handleSavePolicy}
        editPolicy={editingPolicy}
        existingPolicies={policies}
      />

      {/* Modal 2: Dry Run Test Simulation */}
      <PolicyDryRunPanel
        isOpen={dryRunModalOpen}
        initialPolicy={testingPolicy}
        onClose={() => setDryRunModalOpen(false)}
        onApplied={() => fetchPolicies()}
      />
    </div>
  );
}
