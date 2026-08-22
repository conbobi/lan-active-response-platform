// src/pages/Rules.jsx
import React, { useState, useRef } from 'react';
import useRules from '../hooks/useRules';
import RuleTable from '../components/ui/RuleTable';
import RuleForm from '../components/ui/RuleForm';
import RuleTestModal from '../components/ui/RuleTestModal';
import RuleAuditModal from '../components/ui/RuleAuditModal';
import SearchBar from '../components/ui/SearchBar';
import Dropdown from '../components/ui/Dropdown';
import Pagination from '../components/ui/Pagination';
import Button from '../components/ui/Button';
import { FiPlus, FiShield, FiPlay, FiList, FiDownload, FiUpload } from 'react-icons/fi';

const TYPE_FILTER_OPTIONS = [
  { value: 'all', label: 'All Types' },
  { value: 'dns', label: 'DNS Spoofing' },
  { value: 'proxy', label: 'Proxy Detection' },
  { value: 'botnet', label: 'Botnet (IRC)' },
  { value: 'rate_limit', label: 'Rate Limit' },
  { value: 'blacklist', label: 'Blacklist' },
  { value: 'firewall', label: 'Firewall' },
  { value: 'edr', label: 'EDR' },
  { value: 'signature', label: 'Signature' },
];

const SEVERITY_FILTER_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const STATUS_FILTER_OPTIONS = [
  { value: 'all', label: 'All Statuses' },
  { value: 'active', label: 'Active' },
  { value: 'inactive', label: 'Inactive' },
];

export default function Rules() {
  const {
    rules,
    auditLogs,
    filteredCount,
    totalCount,
    loading,
    search,
    setSearch,
    typeFilter,
    setTypeFilter,
    severityFilter,
    setSeverityFilter,
    statusFilter,
    setStatusFilter,
    page,
    setPage,
    totalPages,
    createRule,
    editRule,
    removeRule,
    toggleRule,
    checkConflicts,
    testSimulation,
    exportRulesJson,
    importRulesJson,
  } = useRules(8);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [isAuditModalOpen, setIsAuditModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);

  const fileInputRef = useRef(null);

  const handleOpenCreateModal = () => {
    setEditingRule(null);
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (rule) => {
    setEditingRule(rule);
    setIsModalOpen(true);
  };

  const handleFormSubmit = async (formData) => {
    if (editingRule) {
      await editRule(editingRule.id, formData);
    } else {
      await createRule(formData);
    }
  };

  const handleDeleteRule = async (id) => {
    if (window.confirm('Are you sure you want to delete this security rule?')) {
      await removeRule(id);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const json = JSON.parse(evt.target.result);
        const count = await importRulesJson(json);
        alert(`Successfully imported ${count} security rules!`);
      } catch (err) {
        alert(`Failed to import rules JSON: ${err.message}`);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Rules Engine</h1>
        </div>
        <div className="card skeleton" style={{ height: '320px' }} />
      </div>
    );
  }

  return (
    <div>
      {/* Hidden file picker for JSON import */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".json"
        style={{ display: 'none' }}
      />

      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Rules Engine</h1>
          <p className="page-subtitle">Configure automated security policies, rate limits, and threat signatures</p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Button variant="secondary" size="md" iconLeft={<FiPlay size={14} />} onClick={() => setIsTestModalOpen(true)}>
            Test Simulation
          </Button>

          <Button variant="secondary" size="md" iconLeft={<FiList size={14} />} onClick={() => setIsAuditModalOpen(true)}>
            Audit Log
          </Button>

          <Button variant="outline" size="md" iconLeft={<FiDownload size={14} />} onClick={exportRulesJson}>
            Export
          </Button>

          <Button variant="outline" size="md" iconLeft={<FiUpload size={14} />} onClick={() => fileInputRef.current?.click()}>
            Import
          </Button>

          <Button variant="primary" size="md" iconLeft={<FiPlus size={16} />} onClick={handleOpenCreateModal}>
            Create Rule
          </Button>
        </div>
      </div>

      {/* Main Table Card */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {/* Filters Toolbar */}
        <div
          style={{
            padding: '1rem 1.25rem',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justify: 'space-between',
            gap: '1rem',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiShield size={16} color="var(--primary)" />
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Rules List</span>
            <span className="badge badge-info">{filteredCount}</span>
          </div>

          <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <SearchBar value={search} onChange={setSearch} placeholder="Search rules…" style={{ width: 200 }} />
            <Dropdown label="Type" options={TYPE_FILTER_OPTIONS} value={typeFilter} onChange={setTypeFilter} />
            <Dropdown label="Severity" options={SEVERITY_FILTER_OPTIONS} value={severityFilter} onChange={setSeverityFilter} />
            <Dropdown label="Status" options={STATUS_FILTER_OPTIONS} value={statusFilter} onChange={setStatusFilter} />
          </div>
        </div>

        {/* Table Content */}
        <RuleTable
          rules={rules}
          onEdit={handleOpenEditModal}
          onDelete={handleDeleteRule}
          onToggle={toggleRule}
        />

        {/* Pagination Footer */}
        <div
          style={{
            padding: '1rem 1.25rem',
            display: 'flex',
            justify: 'space-between',
            alignItems: 'center',
            borderTop: '1px solid var(--border)',
          }}
        >
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Showing {filteredCount > 0 ? Math.min((page - 1) * 8 + 1, filteredCount) : 0}–
            {Math.min(page * 8, filteredCount)} of {filteredCount} rules
          </span>
          <Pagination current={page} total={totalPages} onChange={setPage} />
        </div>
      </div>

      {/* Create / Edit Rule Form Modal */}
      <RuleForm
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleFormSubmit}
        onCheckConflicts={checkConflicts}
        rule={editingRule}
      />

      {/* Simulation / Test Modal */}
      <RuleTestModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
        onSimulate={testSimulation}
      />

      {/* Audit Log Modal */}
      <RuleAuditModal
        isOpen={isAuditModalOpen}
        onClose={() => setIsAuditModalOpen(false)}
        auditLogs={auditLogs}
      />
    </div>
  );
}
