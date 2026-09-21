// src/pages/ActionsHistory.jsx
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  FiClock,
  FiRefreshCw,
  FiRotateCcw,
  FiShield,
  FiActivity,
  FiCheckCircle,
  FiAlertCircle,
  FiX,
  FiServer,
  FiUsers,
} from 'react-icons/fi';
import Button from '../components/ui/Button';
import KpiCard from '../components/ui/KpiCard';
import FilterTabs from '../components/ui/FilterTabs';
import Dropdown from '../components/ui/Dropdown';
import SearchBar from '../components/ui/SearchBar';
import Pagination from '../components/ui/Pagination';

import ActionsTable from '../components/actions/ActionsTable';
import BulkUndoConfirmModal from '../components/actions/BulkUndoConfirmModal';
import RollbackConfirmModal from '../components/actions/RollbackConfirmModal';
import AuditLogModal from '../components/actions/AuditLogModal';

import useActions from '../hooks/useActions';
import { getAgents } from '../api/agents';
import { listGroups } from '../api/groups';

export default function ActionsHistory() {
  // Hook for all aggregated actions with 5s background polling
  const {
    actions,
    loading,
    actionLoading,
    fetchAllActions,
    handleUndo,
    handleBulkUndo,
  } = useActions({
    isGlobal: true,
    autoFetch: true,
    pollIntervalMs: 5000,
  });

  // Agents and groups list for filter dropdowns
  const [agentsList, setAgentsList] = useState([]);
  const [groupsList, setGroupsList] = useState([]);

  // Filters State
  const [activeTab, setActiveTab] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [agentFilter, setAgentFilter] = useState('all');
  const [groupFilter, setGroupFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  // Selection State for Bulk Rollback
  const [selectedIds, setSelectedIds] = useState(new Set());

  // Modals State
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [bulkProgress, setBulkProgress] = useState(null);
  const [singleUndoAction, setSingleUndoAction] = useState(null);
  const [auditLogActionId, setAuditLogActionId] = useState(null);

  // Toast message state
  const [toast, setToast] = useState(null);

  // Load agents and groups for filtering
  useEffect(() => {
    let mounted = true;
    const fetchMetadata = async () => {
      try {
        const [agentsRes, groupsRes] = await Promise.all([
          getAgents().catch(() => []),
          listGroups().catch(() => []),
        ]);
        if (mounted) {
          setAgentsList(Array.isArray(agentsRes) ? agentsRes : []);
          setGroupsList(Array.isArray(groupsRes) ? groupsRes : []);
        }
      } catch (err) {
        console.error('Failed to load filter metadata', err);
      }
    };
    fetchMetadata();
    return () => {
      mounted = false;
    };
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 5000);
  };

  // KPI Calculations
  const totalActions = actions.length;
  const appliedCount = actions.filter((a) => a.status === 'applied').length;
  const revertedCount = actions.filter((a) => a.status === 'reverted').length;
  const failedCount = actions.filter((a) => a.status === 'failed').length;

  // Filter Tabs Configuration
  const filterTabs = [
    { label: 'Tất cả', value: 'all', count: totalActions },
    { label: 'Đang hiệu lực', value: 'applied', count: appliedCount },
    { label: 'Đã hoàn nguyên', value: 'reverted', count: revertedCount },
    { label: 'Thất bại', value: 'failed', count: failedCount },
    {
      label: 'Có Auto-Rollback',
      value: 'with_rollback',
      count: actions.filter((a) => !!a.auto_rollback_at).length,
    },
  ];

  // Action Type Dropdown Options
  const typeOptions = [
    { value: 'all', label: 'Tất cả loại hành động' },
    { value: 'isolate', label: 'Cô lập mạng (Isolate)' },
    { value: 'block_ip', label: 'Chặn IP (Block IP)' },
    { value: 'kill', label: 'Diệt Process (Kill)' },
    { value: 'quarantine', label: 'Cách ly File (Quarantine)' },
  ];

  // Agent Dropdown Options
  const agentOptions = useMemo(() => {
    const opts = [{ value: 'all', label: 'Tất cả Agents' }];
    agentsList.forEach((ag) => {
      opts.push({
        value: ag.id,
        label: `${ag.hostname || ag.id} (${ag.ip || ag.id})`,
      });
    });
    return opts;
  }, [agentsList]);

  // Group Dropdown Options
  const groupOptions = useMemo(() => {
    const opts = [{ value: 'all', label: 'Tất cả Nhóm' }];
    groupsList.forEach((g) => {
      opts.push({
        value: g.id,
        label: `${g.name} (${g.agent_count ?? (g.agents?.length || 0)} máy)`,
      });
    });
    return opts;
  }, [groupsList]);

  // Filtering Logic
  const filteredActions = useMemo(() => {
    return actions.filter((act) => {
      // 1. Tab Status filter
      if (activeTab === 'applied' && act.status !== 'applied') return false;
      if (activeTab === 'reverted' && act.status !== 'reverted') return false;
      if (activeTab === 'failed' && act.status !== 'failed') return false;
      if (activeTab === 'with_rollback' && !act.auto_rollback_at) return false;

      // 2. Action Type filter
      if (typeFilter !== 'all') {
        const t = (act.action_type || '').toLowerCase();
        if (typeFilter === 'isolate' && !t.includes('isolate')) return false;
        if (typeFilter === 'block_ip' && !t.includes('block')) return false;
        if (typeFilter === 'kill' && !t.includes('kill')) return false;
        if (typeFilter === 'quarantine' && !t.includes('quarantine')) return false;
      }

      // 3. Agent filter
      if (agentFilter !== 'all' && act.agent_id !== agentFilter) {
        return false;
      }

      // 4. Group filter
      if (groupFilter !== 'all') {
        const actGroupId = act.action_params?.group_id;
        const actGroupName = (act.action_params?.group_name || '').toLowerCase();
        const targetGroup = groupsList.find((g) => g.id === groupFilter);
        const matchId = actGroupId === groupFilter;
        const matchName = targetGroup && actGroupName === targetGroup.name.toLowerCase();
        if (!matchId && !matchName) return false;
      }

      // 5. Search Bar filter
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const actId = (act.id || '').toLowerCase();
        const agentId = (act.agent_id || '').toLowerCase();
        const type = (act.action_type || '').toLowerCase();
        const reason = (act.reason || act.action_params?.reason || '').toLowerCase();
        const groupName = (act.action_params?.group_name || '').toLowerCase();

        const match =
          actId.includes(query) ||
          agentId.includes(query) ||
          type.includes(query) ||
          reason.includes(query) ||
          groupName.includes(query);

        if (!match) return false;
      }

      return true;
    });
  }, [actions, activeTab, typeFilter, agentFilter, groupFilter, searchTerm, groupsList]);

  // Reset page to 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [activeTab, typeFilter, agentFilter, groupFilter, searchTerm]);

  // Pagination Slice
  const totalPages = Math.max(1, Math.ceil(filteredActions.length / pageSize));
  const paginatedActions = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredActions.slice(start, start + pageSize);
  }, [filteredActions, currentPage, pageSize]);

  // Selection Handlers
  const handleToggleSelect = (actionId) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(actionId)) {
        next.delete(actionId);
      } else {
        next.add(actionId);
      }
      return next;
    });
  };

  const handleSelectAll = (checked) => {
    if (!checked) {
      setSelectedIds(new Set());
    } else {
      // Select all currently filtered actions that have status === 'applied'
      const applied = filteredActions.filter((a) => a.status === 'applied').map((a) => a.id);
      setSelectedIds(new Set(applied));
    }
  };

  const handleClearSelection = () => {
    setSelectedIds(new Set());
  };

  // Selected action objects for the bulk modal
  const selectedActionsList = useMemo(() => {
    return actions.filter((a) => selectedIds.has(a.id));
  }, [actions, selectedIds]);

  // Execute Bulk Undo
  const handleConfirmBulkUndo = async (reason) => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;

    setBulkProgress({ current: 0, total: ids.length });
    try {
      const result = await handleBulkUndo(ids, reason, (curr, tot) => {
        setBulkProgress({ current: curr, total: tot });
      });

      setBulkModalOpen(false);
      setSelectedIds(new Set());
      showToast(
        `Đã hoàn nguyên thành công ${result.succeeded}/${ids.length} actions.` +
          (result.failed > 0 ? ` (${result.failed} lỗi)` : ''),
        result.failed > 0 ? 'warning' : 'success'
      );
    } catch (err) {
      showToast(`Hoàn nguyên hàng loạt thất bại: ${err.message}`, 'error');
    } finally {
      setBulkProgress(null);
    }
  };

  // Execute Single Undo
  const handleConfirmSingleUndo = async (reason) => {
    if (!singleUndoAction) return;
    try {
      await handleUndo(singleUndoAction.id, reason);
      showToast(`Đã hoàn nguyên thành công action ${singleUndoAction.id}`, 'success');
      setSingleUndoAction(null);
    } catch (err) {
      showToast(`Không thể hoàn nguyên action ${singleUndoAction.id}: ${err.message}`, 'error');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '5rem', position: 'relative' }}>
      {/* Toast Banner */}
      {toast && (
        <div
          style={{
            position: 'fixed',
            top: '20px',
            right: '24px',
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            padding: '0.85rem 1.25rem',
            borderRadius: 'var(--radius-sm, 6px)',
            background:
              toast.type === 'error'
                ? 'var(--error, #ef4444)'
                : toast.type === 'warning'
                ? 'var(--warning, #f59e0b)'
                : 'var(--success, #10b981)',
            color: '#ffffff',
            boxShadow: '0 4px 14px rgba(0, 0, 0, 0.2)',
            fontSize: '0.85rem',
            fontWeight: 500,
            animation: 'fadeIn 0.2s ease-in-out',
          }}
        >
          {toast.type === 'error' ? (
            <FiAlertCircle size={18} />
          ) : (
            <FiCheckCircle size={18} />
          )}
          <span>{toast.message}</span>
          <button
            onClick={() => setToast(null)}
            style={{
              background: 'none',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              marginLeft: '0.5rem',
              display: 'flex',
            }}
          >
            <FiX size={15} />
          </button>
        </div>
      )}

      {/* Page Header */}
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <h1
            className="page-title"
            style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}
          >
            <FiClock className="text-primary" /> Response Actions History
          </h1>
          <p
            style={{
              fontSize: '0.85rem',
              color: 'var(--text-secondary)',
              marginTop: '0.25rem',
            }}
          >
            Lịch sử toàn bộ phản ứng cô lập, chặn IP, diệt process và hoàn nguyên (Undo / Auto-Rollback)
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAllActions}
            disabled={loading}
            iconLeft={
              <FiRefreshCw
                size={14}
                className={loading ? 'animate-spin' : ''}
              />
            }
          >
            Làm mới
          </Button>
        </div>
      </div>

      {/* KPI Cards Row (4 Cards) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}
      >
        <KpiCard
          title="Total Actions"
          value={totalActions}
          subtitle="Tất cả can thiệp đã kích hoạt"
          icon={<FiActivity size={20} />}
          color="primary"
        />
        <KpiCard
          title="Currently Applied"
          value={appliedCount}
          subtitle="Đang có hiệu lực trên máy trạm"
          icon={<FiShield size={20} />}
          color="error"
        />
        <KpiCard
          title="Reverted"
          value={revertedCount}
          subtitle="Đã khôi phục hoàn nguyên"
          icon={<FiCheckCircle size={20} />}
          color="success"
        />
        <KpiCard
          title="Failed"
          value={failedCount}
          subtitle="Gặp sự cố khi thực thi"
          icon={<FiAlertCircle size={20} />}
          color="warning"
        />
      </div>

      {/* Filter and Search Bar Card */}
      <div
        className="card"
        style={{
          padding: '1rem 1.25rem',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          {/* Status Filter Tabs */}
          <FilterTabs
            tabs={filterTabs}
            active={activeTab}
            onChange={setActiveTab}
          />

          {/* Search Bar */}
          <div style={{ minWidth: '260px', flex: '1', maxWidth: '380px' }}>
            <SearchBar
              value={searchTerm}
              onChange={setSearchTerm}
              placeholder="Tìm theo Action ID, Agent, Lý do..."
            />
          </div>
        </div>

        {/* Dropdown Filters Row */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '0.75rem',
            paddingTop: '0.5rem',
            borderTop: '1px dashed var(--border)',
          }}
        >
          <div>
            <label
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                color: 'var(--text-tertiary)',
                display: 'block',
                marginBottom: '0.35rem',
              }}
            >
              Loại hành động (Action Type)
            </label>
            <Dropdown
              options={typeOptions}
              value={typeFilter}
              onChange={setTypeFilter}
            />
          </div>

          <div>
            <label
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                color: 'var(--text-tertiary)',
                display: 'block',
                marginBottom: '0.35rem',
              }}
            >
              Máy trạm (Agent)
            </label>
            <Dropdown
              options={agentOptions}
              value={agentFilter}
              onChange={setAgentFilter}
            />
          </div>

          <div>
            <label
              style={{
                fontSize: '0.75rem',
                fontWeight: 600,
                color: 'var(--text-tertiary)',
                display: 'block',
                marginBottom: '0.35rem',
              }}
            >
              Nhóm máy (Agent Group)
            </label>
            <Dropdown
              options={groupOptions}
              value={groupFilter}
              onChange={setGroupFilter}
            />
          </div>
        </div>
      </div>

      {/* Actions Table */}
      <ActionsTable
        actions={paginatedActions}
        selectedIds={selectedIds}
        onToggleSelect={handleToggleSelect}
        onSelectAll={handleSelectAll}
        onUndo={(act) => setSingleUndoAction(act)}
        onViewLog={(actId) => setAuditLogActionId(actId)}
        loading={loading}
      />

      {/* Pagination Footer */}
      {filteredActions.length > 0 && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem',
            padding: '0.5rem 0.25rem',
          }}
        >
          <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            Hiển thị{' '}
            <strong>
              {(currentPage - 1) * pageSize + 1} -{' '}
              {Math.min(currentPage * pageSize, filteredActions.length)}
            </strong>{' '}
            trong số <strong>{filteredActions.length}</strong> actions
            {filteredActions.length !== totalActions && ` (đã lọc từ ${totalActions})`}
          </div>

          <Pagination
            current={currentPage}
            total={totalPages}
            onChange={setCurrentPage}
          />
        </div>
      )}

      {/* Sticky Selection Toolbar (Appears when >= 1 action is selected) */}
      {selectedIds.size > 0 && (
        <div
          style={{
            position: 'fixed',
            bottom: '24px',
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'var(--bg-card, #ffffff)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-full, 9999px)',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.2)',
            padding: '0.65rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '1.25rem',
            zIndex: 100,
            animation: 'slideUp 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', fontWeight: 600 }}>
            <span
              style={{
                width: '24px',
                height: '24px',
                borderRadius: '50%',
                background: 'var(--primary)',
                color: '#ffffff',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '0.75rem',
              }}
            >
              {selectedIds.size}
            </span>
            <span style={{ color: 'var(--text-primary)' }}>actions đã được chọn</span>
          </div>

          <div style={{ height: '20px', width: '1px', background: 'var(--border)' }} />

          <Button
            variant="danger"
            size="sm"
            onClick={() => setBulkModalOpen(true)}
            iconLeft={<FiRotateCcw size={14} />}
          >
            Rollback {selectedIds.size} Actions
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleClearSelection}
            style={{ color: 'var(--text-secondary)' }}
          >
            Bỏ chọn
          </Button>
        </div>
      )}

      {/* Bulk Undo Confirmation Modal */}
      <BulkUndoConfirmModal
        isOpen={bulkModalOpen}
        actions={selectedActionsList}
        onClose={() => setBulkModalOpen(false)}
        onConfirm={handleConfirmBulkUndo}
        loading={actionLoading}
        progress={bulkProgress}
      />

      {/* Single Undo Confirmation Modal */}
      <RollbackConfirmModal
        isOpen={!!singleUndoAction}
        action={singleUndoAction}
        onClose={() => setSingleUndoAction(null)}
        onConfirm={handleConfirmSingleUndo}
      />

      {/* Audit Log Modal */}
      <AuditLogModal
        isOpen={!!auditLogActionId}
        actionId={auditLogActionId}
        onClose={() => setAuditLogActionId(null)}
      />
    </div>
  );
}
