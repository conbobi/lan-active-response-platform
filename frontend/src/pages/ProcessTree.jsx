import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import toast from 'react-hot-toast';
import useProcessTree from '../hooks/useProcessTree';
import { useAgents } from '../hooks/useAgents';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import ErrorState from '../components/ui/ErrorState';
import EmptyState from '../components/ui/EmptyState';
import InfoTooltip from '../components/ui/InfoTooltip';
import { TOOLTIPS } from '../constants/tooltips';
import KillProcessModal from '../components/process/KillProcessModal';
import TreeNode from '../components/process/TreeNode';
import { killProcess } from '../api/process';
import {
  FiCpu,
  FiAlertOctagon,
  FiRotateCw,
  FiXCircle,
  FiCornerDownRight,
  FiChevronDown,
  FiChevronRight,
  FiMaximize2,
  FiMinimize2,
  FiLayers,
  FiTerminal,
  FiCheckCircle,
  FiX
} from 'react-icons/fi';

export default function ProcessTree() {
  const { agents } = useAgents();
  const [selectedAgent, setSelectedAgent] = useState('');

  const {
    processTree,
    suspiciousProcesses,
    loading,
    killing,
    error,
    actionSuccess,
    clearActionSuccess,
    clearError,
    refreshProcessData,
    handleKillProcess,
    handleKillProcessTree,
  } = useProcessTree(selectedAgent);

  const [expandedPids, setExpandedPids] = useState(new Set());
  const [killTarget, setKillTarget] = useState(null);
  const prevAgentRef = useRef('');

  // Auto-dismiss success notification after 4.5 seconds
  useEffect(() => {
    if (actionSuccess) {
      const timer = setTimeout(() => {
        if (clearActionSuccess) clearActionSuccess();
      }, 4500);
      return () => clearTimeout(timer);
    }
  }, [actionSuccess, clearActionSuccess]);

  // Client-side dedup: ưu tiên agent active, nếu không thì last_seen mới nhất
  const dedupedAgents = useMemo(() => {
    if (!agents || agents.length === 0) return [];
    const byHostname = {};
    for (const a of agents) {
      const key = a.hostname || a.id;
      const existing = byHostname[key];
      if (!existing) {
        byHostname[key] = a;
        continue;
      }
      const aIsActive = (a.status || '').toLowerCase() === 'active' || (a.status || '').toLowerCase() === 'online';
      const eIsActive = (existing.status || '').toLowerCase() === 'active' || (existing.status || '').toLowerCase() === 'online';

      if (aIsActive && !eIsActive) {
        byHostname[key] = a;
      } else if (!aIsActive && eIsActive) {
        // keep existing
      } else {
        const aTs = a.last_seen || a.created_at;
        const eTs = existing.last_seen || existing.created_at;
        if (aTs && (!eTs || new Date(aTs) > new Date(eTs))) {
          byHostname[key] = a;
        }
      }
    }
    return Object.values(byHostname);
  }, [agents]);

  // Ưu tiên chọn agent active làm default
  useEffect(() => {
    if (dedupedAgents.length > 0) {
      const isCurrentValid = dedupedAgents.some((a) => a.id === selectedAgent);
      if (!selectedAgent || !isCurrentValid) {
        const activeAgent =
          dedupedAgents.find((a) => {
            const s = (a.status || '').toLowerCase();
            return s === 'active' || s === 'online';
          }) || dedupedAgents[0];
        if (activeAgent) {
          setSelectedAgent(activeAgent.id);
        }
      }
    }
  }, [dedupedAgents, selectedAgent]);

  // Auto-expand tree when agent changes or process tree loads, while preserving user expanded state
  useEffect(() => {
    if (!processTree || !selectedAgent) return;
    const roots = processTree.tree || (Array.isArray(processTree) ? processTree : [processTree]);
    if (!Array.isArray(roots)) return;

    setExpandedPids((prev) => {
      const next = new Set(prev);
      let changed = false;

      const walk = (nodes, depth) => {
        for (const n of nodes || []) {
          // Auto-expand: depth < 2, HOẶC process quan trọng (explorer/notepad/edge/code)
          const isImportant = /explorer\.exe|notepad\.exe|msedge\.exe|chrome\.exe|Code\.exe/i.test(n.name || '');
          if ((depth < 2 || isImportant || n.is_suspicious) && !next.has(n.pid)) {
            next.add(n.pid);
            changed = true;
          }
          if (Array.isArray(n.children)) {
            walk(n.children, depth + 1);
          }
        }
      };
      walk(roots, 0);

      // Chỉ trả set mới nếu có thay đổi → tránh re-render vô ích
      return changed ? next : prev;
    });
  }, [processTree, selectedAgent]);

  const agentOptions = useMemo(() => {
    return dedupedAgents.map((a) => {
      const isActive = (a.status || '').toLowerCase() === 'active' || (a.status || '').toLowerCase() === 'online';
      const badge = isActive ? ' 🟢' : ' ⚪';
      const name = a.name || a.hostname || a.id;
      const ip = a.ip || a.ip_address || 'N/A';
      return {
        value: a.id,
        label: `${name} (${ip})${badge}`,
      };
    });
  }, [dedupedAgents]);

  const handleToggle = useCallback((pid) => {
    setExpandedPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) {
        next.delete(pid);
      } else {
        next.add(pid);
      }
      return next;
    });
  }, []);

  const handleKillPidAction = useCallback((proc) => {
    openKillModal(proc, false);
  }, []);

  const handleKillTreeAction = useCallback((proc) => {
    openKillModal(proc, true);
  }, []);

  const expandAll = () => {
    const allPids = new Set();
    const collect = (nodes) => {
      nodes.forEach((n) => {
        if (n && n.pid) {
          allPids.add(n.pid);
          if (Array.isArray(n.children)) collect(n.children);
        }
      });
    };
    const roots = processTree?.tree || (Array.isArray(processTree) ? processTree : [processTree]);
    if (Array.isArray(roots)) collect(roots);
    setExpandedPids(allPids);
  };

  const collapseAll = () => {
    setExpandedPids(new Set());
  };

  const openKillModal = (proc, isTreeMode = true) => {
    setKillTarget({ ...proc, defaultKillTree: isTreeMode });
  };

  const handleKill = async ({ pid, reason, killTree }) => {
    try {
      const result = await killProcess(selectedAgent, pid, { reason, killTree });
      toast.success(`Đã gửi lệnh ${result?.action_type || (killTree ? 'kill_tree' : 'kill_process')} cho PID ${pid}`);
      if (clearError) clearError();
      if (killTree) {
        await handleKillProcessTree(pid);
      } else {
        await handleKillProcess(pid);
      }
      setTimeout(() => {
        refreshProcessData();
      }, 1500);
    } catch (err) {
      if (err.response?.status === 429) {
        const detail = err.response.data?.detail || "";
        const match = detail.match(/(\d+)s remaining/);
        const remaining = match ? match[1] : "unknown";
        toast.error(`⏳ Agent đang cooldown. Còn ${remaining}s`, { duration: 6000 });
      } else {
        toast.error(`Kill failed: ${err.response?.data?.detail || err.message}`);
      }
      throw err;
    }
  };


  const renderTreeContent = () => {
    if (!processTree) {
      return (
        <EmptyState
          icon="🌳"
          title="Chưa có dữ liệu process"
          description={`Process tree sẽ hiển thị khi agent ${selectedAgent || ''} gửi telemetry.`}
        />
      );
    }

    const treeData = processTree.tree || (Array.isArray(processTree) ? processTree : [processTree]);

    if (!Array.isArray(treeData) || treeData.length === 0) {
      return (
        <EmptyState
          icon="🌳"
          title="Chưa có dữ liệu process"
          description={`Process tree sẽ hiển thị khi agent ${selectedAgent || ''} gửi telemetry.`}
        />
      );
    }

    return (
      <div className="process-tree-container">
        {treeData.map((rootNode) => (
          <TreeNode
            key={rootNode.pid}
            node={rootNode}
            level={0}
            expandedPids={expandedPids}
            onToggle={handleToggle}
            onKillPid={handleKillPidAction}
            onKillTree={handleKillTreeAction}
            killing={killing}
          />
        ))}
      </div>
    );
  };

  if (error && !processTree) {
    return (
      <ErrorState
        title="Không thể tải Process Tree"
        message={`${error}. Vui lòng kiểm tra kết nối với agent hoặc backend.`}
        onRetry={refreshProcessData}
      />
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Process & Root Cause Analysis</h1>
          <p className="page-subtitle">Inspect host process trees, identify anomalous parent-child relationships, and terminate malicious execution</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          {killing && (
            <span style={{ fontSize: '0.85rem', color: 'var(--warning)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <FiRotateCw size={14} className="spin" /> Dispatching Kill & Syncing...
            </span>
          )}
          <div style={{ width: 260 }} title="Các agent cũ cùng hostname đã được tự động ẩn để tránh nhầm lẫn">
            <Dropdown
              options={agentOptions}
              value={selectedAgent}
              onChange={setSelectedAgent}
              disabled={killing}
            />
          </div>
          <Button
            variant="outline"
            iconLeft={<FiRotateCw size={15} className={killing ? 'spin' : ''} />}
            onClick={refreshProcessData}
            disabled={killing}
          >
            {killing ? 'Syncing...' : 'Refresh'}
          </Button>
        </div>
      </div>

      {/* Success Notification Alert */}
      {actionSuccess && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.75rem 1rem',
            background: 'rgba(0,192,123,0.12)',
            border: '1px solid var(--success)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '1.25rem',
            color: 'var(--success)',
            fontSize: '0.875rem',
            fontWeight: 600
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiCheckCircle size={17} />
            <span>{actionSuccess} — Process list refreshed successfully.</span>
          </div>
          <button
            onClick={clearActionSuccess}
            style={{ background: 'none', border: 'none', color: 'var(--success)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
          >
            <FiX size={16} />
          </button>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.75rem 1rem',
            background: 'rgba(239,68,68,0.12)',
            border: '1px solid var(--error)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '1.25rem',
            color: 'var(--error)',
            fontSize: '0.875rem',
            fontWeight: 600
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiAlertOctagon size={17} />
            <span>{error}</span>
          </div>
          <button
            onClick={clearError}
            style={{ background: 'none', border: 'none', color: 'var(--error)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
          >
            <FiX size={16} />
          </button>
        </div>
      )}

      {/* Flagged Suspicious Processes Alert Card */}
      <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid var(--error)' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiAlertOctagon size={18} /> Flagged Suspicious Processes ({suspiciousProcesses.length})
        </h3>

        {suspiciousProcesses.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: 'var(--success)' }}>
            ✓ No active suspicious processes detected on agent <strong>{selectedAgent}</strong>.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {suspiciousProcesses.map((proc) => (
              <div
                key={proc.pid}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '0.75rem 1rem',
                  background: 'rgba(239,68,68,0.06)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid rgba(239,68,68,0.25)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <span style={{ fontWeight: 700, fontFamily: 'monospace', color: 'var(--error)' }}>
                      <InfoTooltip {...TOOLTIPS.PID}>PID {proc.pid}</InfoTooltip>
                    </span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{proc.name}</span>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                      {proc.exe || proc.path || proc.cmdline || ''}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                    Reason: <strong>{proc.reason || 'Malicious heuristic flagged'}</strong>
                  </div>

                  {Array.isArray(proc.parent_chain) && proc.parent_chain.length > 0 && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <FiTerminal size={12} /> <InfoTooltip {...TOOLTIPS.PPID}>Parent Execution Lineage:</InfoTooltip>{' '}
                      {proc.parent_chain.map((p, idx) => (
                        <span key={p.pid || idx} style={{ fontFamily: 'monospace' }}>
                          {idx > 0 && ' → '}
                          {p.name} (<InfoTooltip {...TOOLTIPS.PID}>PID {p.pid}</InfoTooltip>)
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <Button
                    variant="ghost"
                    size="sm"
                    iconLeft={<FiXCircle size={14} />}
                    onClick={() => openKillModal(proc, false)}
                    disabled={killing}
                    title="Dừng tiến trình này"
                  >
                    Kill PID {proc.pid}
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    iconLeft={<FiLayers size={14} />}
                    onClick={() => openKillModal(proc, true)}
                    disabled={killing}
                    title="Dừng tiến trình độc hại (kèm process con)"
                  >
                    Kill Tree {proc.pid}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Complete Execution Tree Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiCpu color="var(--primary)" /> Complete Execution Tree Hierarchy
            {processTree?.total_processes ? (
              <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', fontWeight: 400 }}>
                ({processTree.total_processes} processes)
              </span>
            ) : null}
          </h3>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <Button variant="ghost" size="sm" iconLeft={<FiMaximize2 size={13} />} onClick={expandAll} disabled={killing}>
              Expand All
            </Button>
            <Button variant="ghost" size="sm" iconLeft={<FiMinimize2 size={13} />} onClick={collapseAll} disabled={killing}>
              Collapse All
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="skeleton" style={{ height: '320px' }} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {renderTreeContent()}
          </div>
        )}
      </div>

      {/* Kill Process Modal */}
      <KillProcessModal
        isOpen={!!killTarget}
        process={killTarget}
        agentId={selectedAgent}
        onClose={() => setKillTarget(null)}
        onConfirm={handleKill}
      />
    </div>
  );
}
