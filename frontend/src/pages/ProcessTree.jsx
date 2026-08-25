// src/pages/ProcessTree.jsx
import React, { useState, useEffect, useMemo } from 'react';
import useProcessTree from '../hooks/useProcessTree';
import { useAgents } from '../hooks/useAgents';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
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
  FiTerminal
} from 'react-icons/fi';

export default function ProcessTree() {
  const { agents } = useAgents();
  const [selectedAgent, setSelectedAgent] = useState('');

  const {
    processTree,
    suspiciousProcesses,
    loading,
    killing,
    refreshProcessData,
    handleKillProcess,
    handleKillProcessTree,
  } = useProcessTree(selectedAgent);

  const [expandedPids, setExpandedPids] = useState(new Set());
  const [killModalProc, setKillModalProc] = useState(null);
  const [killTreeMode, setKillTreeMode] = useState(true);

  useEffect(() => {
    if (agents.length > 0 && !selectedAgent) {
      setSelectedAgent(agents[0].id);
    }
  }, [agents, selectedAgent]);

  // Auto-expand top roots when process tree loads
  useEffect(() => {
    if (processTree) {
      const roots = processTree.tree || (Array.isArray(processTree) ? processTree : [processTree]);
      if (Array.isArray(roots)) {
        const initialPids = new Set();
        const collectPids = (nodes, depth = 0) => {
          nodes.forEach((n) => {
            if (n && n.pid) {
              // Auto expand top 2 levels or suspicious nodes
              if (depth < 2 || n.is_suspicious) {
                initialPids.add(n.pid);
              }
              if (Array.isArray(n.children)) {
                collectPids(n.children, depth + 1);
              }
            }
          });
        };
        collectPids(roots, 0);
        setExpandedPids(initialPids);
      }
    }
  }, [processTree]);

  const agentOptions = useMemo(() => {
    return agents.map((a) => ({
      value: a.id,
      label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
    }));
  }, [agents]);

  const toggleExpand = (pid) => {
    setExpandedPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) {
        next.delete(pid);
      } else {
        next.add(pid);
      }
      return next;
    });
  };

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
    setKillModalProc(proc);
    setKillTreeMode(isTreeMode);
  };

  const confirmKill = async () => {
    if (!killModalProc) return;
    if (killTreeMode) {
      await handleKillProcessTree(killModalProc.pid, killModalProc.name);
    } else {
      await handleKillProcess(killModalProc.pid);
    }
    setKillModalProc(null);
  };

  // Render recursive process tree nodes with expand/collapse
  const renderTreeNode = (node, depth = 0) => {
    if (!node) return null;
    const hasChildren = Array.isArray(node.children) && node.children.length > 0;
    const isExpanded = expandedPids.has(node.pid);
    const isSusp = node.is_suspicious;

    return (
      <div key={node.pid || Math.random()} style={{ display: 'flex', flexDirection: 'column' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.55rem 0.85rem',
            marginLeft: `${depth * 22}px`,
            borderLeft: depth > 0 ? '2px solid var(--border)' : 'none',
            background: isSusp ? 'rgba(239,68,68,0.08)' : 'var(--bg-secondary)',
            border: isSusp ? '1px solid rgba(239,68,68,0.3)' : '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '0.35rem',
            transition: 'background 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, overflow: 'hidden' }}>
            {hasChildren ? (
              <button
                onClick={() => toggleExpand(node.pid)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  padding: '2px',
                }}
                title={isExpanded ? 'Collapse' : 'Expand'}
              >
                {isExpanded ? <FiChevronDown size={16} color="var(--primary)" /> : <FiChevronRight size={16} />}
              </button>
            ) : (
              <span style={{ width: 16, display: 'inline-block' }} />
            )}

            {depth > 0 && <FiCornerDownRight size={13} color="var(--text-tertiary)" />}

            <span
              style={{
                fontWeight: 700,
                fontFamily: 'monospace',
                fontSize: '0.82rem',
                color: isSusp ? 'var(--error)' : 'var(--primary)',
                minWidth: 70,
              }}
            >
              PID {node.pid}
            </span>

            <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
              {node.name}
            </span>

            {node.cmdline && (
              <span
                style={{
                  fontSize: '0.76rem',
                  color: 'var(--text-tertiary)',
                  fontFamily: 'monospace',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  maxWidth: 320,
                }}
                title={node.cmdline}
              >
                ({node.cmdline})
              </span>
            )}

            {isSusp && <Badge status="critical" label="SUSPICIOUS" />}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexShrink: 0 }}>
            {node.cpu_percent !== undefined && (
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                CPU: <strong>{node.cpu_percent}%</strong>
              </span>
            )}
            {node.memory_percent !== undefined && (
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                RAM: <strong>{node.memory_percent}%</strong>
              </span>
            )}

            <Button
              variant="ghost"
              size="sm"
              iconLeft={<FiXCircle size={13} />}
              onClick={() => openKillModal(node, false)}
            >
              Kill PID
            </Button>
            <Button
              variant={isSusp ? 'danger' : 'outline'}
              size="sm"
              iconLeft={<FiLayers size={13} />}
              onClick={() => openKillModal(node, true)}
            >
              Kill Tree
            </Button>
          </div>
        </div>

        {/* Render child nodes recursively if expanded */}
        {hasChildren && isExpanded && (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {node.children.map((child) => renderTreeNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  const renderTreeContent = () => {
    if (!processTree) {
      return (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
          No process telemetry recorded yet for agent <strong>{selectedAgent}</strong>
        </div>
      );
    }

    const treeData = processTree.tree || (Array.isArray(processTree) ? processTree : [processTree]);

    if (!Array.isArray(treeData) || treeData.length === 0) {
      return (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
          Process list is currently empty for agent <strong>{selectedAgent}</strong>
        </div>
      );
    }

    return treeData.map((rootNode) => renderTreeNode(rootNode, 0));
  };

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
              <FiRotateCw size={14} className="spin" /> Dispatching Kill Signal...
            </span>
          )}
          <div style={{ width: 240 }}>
            <Dropdown
              options={agentOptions}
              value={selectedAgent}
              onChange={setSelectedAgent}
            />
          </div>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshProcessData}>
            Refresh
          </Button>
        </div>
      </div>

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
                  justify: 'space-between',
                  padding: '0.75rem 1rem',
                  background: 'rgba(239,68,68,0.06)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid rgba(239,68,68,0.25)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <span style={{ fontWeight: 700, fontFamily: 'monospace', color: 'var(--error)' }}>PID {proc.pid}</span>
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
                      <FiTerminal size={12} /> Parent Execution Lineage:{' '}
                      {proc.parent_chain.map((p, idx) => (
                        <span key={p.pid || idx} style={{ fontFamily: 'monospace' }}>
                          {idx > 0 && ' → '}
                          {p.name} (PID {p.pid})
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <Button variant="ghost" size="sm" iconLeft={<FiXCircle size={14} />} onClick={() => openKillModal(proc, false)}>
                    Kill PID {proc.pid}
                  </Button>
                  <Button variant="danger" size="sm" iconLeft={<FiLayers size={14} />} onClick={() => openKillModal(proc, true)}>
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
            <Button variant="ghost" size="sm" iconLeft={<FiMaximize2 size={13} />} onClick={expandAll}>
              Expand All
            </Button>
            <Button variant="ghost" size="sm" iconLeft={<FiMinimize2 size={13} />} onClick={collapseAll}>
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

      {/* Kill Confirmation Modal */}
      <Modal
        isOpen={!!killModalProc}
        onClose={() => setKillModalProc(null)}
        title={killTreeMode ? 'Terminate Process Tree Confirmation' : 'Terminate Process Confirmation'}
      >
        {killModalProc && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Are you sure you want to dispatch a <strong>{killTreeMode ? 'KILL_PROCESS_TREE' : 'KILL_PROCESS'}</strong> signal to process <strong>{killModalProc.name}</strong> (PID: {killModalProc.pid}) on agent <strong>{selectedAgent}</strong>?
            </p>
            {killTreeMode && (
              <div
                style={{
                  fontSize: '0.82rem',
                  padding: '0.6rem 0.85rem',
                  background: 'rgba(239,68,68,0.1)',
                  border: '1px solid var(--error)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--error)',
                }}
              >
                ⚡ This will recursively kill PID {killModalProc.pid} and all child processes spawned by this process tree to prevent zombie execution.
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <Button variant="ghost" onClick={() => setKillModalProc(null)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                iconLeft={killTreeMode ? <FiLayers size={14} /> : <FiXCircle size={14} />}
                onClick={confirmKill}
                disabled={killing}
              >
                {killing ? 'Dispatching...' : killTreeMode ? `Confirm Kill Tree (PID ${killModalProc.pid})` : `Confirm Kill PID ${killModalProc.pid}`}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
