// src/pages/ProcessTree.jsx
import React, { useState, useEffect, useMemo } from 'react';
import useProcessTree from '../hooks/useProcessTree';
import { useAgents } from '../hooks/useAgents';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import { FiCpu, FiAlertOctagon, FiRotateCw, FiXCircle, FiCornerDownRight } from 'react-icons/fi';

export default function ProcessTree() {
  const { agents } = useAgents();
  const [selectedAgent, setSelectedAgent] = useState('');

  const {
    processTree,
    suspiciousProcesses,
    loading,
    refreshProcessData,
    handleKillProcess,
  } = useProcessTree(selectedAgent);

  const [killModalProc, setKillModalProc] = useState(null);

  useEffect(() => {
    if (agents.length > 0 && !selectedAgent) {
      setSelectedAgent(agents[0].id);
    }
  }, [agents, selectedAgent]);

  const agentOptions = useMemo(() => {
    return agents.map((a) => ({
      value: a.id,
      label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
    }));
  }, [agents]);

  const confirmKill = async () => {
    if (!killModalProc) return;
    await handleKillProcess(killModalProc.pid);
    setKillModalProc(null);
  };

  // Helper component to render recursive process tree nodes
  const renderTreeNode = (node, depth = 0) => {
    if (!node) return null;
    const isSusp = node.is_suspicious;

    return (
      <div key={node.pid || Math.random()} style={{ display: 'flex', flexDirection: 'column' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justify: 'space-between',
            padding: '0.6rem 0.85rem',
            marginLeft: `${depth * 20}px`,
            borderLeft: depth > 0 ? '2px solid var(--border)' : 'none',
            background: isSusp ? 'rgba(239,68,68,0.08)' : 'var(--bg)',
            border: isSusp ? '1px solid rgba(239,68,68,0.3)' : '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '0.4rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {depth > 0 && <FiCornerDownRight size={14} color="var(--text-tertiary)" />}
            <span style={{ fontWeight: 700, fontFamily: 'monospace', fontSize: '0.85rem', color: isSusp ? 'var(--error)' : 'var(--primary)' }}>
              PID {node.pid}
            </span>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.875rem' }}>
              {node.name}
            </span>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
              ({node.path})
            </span>
            {isSusp && <Badge status="critical" label="SUSPICIOUS" />}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              CPU: <strong>{node.cpu}%</strong>
            </span>
            <Button
              variant={isSusp ? 'danger' : 'ghost'}
              size="sm"
              iconLeft={<FiXCircle size={13} />}
              onClick={() => setKillModalProc(node)}
            >
              Kill
            </Button>
          </div>
        </div>

        {Array.isArray(node.children) && node.children.map((child) => renderTreeNode(child, depth + 1))}
      </div>
    );
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Process & Root Cause Analysis</h1>
          <p className="page-subtitle">Inspect host process trees, identify anomalous parent-child relationships, and terminate malicious execution</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <div style={{ width: 220 }}>
            <Dropdown
              options={agentOptions}
              value={selectedAgent}
              onChange={setSelectedAgent}
            />
          </div>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshProcessData}>
            Refresh Tree
          </Button>
        </div>
      </div>

      {/* Suspicious Processes Alert Card */}
      <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid var(--error)' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiAlertOctagon size={18} /> Flagged Suspicious Processes ({suspiciousProcesses.length})
        </h3>

        {suspiciousProcesses.length === 0 ? (
          <div style={{ fontSize: '0.85rem', color: 'var(--success)' }}>
            ✓ No active suspicious processes detected on target agent.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
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
                  border: '1px solid rgba(239,68,68,0.2)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <span style={{ fontWeight: 700, fontFamily: 'monospace', color: 'var(--error)' }}>PID {proc.pid}</span>
                    <span style={{ fontWeight: 600 }}>{proc.name}</span>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)' }}>{proc.path}</span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Reason: <strong>{proc.reason || 'Malicious heuristic flagged'}</strong>
                  </div>
                </div>

                <Button variant="danger" size="sm" iconLeft={<FiXCircle size={14} />} onClick={() => setKillModalProc(proc)}>
                  Terminate PID {proc.pid}
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Main Process Tree Card */}
      <div className="card">
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FiCpu color="var(--primary)" /> Complete Execution Tree Hierarchy
        </h3>

        {loading ? (
          <div className="skeleton" style={{ height: '300px' }} />
        ) : !processTree ? (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
            No process tree telemetry available for agent {selectedAgent}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {renderTreeNode(processTree, 0)}
          </div>
        )}
      </div>

      {/* Kill Confirmation Modal */}
      <Modal isOpen={!!killModalProc} onClose={() => setKillModalProc(null)} title="Terminate Process Confirmation">
        {killModalProc && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Are you sure you want to dispatch a SIGKILL signal to process <strong>{killModalProc.name}</strong> (PID: {killModalProc.pid}) on agent <strong>{selectedAgent}</strong>?
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <Button variant="ghost" onClick={() => setKillModalProc(null)}>
                Cancel
              </Button>
              <Button variant="danger" iconLeft={<FiXCircle size={14} />} onClick={confirmKill}>
                Confirm Kill PID {killModalProc.pid}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
