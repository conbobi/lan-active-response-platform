// src/components/incidents/ProcessAncestry.jsx
import React, { useState, useEffect } from 'react';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import api from '../../api/api';
import {
  FiTerminal,
  FiSlash,
  FiCornerDownRight,
  FiLayers,
  FiCpu,
  FiHash,
  FiFolder,
  FiCheckCircle,
  FiAlertTriangle,
  FiRefreshCw
} from 'react-icons/fi';

export default function ProcessAncestry({
  incident,
  onAction,
  actionLoading,
}) {
  const [treeData, setTreeData] = useState(null);
  const [loading, setLoading] = useState(false);

  const culprit = incident?.culpritProcess || {
    pid: 4128,
    name: 'key_test.exe',
    exe_path: 'C:\\Users\\AppData\\Local\\Temp\\key_test.exe',
    cmdline: 'key_test.exe --hidden',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    is_suspicious: true,
  };

  const parent = incident?.parentProcess || {
    pid: 3500,
    name: 'cmd.exe',
    exe_path: 'C:\\Windows\\System32\\cmd.exe',
  };

  useEffect(() => {
    if (!incident?.agentId) return;
    setLoading(true);
    api.get(`/process/${incident.agentId}/tree`)
      .then((data) => setTreeData(data))
      .catch((err) => {
        console.warn('Failed to load process tree:', err);
        setTreeData(null);
      })
      .finally(() => setLoading(false));
  }, [incident?.agentId]);

  // Construct ancestry chain: Grandparent -> Parent -> Culprit -> Children
  const ancestryChain = [
    {
      level: 'Grandparent',
      name: 'explorer.exe',
      pid: 1804,
      path: 'C:\\Windows\\explorer.exe',
      role: 'normal',
    },
    {
      level: 'Parent Process',
      name: parent.name || 'cmd.exe',
      pid: parent.pid || 3500,
      path: parent.exe_path || 'C:\\Windows\\System32\\cmd.exe',
      role: 'parent',
    },
    {
      level: 'Malicious Culprit',
      name: culprit.name || 'key_test.exe',
      pid: culprit.pid || 4128,
      path: culprit.exe_path || 'C:\\Users\\AppData\\Local\\Temp\\key_test.exe',
      cmdline: culprit.cmdline,
      role: 'culprit',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Controls & Status */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Mini Process Ancestry Tree
          </h4>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
            Trace 3-level execution lineage from parent launcher down to culprit process
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button
            variant="warning"
            size="sm"
            disabled={actionLoading || !culprit.pid}
            iconLeft={<FiSlash size={13} />}
            onClick={() => onAction && onAction('kill_process_tree', { pid: culprit.pid, process_name: culprit.name })}
          >
            Kill Process (PID {culprit.pid})
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={actionLoading || !culprit.pid}
            iconLeft={<FiLayers size={13} />}
            onClick={() => onAction && onAction('kill_process_tree', { pid: culprit.pid, process_name: culprit.name })}
          >
            Kill Full Tree
          </Button>
        </div>
      </div>

      {/* Mini Visual Process Tree */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {ancestryChain.map((node, index) => {
            const isCulprit = node.role === 'culprit';
            const isParent = node.role === 'parent';

            return (
              <div
                key={node.pid}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  marginLeft: `${index * 1.75}rem`,
                  position: 'relative',
                }}
              >
                {/* Connector line for child levels */}
                {index > 0 && (
                  <FiCornerDownRight
                    size={16}
                    style={{
                      color: isCulprit ? 'var(--error)' : 'var(--text-tertiary)',
                      flexShrink: 0,
                    }}
                  />
                )}

                {/* Node Box */}
                <div
                  style={{
                    flex: 1,
                    maxWidth: '560px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.65rem 1rem',
                    background: isCulprit
                      ? 'rgba(239, 68, 68, 0.12)'
                      : isParent
                      ? 'rgba(245, 158, 11, 0.08)'
                      : 'var(--bg-tertiary)',
                    border: `1.5px solid ${
                      isCulprit ? 'var(--error)' : isParent ? 'var(--warning)' : 'var(--border)'
                    }`,
                    borderRadius: 'var(--radius-sm)',
                    boxShadow: isCulprit ? '0 0 12px rgba(239, 68, 68, 0.2)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <FiTerminal
                      size={15}
                      style={{
                        color: isCulprit ? 'var(--error)' : isParent ? 'var(--warning)' : 'var(--text-secondary)',
                      }}
                    />
                    <div>
                      <span style={{ fontWeight: 700, fontSize: '0.9rem', color: isCulprit ? 'var(--error)' : 'var(--text-primary)' }}>
                        {node.name}
                      </span>
                      <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginLeft: '0.5rem' }}>
                        PID: <strong>{node.pid}</strong>
                      </span>
                    </div>
                  </div>

                  <div>
                    {isCulprit ? (
                      <span
                        style={{
                          background: 'var(--error)',
                          color: '#fff',
                          fontSize: '0.68rem',
                          fontWeight: 800,
                          padding: '0.15rem 0.45rem',
                          borderRadius: 'var(--radius-xs)',
                          letterSpacing: '0.05em',
                        }}
                      >
                        CULPRIT
                      </span>
                    ) : isParent ? (
                      <span
                        style={{
                          background: 'rgba(245, 158, 11, 0.2)',
                          color: 'var(--warning)',
                          border: '1px solid var(--warning)',
                          fontSize: '0.68rem',
                          fontWeight: 700,
                          padding: '0.1rem 0.4rem',
                          borderRadius: 'var(--radius-xs)',
                        }}
                      >
                        PARENT
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>ROOT</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Culprit Forensic Details Card */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '1rem 1.25rem',
        }}
      >
        <h5 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
          Culprit Binary Forensics & Indicators
        </h5>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.75rem', fontSize: '0.85rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Executable Full Path</span>
            <code style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
              {culprit.exe_path || 'C:\\Users\\AppData\\Local\\Temp\\key_test.exe'}
            </code>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Commandline Execution</span>
            <code style={{ color: 'var(--warning)', wordBreak: 'break-all' }}>
              {culprit.cmdline || `${culprit.name} --hidden`}
            </code>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>SHA256 File Hash</span>
            <code style={{ color: 'var(--primary)', wordBreak: 'break-all', fontSize: '0.78rem' }}>
              {culprit.sha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
            </code>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Digital Signature & Status</span>
            <span style={{ color: 'var(--error)', fontWeight: 600 }}>
              Unsigned (Untrusted Developer Certificate)
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
