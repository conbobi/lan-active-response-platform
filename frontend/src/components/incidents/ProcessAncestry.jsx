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
  FiAlertTriangle,
  FiRefreshCw
} from 'react-icons/fi';

export default function ProcessAncestry({
  incident,
  onAction,
  actionLoading,
}) {
  const [incData, setIncData] = useState(incident);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (incident?.id) {
      if (!incident.culpritProcess && !incident.culprit_process && !incident.parentProcess && !incident.parent_process) {
        setLoading(true);
        api.get(`/incidents/${incident.id}`)
          .then((res) => {
            if (res) {
              setIncData(res);
            }
          })
          .catch((err) => {
            console.warn('Failed to load incident detail for ancestry:', err);
          })
          .finally(() => setLoading(false));
      } else {
        setIncData(incident);
      }
    }
  }, [incident]);

  const culprit = incData?.culpritProcess || incData?.culprit_process || null;
  const parent = incData?.parentProcess || incData?.parent_process || null;

  if (!culprit && !parent) {
    return (
      <div
        className="empty-state"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '2.5rem',
          background: 'var(--bg-secondary)',
          border: '1px dashed var(--border)',
          borderRadius: 'var(--radius-md)',
          color: 'var(--text-tertiary)',
          fontSize: '0.9rem',
          textAlign: 'center',
        }}
      >
        <FiAlertTriangle size={24} style={{ marginBottom: '0.5rem', color: 'var(--warning)' }} />
        <span>Chưa có dữ liệu process tree</span>
      </div>
    );
  }

  // Construct dynamic ancestry chain from available culprit and parent data
  const ancestryChain = [];
  if (parent) {
    ancestryChain.push({
      level: 'Parent Process',
      name: parent.name || parent.process_name || 'parent',
      pid: parent.pid || 'N/A',
      path: parent.exe_path || parent.exe || parent.path || '',
      cmdline: parent.cmdline || '',
      role: 'parent',
    });
  }

  if (culprit) {
    ancestryChain.push({
      level: 'Malicious Culprit',
      name: culprit.name || culprit.process_name || 'culprit',
      pid: culprit.pid || 'N/A',
      path: culprit.exe_path || culprit.exe || culprit.path || '',
      cmdline: culprit.cmdline || '',
      sha256: culprit.sha256 || '',
      role: 'culprit',
    });
  }

  const culpritPid = culprit?.pid;
  const culpritName = culprit?.name || culprit?.process_name || 'process';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Top Controls & Status */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Process Ancestry Tree
          </h4>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
            Trace execution lineage from parent launcher down to culprit process
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button
            variant="warning"
            size="sm"
            disabled={actionLoading || !culpritPid}
            iconLeft={<FiSlash size={13} />}
            onClick={() => onAction && onAction('kill_process_tree', { pid: culpritPid, process_name: culpritName })}
          >
            Kill Process {culpritPid ? `(PID ${culpritPid})` : ''}
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={actionLoading || !culpritPid}
            iconLeft={<FiLayers size={13} />}
            onClick={() => onAction && onAction('kill_process_tree', { pid: culpritPid, process_name: culpritName })}
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
                key={node.pid || index}
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
                      {node.pid && node.pid !== 'N/A' && (
                        <span style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', marginLeft: '0.5rem' }}>
                          PID: <strong>{node.pid}</strong>
                        </span>
                      )}
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
                    ) : (
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
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Culprit Forensic Details Card */}
      {culprit && (
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
                {culprit.exe_path || culprit.exe || culprit.path || 'N/A'}
              </code>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
              <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Commandline Execution</span>
              <code style={{ color: 'var(--warning)', wordBreak: 'break-all' }}>
                {culprit.cmdline || 'N/A'}
              </code>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
              <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>SHA256 File Hash</span>
              <code style={{ color: 'var(--primary)', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                {culprit.sha256 || 'N/A'}
              </code>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
              <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>Digital Signature & Status</span>
              <span style={{ color: culprit.is_suspicious ? 'var(--error)' : 'var(--text-secondary)', fontWeight: 600 }}>
                {culprit.is_suspicious ? 'Unsigned / Untrusted' : 'Standard Process'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
