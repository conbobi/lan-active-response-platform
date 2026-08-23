// src/pages/Whitelist.jsx
import React, { useState, useMemo } from 'react';
import useWhitelist from '../hooks/useWhitelist';
import { useAgents } from '../hooks/useAgents';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import SearchBar from '../components/ui/SearchBar';
import { FiCheckSquare, FiPlus, FiTrash2, FiShield, FiRotateCw } from 'react-icons/fi';

export default function Whitelist() {
  const { whitelist, loading, refreshWhitelist, addWhitelistEntry, removeWhitelistEntry } = useWhitelist();
  const { agents } = useAgents();

  const [search, setSearch] = useState('');
  const [modalOpen, setModalOpen] = useState(false);

  // Form State
  const [agentId, setAgentId] = useState('');
  const [processName, setProcessName] = useState('');
  const [path, setPath] = useState('');
  const [reason, setReason] = useState('');

  const agentOptions = useMemo(() => {
    const list = agents.map((a) => ({
      value: a.id,
      label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
    }));
    return [{ value: 'GLOBAL', label: 'GLOBAL (All Agents)' }, ...list];
  }, [agents]);

  const filteredWhitelist = useMemo(() => {
    return whitelist.filter((item) => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (
        (item.agent_id && item.agent_id.toLowerCase().includes(s)) ||
        (item.process_name && item.process_name.toLowerCase().includes(s)) ||
        (item.path && item.path.toLowerCase().includes(s)) ||
        (item.reason && item.reason.toLowerCase().includes(s))
      );
    });
  }, [whitelist, search]);

  const handleAddSubmit = async (e) => {
    e.preventDefault();
    await addWhitelistEntry({
      agent_id: agentId || (agentOptions[0]?.value || 'GLOBAL'),
      process_name: processName.trim(),
      path: path.trim(),
      reason: reason.trim(),
    });

    setModalOpen(false);
    setProcessName('');
    setPath('');
    setReason('');
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Authorized Whitelist</h1>
        </div>
        <div className="card skeleton" style={{ height: '350px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Authorized Whitelist</h1>
          <p className="page-subtitle">Configure trusted processes, paths, and agents exempted from active automated response actions</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshWhitelist}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={() => setModalOpen(true)}>
            Add Whitelist Entry
          </Button>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            Total Whitelisted Rules: <strong>{whitelist.length}</strong>
          </span>
          <SearchBar value={search} onChange={setSearch} placeholder="Search whitelist..." style={{ width: 260 }} />
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.85rem 1.25rem' }}>Entry ID</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Target Agent</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Process Name</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Binary Executable Path</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Exemption Reason</th>
                <th style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredWhitelist.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No whitelist entries found
                  </td>
                </tr>
              ) : (
                filteredWhitelist.map((item) => (
                  <tr key={item.entry_id || item.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 700, color: 'var(--primary)' }}>
                      {item.entry_id || item.id}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <Badge status="info" label={item.agent_id} showDot={false} />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>
                      {item.process_name}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {item.path}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-secondary)' }}>
                      {item.reason}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                      <Button
                        variant="ghost"
                        size="sm"
                        iconLeft={<FiTrash2 size={14} />}
                        onClick={() => removeWhitelistEntry(item.entry_id || item.id)}
                      >
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Whitelist Entry Modal */}
      <Modal isOpen={modalOpen} onClose={() => setModalOpen(false)} title="Add Trusted Whitelist Entry">
        <form onSubmit={handleAddSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Dropdown
            label="Target Agent Scope"
            options={agentOptions}
            value={agentId || (agentOptions[0]?.value || 'GLOBAL')}
            onChange={setAgentId}
          />

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Process Name
            </label>
            <input
              type="text"
              placeholder="e.g. sshd, prometheus, backup_service.exe"
              value={processName}
              onChange={(e) => setProcessName(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
              }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Binary Path
            </label>
            <input
              type="text"
              placeholder="e.g. /usr/sbin/sshd or C:\Program Files\..."
              value={path}
              onChange={(e) => setPath(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontFamily: 'monospace',
              }}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Reason / Justification
            </label>
            <textarea
              rows={2}
              placeholder="Explain why this process is exempted..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
              }}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" iconLeft={<FiCheckSquare size={15} />}>
              Add Whitelist Rule
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
