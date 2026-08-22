// src/pages/Commands.jsx
import React, { useState, useMemo } from 'react';
import useCommands from '../hooks/useCommands';
import { useAgents } from '../hooks/useAgents';
import Badge from '../components/ui/Badge';
import FilterTabs from '../components/ui/FilterTabs';
import SearchBar from '../components/ui/SearchBar';
import Pagination from '../components/ui/Pagination';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import Dropdown from '../components/ui/Dropdown';
import { FiTerminal, FiRotateCw, FiPlusCircle, FiEye, FiCheckCircle, FiXCircle } from 'react-icons/fi';

const PAGE_SIZE = 8;

const STATUS_TABS = [
  { value: 'all', label: 'All' },
  { value: 'pending', label: 'Pending' },
  { value: 'executing', label: 'Executing' },
  { value: 'success', label: 'Success' },
  { value: 'failed', label: 'Failed' },
];

const COMMAND_OPTIONS = [
  { value: 'isolate_agent', label: 'Isolate Agent (Network Isolation)' },
  { value: 'unisolate_agent', label: 'Unisolate Agent (Restore Network)' },
  { value: 'update_firewall_rule', label: 'Update Firewall Rule (eBPF)' },
  { value: 'collect_sys_logs', label: 'Collect System Logs' },
  { value: 'execute_script', label: 'Execute Shell Script' },
];

export default function Commands() {
  const { commands, loading, handleCreateCommand, handleRetryCommand, refreshCommands } = useCommands();
  const { agents } = useAgents();

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);
  const [selectedCommand, setSelectedCommand] = useState(null);
  const [isDispatchModalOpen, setIsDispatchModalOpen] = useState(false);

  // Form State
  const [targetAgent, setTargetAgent] = useState('');
  const [commandType, setCommandType] = useState('isolate_agent');
  const [paramsInput, setParamsInput] = useState('{"reason": "Manual dispatch"}');

  const agentOptions = useMemo(() => {
    const list = agents.map((a) => ({
      value: a.id,
      label: `${a.name || a.hostname} (${a.ip || a.ip_address})`,
    }));
    return [{ value: 'ALL', label: 'ALL AGENTS (Broadcast)' }, ...list];
  }, [agents]);

  const filteredCommands = useMemo(() => {
    return commands.filter((cmd) => {
      const matchStatus = statusFilter === 'all' || cmd.status.toLowerCase() === statusFilter;
      const matchSearch =
        !search ||
        cmd.id.toLowerCase().includes(search.toLowerCase()) ||
        cmd.agentId.toLowerCase().includes(search.toLowerCase()) ||
        cmd.command.toLowerCase().includes(search.toLowerCase());
      return matchStatus && matchSearch;
    });
  }, [commands, search, statusFilter]);

  const totalPages = Math.ceil(filteredCommands.length / PAGE_SIZE) || 1;
  const paginated = filteredCommands.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const tabsWithCount = STATUS_TABS.map((t) => ({
    ...t,
    count: t.value === 'all' ? commands.length : commands.filter((c) => c.status.toLowerCase() === t.value).length,
  }));

  const pendingCount = commands.filter((c) => c.status === 'PENDING').length;
  const executingCount = commands.filter((c) => c.status === 'EXECUTING').length;
  const successCount = commands.filter((c) => c.status === 'SUCCESS').length;
  const failedCount = commands.filter((c) => c.status === 'FAILED').length;

  const onDispatchSubmit = async (e) => {
    e.preventDefault();
    let parsedParams = {};
    try {
      parsedParams = JSON.parse(paramsInput);
    } catch (err) {
      parsedParams = { raw: paramsInput };
    }

    await handleCreateCommand({
      agent_id: targetAgent || (agentOptions[0]?.value || 'ALL'),
      command: commandType,
      parameters: parsedParams,
    });

    setIsDispatchModalOpen(false);
    setParamsInput('{"reason": "Manual dispatch"}');
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Command Dispatch & Audit Log</h1>
        </div>
        <div className="card skeleton" style={{ height: '400px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Command Dispatch & Audit Log</h1>
          <p className="page-subtitle">Dispatch active response actions and monitor execution state across LAN agents</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshCommands}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlusCircle size={15} />} onClick={() => setIsDispatchModalOpen(true)}>
            Dispatch Command
          </Button>
        </div>
      </div>

      {/* KPI Header */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Total Dispatched</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
            {commands.length}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Pending / Executing</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--warning)', marginTop: '0.2rem' }}>
            {pendingCount + executingCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Success</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--success)', marginTop: '0.2rem' }}>
            {successCount}
          </div>
        </div>

        <div className="card" style={{ padding: '1rem 1.25rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Failed</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--error)', marginTop: '0.2rem' }}>
            {failedCount}
          </div>
        </div>
      </div>

      {/* Table Card */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <FilterTabs tabs={tabsWithCount} active={statusFilter} onChange={(v) => { setStatusFilter(v); setPage(1); }} />
          <div style={{ marginLeft: 'auto' }}>
            <SearchBar value={search} onChange={(v) => { setSearch(v); setPage(1); }} placeholder="Search commands..." style={{ width: 240 }} />
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.85rem 1.25rem' }}>Command ID</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Target Agent</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Action / Command</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Parameters</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Status</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Executed At</th>
                <th style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No commands found
                  </td>
                </tr>
              ) : (
                paginated.map((cmd) => (
                  <tr key={cmd.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600, color: 'var(--primary)' }}>
                      {cmd.id}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 500 }}>
                      {cmd.agentId}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {cmd.command}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {cmd.parameters}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <Badge
                        status={
                          cmd.status === 'SUCCESS' ? 'online' : cmd.status === 'FAILED' ? 'critical' : 'warning'
                        }
                        label={cmd.status}
                      />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                      {cmd.executedAt ? new Date(cmd.executedAt).toLocaleString() : 'Pending'}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                        <Button variant="ghost" size="sm" iconLeft={<FiEye size={14} />} onClick={() => setSelectedCommand(cmd)}>
                          View
                        </Button>
                        {cmd.status === 'FAILED' && (
                          <Button variant="outline" size="sm" iconLeft={<FiRotateCw size={14} />} onClick={() => handleRetryCommand(cmd.id)}>
                            Retry
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div style={{ padding: '1rem 1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Showing {Math.min((page - 1) * PAGE_SIZE + 1, filteredCommands.length)}–{Math.min(page * PAGE_SIZE, filteredCommands.length)} of {filteredCommands.length}
          </span>
          <Pagination current={page} total={totalPages} onChange={setPage} />
        </div>
      </div>

      {/* View Detail Modal */}
      <Modal isOpen={!!selectedCommand} onClose={() => setSelectedCommand(null)} title="Command Detail">
        {selectedCommand && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {[
              ['Command ID', selectedCommand.id],
              ['Agent ID', selectedCommand.agentId],
              ['Command Name', selectedCommand.command],
              ['Parameters', selectedCommand.parameters],
              ['Execution Status', selectedCommand.status],
              ['Result Output', selectedCommand.result || 'No output recorded'],
              ['Created At', new Date(selectedCommand.createdAt).toLocaleString()],
              ['Executed At', selectedCommand.executedAt ? new Date(selectedCommand.executedAt).toLocaleString() : 'N/A'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{k}</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)', maxWidth: '60%', textAlign: 'right', fontFamily: k === 'Parameters' || k === 'Result Output' ? 'monospace' : 'inherit' }}>
                  {v}
                </span>
              </div>
            ))}
          </div>
        )}
      </Modal>

      {/* Dispatch New Command Modal */}
      <Modal isOpen={isDispatchModalOpen} onClose={() => setIsDispatchModalOpen(false)} title="Dispatch Action Command">
        <form onSubmit={onDispatchSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Dropdown
            label="Target Agent"
            options={agentOptions}
            value={targetAgent || (agentOptions[0]?.value || 'ALL')}
            onChange={setTargetAgent}
          />

          <Dropdown
            label="Command Action"
            options={COMMAND_OPTIONS}
            value={commandType}
            onChange={setCommandType}
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
              Parameters (JSON string)
            </label>
            <textarea
              rows={4}
              value={paramsInput}
              onChange={(e) => setParamsInput(e.target.value)}
              style={{
                width: '100%',
                padding: '0.65rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontFamily: 'monospace',
                fontSize: '0.85rem',
              }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" onClick={() => setIsDispatchModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" iconLeft={<FiTerminal size={15} />}>
              Dispatch Command
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
