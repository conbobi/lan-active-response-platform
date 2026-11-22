import { useState } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler } from 'chart.js';
import { useAgentHistory } from '../../hooks/useAgentHistory';
import useActions from '../../hooks/useActions';
import ActionTimeline from '../actions/ActionTimeline';
import AgentSecurityContext from '../agents/AgentSecurityContext';
import NetworkFirewallTab from '../agents/NetworkFirewallTab';
import Badge from './Badge';
import { FiX, FiCpu, FiHardDrive, FiShield, FiGlobe, FiTrash2 } from 'react-icons/fi';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler);

const TABS = ['Overview', '🚨 Active Threats', 'CPU/RAM', 'Info', 'Network & Firewall', 'Mitigations'];

export default function AgentDetailModal({ agent, onClose, onDeleteAgent, initialTab = 'Overview' }) {
    const { history, loading } = useAgentHistory(agent?.id);
    const {
        actions,
        loading: loadingActions,
        actionLoading,
        handleUndo,
        handleUndoAll,
    } = useActions({ agentId: agent?.id });
    const [tab, setTab] = useState(initialTab);
    if (!agent) return null;

    const isDead = ['dead', 'offline', 'inactive'].includes(String(agent.status || '').toLowerCase());

    const labels = history.map((h) => new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    const mkDataset = (label, data, color) => ({
        label, data,
        borderColor: color, backgroundColor: color.replace(')', ', 0.1)').replace('rgb', 'rgba'),
        tension: 0.4, fill: true, pointRadius: 3,
    });
    const chartOpts = { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100, grid: { color: 'var(--border)' } }, x: { grid: { display: false } } }, plugins: { legend: { display: false } } };

    return (
        <div className="modal-overlay" onClick={(e) => { if (e.target.classList.contains('modal-overlay')) onClose(); }}>
            <div className="modal-box" style={{ maxWidth: tab === 'Network & Firewall' ? 1240 : 680 }}>
                <div className="modal-header">
                    <div>
                        <h3 className="modal-title">{agent.hostname}</h3>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: 2 }}>{agent.ip}</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <Badge status={agent.status} />
                        {isDead && onDeleteAgent && (
                            <button
                                style={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.3rem',
                                    padding: '0.25rem 0.55rem',
                                    fontSize: '0.75rem',
                                    fontWeight: 600,
                                    color: 'var(--error)',
                                    background: 'rgba(239, 68, 68, 0.1)',
                                    border: '1px solid rgba(239, 68, 68, 0.3)',
                                    borderRadius: 'var(--radius-sm)',
                                    cursor: 'pointer',
                                }}
                                onClick={() => {
                                    onDeleteAgent(agent.id, agent.hostname);
                                    onClose();
                                }}
                                title="Gỡ bỏ agent offline này khỏi hệ thống"
                            >
                                <FiTrash2 size={13} /> Gỡ bỏ
                            </button>
                        )}
                        <button className="modal-close" onClick={onClose}><FiX size={16} /></button>
                    </div>
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', padding: '0.75rem 1.5rem', borderBottom: '1px solid var(--border)' }}>
                    {TABS.map((t) => (
                        <button key={t} onClick={() => setTab(t)}
                            className={`filter-tab ${tab === t ? 'active' : ''}`} style={{ borderRadius: 'var(--radius-sm)', padding: '0.3rem 0.75rem' }}>
                            {t}
                        </button>
                    ))}
                </div>

                <div className="modal-body">
                    {tab === 'Overview' && (
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                            {[
                                { icon: <FiCpu size={16} />, label: 'CPU', value: `${agent.cpu}%`, color: agent.cpu > 80 ? 'var(--error)' : 'var(--success)' },
                                { icon: <FiHardDrive size={16} />, label: 'RAM', value: `${agent.ram}%`, color: agent.ram > 80 ? 'var(--error)' : 'var(--primary)' },
                                { icon: <FiShield size={16} />, label: 'Firewall', value: 'View firewall status', color: 'var(--primary)', action: () => setTab('Network & Firewall') },
                                { icon: <FiGlobe size={16} />, label: 'Disk', value: `${agent.disk}%`, color: agent.disk > 90 ? 'var(--error)' : 'var(--warning)' },
                            ].map(({ icon, label, value, color, action }) => (
                                <div key={label} style={{ background: 'var(--bg)', borderRadius: 'var(--radius-md)', padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                    <div style={{ color, background: `${color}18`, borderRadius: 'var(--radius-sm)', width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{icon}</div>
                                    <div>
                                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{label}</div>
                                        {action ? <button type="button" className="filter-tab" onClick={action}>{value}</button> :
                                            <div style={{ fontWeight: 700, color, fontSize: '1.1rem' }}>{value}</div>}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                    {tab === '🚨 Active Threats' && (
                        <AgentSecurityContext agent={agent} />
                    )}
                    {tab === 'CPU/RAM' && (
                        loading ? <p style={{ color: 'var(--text-secondary)' }}>Loading...</p> : (
                            <>
                                <div style={{ marginBottom: '0.5rem', fontWeight: 600, fontSize: '0.85rem' }}>CPU History</div>
                                <div style={{ height: 160, marginBottom: '1rem' }}>
                                    <Line data={{ labels, datasets: [mkDataset('CPU %', history.map((h) => h.cpu), '#6100ff')] }} options={chartOpts} />
                                </div>
                                <div style={{ marginBottom: '0.5rem', fontWeight: 600, fontSize: '0.85rem' }}>RAM History</div>
                                <div style={{ height: 160 }}>
                                    <Line data={{ labels, datasets: [mkDataset('RAM %', history.map((h) => h.ram), '#3b82f6')] }} options={chartOpts} />
                                </div>
                            </>
                        )
                    )}
                    {tab === 'Info' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            {[['Agent ID', agent.id], ['Hostname', agent.hostname], ['IP Address', agent.ip], ['Status', agent.status]].map(([k, v]) => (
                                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.6rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>{k}</span>
                                    <span style={{ fontWeight: 500 }}>{v}</span>
                                </div>
                            ))}
                        </div>
                    )}
                    {tab === 'Network & Firewall' && <NetworkFirewallTab key={agent.id} agent={agent} />}
                    {tab === 'Mitigations' && (
                        <ActionTimeline
                            actions={actions}
                            onUndo={handleUndo}
                            onUndoAll={handleUndoAll}
                            loading={loadingActions}
                            actionLoading={actionLoading}
                        />
                    )}
                </div>
            </div>
        </div>
    );
}