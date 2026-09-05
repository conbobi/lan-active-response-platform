import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import RiskGauge from '../components/ui/RiskGauge';
import Button from '../components/ui/Button';
import LineChart from '../components/charts/LineChart';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import DockerMonitorTable from '../components/ui/DockerMonitorTable';
import { useAgents } from '../hooks/useAgents';
import { useFlows } from '../hooks/useFlows';
import { useEvents } from '../hooks/useEvents';
import { useDockerStatus } from '../hooks/useDockerStatus';
import { useDashboardSocket } from '../hooks/useDashboardSocket';
import { FiZap, FiActivity, FiRadio, FiFilter } from 'react-icons/fi';

export default function Dashboard() {
    const navigate = useNavigate();
    const { agents, refreshAgents } = useAgents();
    const [selectedFlowAgent, setSelectedFlowAgent] = useState('all');
    const { flows, loading: flowsLoading, refresh: refreshFlows } = useFlows(selectedFlowAgent);
    const { events } = useEvents();
    const {
        containers: dockerContainers,
        loading: dockerLoading,
        error: dockerError,
        refresh: refreshDocker
    } = useDockerStatus();
    const [selectedAgent, setSelectedAgent] = useState(null);

    const handleSocketMessage = useCallback((msg) => {
        console.log('[Dashboard] WS Message received:', msg);
        if (msg.event === 'heartbeat' || msg.event === 'topology_update' || msg.event === 'dead_agent') {
            if (refreshAgents) refreshAgents();
        }
    }, [refreshAgents]);

    const { isConnected } = useDashboardSocket(handleSocketMessage);

    const totalOnline = agents.filter((a) => a.status === 'online').length;
    const alertsToday = events.filter((e) => new Date(e.timestamp).toDateString() === new Date().toDateString()).length;
    const avgRisk = Math.round(events.reduce((s, e) => s + e.riskScore, 0) / (events.length || 1));
    const blockedIps = events.filter((e) => e.type === 'block_ip').length;

    // Calculate current live rates
    const latestFlow = flows.length > 0 ? flows[flows.length - 1] : null;
    const currentSyn = latestFlow ? latestFlow.syn : 0;
    const currentUdp = latestFlow ? latestFlow.udp : 0;
    const currentTotal = latestFlow ? latestFlow.total : 0;

    const chartData = {
        labels: flows.map((f) => {
            const d = new Date(f.timestamp);
            return isNaN(d.getTime())
                ? String(f.timestamp)
                : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }),
        datasets: [
            {
                label: 'SYN/s (TCP)',
                data: flows.map((f) => f.syn),
                borderColor: '#8b5cf6',
                backgroundColor: 'rgba(139, 92, 246, 0.08)',
                tension: 0.35,
                fill: true,
                pointRadius: 2.5,
                pointHoverRadius: 5
            },
            {
                label: 'UDP/s',
                data: flows.map((f) => f.udp),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.08)',
                tension: 0.35,
                fill: true,
                pointRadius: 2.5,
                pointHoverRadius: 5
            },
            {
                label: 'Total/s',
                data: flows.map((f) => f.total),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.08)',
                tension: 0.35,
                fill: false,
                pointRadius: 2.5,
                pointHoverRadius: 5,
                borderWidth: 2
            },
        ],
    };

    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    color: '#64748b',
                    font: { size: 11, weight: '600' },
                    usePointStyle: true,
                    boxWidth: 8
                }
            },
            tooltip: {
                mode: 'index',
                intersect: false,
                backgroundColor: 'rgba(15, 23, 42, 0.9)',
                titleFont: { size: 11 },
                bodyFont: { size: 11 }
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: { color: 'rgba(241, 245, 249, 0.8)' },
                ticks: { color: '#94a3b8', font: { size: 10 } }
            },
            x: {
                grid: { display: false },
                ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 6 }
            },
        },
    };

    return (
        <div>
            <div className="page-header">
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <h1 className="page-title">Security Dashboard</h1>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', padding: '0.2rem 0.6rem', borderRadius: '12px', background: isConnected ? 'rgba(0,192,123,0.12)' : 'rgba(239,68,68,0.12)', color: isConnected ? 'var(--success)' : 'var(--error)' }}>
                            <FiRadio size={12} />
                            <span>{isConnected ? 'LIVE WS' : 'OFFLINE'}</span>
                        </div>
                    </div>
                    <p className="page-subtitle">AI Agent Manager — Real-time SOC Overview</p>
                </div>
                <Button variant="danger" size="md" iconLeft={<FiZap size={14} />} onClick={() => navigate('/attack')}>
                    Launch Attack Sim
                </Button>
            </div>

            <div className="grid-4" style={{ marginBottom: '1.25rem' }}>
                <KpiCard type="agents" value={totalOnline} trendValue={12} />
                <KpiCard type="alerts" value={alertsToday} trendValue={-5} />
                <KpiCard type="risk" value={avgRisk} trendValue={8} />
                <KpiCard type="blocked" value={blockedIps} trendValue={-2} />
            </div>

            <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
                <AgentTable agents={agents} onViewAgent={setSelectedAgent} />
                
                {/* Network Traffic Card with Filter */}
                <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <FiActivity size={16} color="var(--primary)" />
                            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Network Traffic (last 5 min)</span>
                        </div>
                        
                        {/* Server & Agent Filter Selector */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <FiFilter size={12} color="var(--text-tertiary)" />
                            <select
                                value={selectedFlowAgent}
                                onChange={(e) => setSelectedFlowAgent(e.target.value)}
                                style={{
                                    padding: '0.25rem 0.6rem',
                                    border: '1px solid var(--border)',
                                    borderRadius: 'var(--radius-full)',
                                    fontSize: '0.78rem',
                                    background: 'var(--bg)',
                                    color: 'var(--text-primary)',
                                    outline: 'none',
                                    cursor: 'pointer'
                                }}
                            >
                                <option value="all">🌐 All Devices (LAN)</option>
                                <option value="manager">🖥️ Manager (Host)</option>
                                {agents.map((a) => (
                                    <option key={a.id} value={a.id}>
                                        🤖 {a.hostname || a.id}
                                    </option>
                                ))}
                            </select>
                        </div>
                    </div>

                    {/* Live Metric Badges */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem', fontSize: '0.75rem' }}>
                        <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(139, 92, 246, 0.1)', color: '#8b5cf6', fontWeight: 600 }}>
                            SYN: {currentSyn} pkts/s
                        </span>
                        <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', fontWeight: 600 }}>
                            UDP: {currentUdp} pkts/s
                        </span>
                        <span style={{ padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', fontWeight: 600 }}>
                            Total: {currentTotal} pkts/s
                        </span>
                    </div>

                    <div style={{ height: 230, position: 'relative' }}>
                        {flows && flows.length > 0 ? (
                            <LineChart data={chartData} options={chartOptions} />
                        ) : (
                            <div style={{
                                height: '100%',
                                display: 'flex',
                                flexDirection: 'column',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'var(--text-tertiary)',
                                gap: '0.5rem',
                                border: '1px dashed var(--border)',
                                borderRadius: 'var(--radius-sm)',
                                background: 'rgba(0,0,0,0.01)'
                            }}>
                                <FiActivity size={32} style={{ opacity: 0.35, color: 'var(--primary)' }} />
                                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                                    No traffic data available
                                </span>
                                <span style={{ fontSize: '0.75rem', opacity: 0.7 }}>
                                    Network flow metrics will be graphed in real-time as traffic occurs.
                                </span>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
                <DockerMonitorTable
                    containers={dockerContainers}
                    loading={dockerLoading}
                    error={dockerError}
                    onRefresh={refreshDocker}
                />
            </div>

            <div className="grid-2">
                <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                    <h3 style={{ fontWeight: 700, fontSize: '0.95rem', alignSelf: 'flex-start' }}>Risk Score</h3>
                    <RiskGauge value={avgRisk} />
                </div>
                <RecentAlerts events={events} />
            </div>

            {selectedAgent && <AgentDetailModal agent={selectedAgent} onClose={() => setSelectedAgent(null)} />}
        </div>
    );
}