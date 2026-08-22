import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import RiskGauge from '../components/ui/RiskGauge';
import Button from '../components/ui/Button';
import LineChart from '../components/charts/LineChart';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import { useAgents } from '../hooks/useAgents';
import { useFlows } from '../hooks/useFlows';
import { useEvents } from '../hooks/useEvents';
import { useDashboardSocket } from '../hooks/useDashboardSocket';
import { FiZap, FiActivity, FiRadio } from 'react-icons/fi';

export default function Dashboard() {
    const navigate = useNavigate();
    const { agents, refreshAgents } = useAgents();
    const { flows } = useFlows();
    const { events } = useEvents();
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

    const chartData = {
        labels: flows.map((f) => new Date(f.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })),
        datasets: [
            { label: 'SYN/s', data: flows.map((f) => f.syn), borderColor: '#6100ff', backgroundColor: 'rgba(97,0,255,0.08)', tension: 0.4, fill: true, pointRadius: 2 },
            { label: 'UDP/s', data: flows.map((f) => f.udp), borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.08)', tension: 0.4, fill: true, pointRadius: 2 },
            { label: 'Total/s', data: flows.map((f) => f.total), borderColor: '#00c07b', backgroundColor: 'rgba(0,192,123,0.08)', tension: 0.4, fill: false, pointRadius: 2 },
        ],
    };
    const chartOptions = {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { color: '#64748b', font: { size: 11 } } } },
        scales: {
            y: { beginAtZero: true, grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8', font: { size: 10 } } },
            x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 6 } },
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
                <div className="card">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <FiActivity size={16} color="var(--primary)" />
                        <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Network Traffic (last 5 min)</span>
                    </div>
                    <div style={{ height: 260 }}>
                        <LineChart data={chartData} options={chartOptions} />
                    </div>
                </div>
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