import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import Button from '../components/ui/Button';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import DockerMonitorTable from '../components/ui/DockerMonitorTable';
import HealthScoreGauge from '../components/dashboard/HealthScoreGauge';
import RecentThreats from '../components/dashboard/RecentThreats';
import ErrorState from '../components/ui/ErrorState';
import { SkeletonCard } from '../components/ui/Skeleton';
import { getAgents } from '../api/agents';
import { getIncidents } from '../api/incidents';
import { getEvents } from '../api/events';
import { getDockerStatus } from '../api/docker';
import { useDashboardSocket } from '../hooks/useDashboardSocket';
import { FiZap, FiRadio, FiShield } from 'react-icons/fi';

function FalsePositiveBanner() {
    const [fpData, setFpData] = useState(null);

    useEffect(() => {
        let mounted = true;
        async function check() {
            try {
                const res = await fetch('/api/v1/risk/verify-phase2');
                if (!res.ok) return;
                const data = await res.json();
                if (mounted) setFpData(data);
            } catch (err) {
                // ignore
            }
        }
        check();
        const interval = setInterval(check, 15000);
        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, []);

    if (!fpData) return null;

    const hasManagerFP = !fpData.manager_ip_bypassed;
    const hasIdleFP = !fpData.idle_agents_safe;

    if (!hasManagerFP && !hasIdleFP) {
        return null; // Không có FP -> tự động ẩn!
    }

    return (
        <div
            style={{
                backgroundColor: '#fef2f2',
                borderLeft: '4px solid #ef4444',
                padding: '12px 16px',
                marginBottom: '16px',
                borderRadius: '6px',
                boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
            }}
        >
            <div style={{ fontWeight: 700, color: '#991b1b', display: 'flex', alignItems: 'center', gap: '6px' }}>
                ⚠️ Cảnh báo: Phát hiện False Positive trong hệ thống chấm điểm rủi ro
            </div>
            <ul style={{ fontSize: '13px', color: '#b91c1c', marginTop: '4px', paddingLeft: '20px' }}>
                {hasManagerFP && (
                    <li>• {fpData.details?.manager_ip_records ?? 0} bản ghi nhận diện nhầm kết nối Manager (172.19.0.3) là C2 Beaconing</li>
                )}
                {hasIdleFP && (
                    <li>• Agent nhàn rỗi có điểm rủi ro bất thường (Max score: {fpData.details?.max_idle_score ?? 0})</li>
                )}
            </ul>
        </div>
    );
}

export default function Dashboard() {
    const navigate = useNavigate();
    const [agents, setAgents] = useState([]);
    const [incidents, setIncidents] = useState([]);
    const [events, setEvents] = useState([]);
    const [dockerContainers, setDockerContainers] = useState([]);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const [selectedAgent, setSelectedAgent] = useState(null);

    const loadData = useCallback(async () => {
        try {
            const [agentsData, incidentsData, eventsData, dockerData] = await Promise.all([
                getAgents(),
                getIncidents(),
                getEvents(),
                getDockerStatus().catch(() => []),
            ]);

            setAgents(Array.isArray(agentsData) ? agentsData : []);
            setIncidents(Array.isArray(incidentsData) ? incidentsData : []);
            setEvents(Array.isArray(eventsData) ? eventsData : []);
            setDockerContainers(Array.isArray(dockerData) ? dockerData : []);
            setError(null);
        } catch (err) {
            console.error('[Dashboard] loadData error:', err);
            // If we don't have data yet, show error state
            setError(err);
        } finally {
            setLoading(false);
        }
    }, []);

    // Initial load + Real-time polling every 2s (P0.1)
    useEffect(() => {
        loadData();
        const interval = setInterval(loadData, 2000);
        return () => clearInterval(interval);
    }, [loadData]);

    const handleSocketMessage = useCallback((msg) => {
        const evt = msg.event || msg.type;
        if (evt === 'heartbeat' || evt === 'dead_agent' || evt === 'TELEMETRY_RISK' || evt === 'INCIDENT_CREATED') {
            loadData();
        }
    }, [loadData]);

    const { isConnected } = useDashboardSocket(handleSocketMessage);

    if (error) {
        return (
            <ErrorState
                title="Không thể kết nối Manager"
                message={`${error.message || 'Lỗi mạng'}. Kiểm tra backend tại http://localhost:8005`}
                onRetry={loadData}
            />
        );
    }

    const totalOnline = agents.filter((a) => a.status === 'online' || a.status === 'active' || a.status === 'ACTIVE').length;
    const alertsToday = events.filter((e) => new Date(e.timestamp).toDateString() === new Date().toDateString()).length;
    const blockedIps = events.filter((e) => e.type === 'block_ip').length;
    const isolatedAgents = agents.filter((a) => a.status === 'isolated' || a.is_isolated).length;

    return (
        <div>
            <FalsePositiveBanner />
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

            {/* Health Score Gauge (P0.2 & Fix #1 Context) */}
            {loading ? <SkeletonCard /> : <HealthScoreGauge agents={agents} incidents={incidents} loading={loading} />}

            {/* KPI Cards */}
            <div className="grid-4" style={{ marginBottom: '1.25rem' }}>
                <KpiCard type="agents" label="Agents Online" value={`${totalOnline}/${agents.length || 0}`} trendValue={12} />
                <KpiCard type="alerts" label="Alerts Today" value={alertsToday} trendValue={-5} />
                <KpiCard type="blocked" label="IPs Blocked" value={blockedIps} trendValue={-2} />
                <KpiCard icon={<FiShield size={20} />} label="Isolated Agents" color="var(--warning)" value={isolatedAgents} trendValue={0} />
            </div>

            {/* Middle Grid: Agents Table + Recent Threats (Fix #2) */}
            <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
                <AgentTable agents={agents} onViewAgent={setSelectedAgent} />
                <RecentThreats incidents={incidents} agents={agents} />
            </div>

            {/* Docker Infrastructure Status */}
            <div style={{ marginBottom: '1.25rem' }}>
                <DockerMonitorTable
                    containers={dockerContainers}
                    loading={loading}
                    error={null}
                    onRefresh={loadData}
                />
            </div>

            {/* Full-width Recent Alerts (Fix #3 - RiskGauge removed) */}
            <div style={{ marginBottom: '1.25rem' }}>
                <RecentAlerts events={events} />
            </div>

            {selectedAgent && <AgentDetailModal agent={selectedAgent} onClose={() => setSelectedAgent(null)} />}
        </div>
    );
}