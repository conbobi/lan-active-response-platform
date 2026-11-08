import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import Button from '../components/ui/Button';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import HealthScoreGauge from '../components/dashboard/HealthScoreGauge';
import RecentThreats from '../components/dashboard/RecentThreats';
import ErrorState from '../components/ui/ErrorState';
import { SkeletonCard } from '../components/ui/Skeleton';
import { getAgents, isolateAgent } from '../api/agents';
import { getIncidents } from '../api/incidents';
import { getEvents } from '../api/events';
import { useDashboardSocket } from '../hooks/useDashboardSocket';
import { FiRadio, FiShield, FiAlertTriangle, FiRotateCw, FiTerminal, FiEye } from 'react-icons/fi';

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
        return null;
    }

    return (
        <div
            style={{
                backgroundColor: 'var(--error-dim)',
                borderLeft: '4px solid var(--error)',
                borderTop: '1px solid rgba(248, 81, 73, 0.25)',
                borderRight: '1px solid rgba(248, 81, 73, 0.25)',
                borderBottom: '1px solid rgba(248, 81, 73, 0.25)',
                padding: '12px 16px',
                marginBottom: '16px',
                borderRadius: 'var(--radius-sm)',
                boxShadow: '0 0 12px var(--error-glow)'
            }}
        >
            <div style={{ fontWeight: 700, color: 'var(--error)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                ⚠️ Cảnh báo: Phát hiện False Positive trong hệ thống chấm điểm rủi ro
            </div>
            <ul style={{ fontSize: '13px', color: 'var(--text-primary)', marginTop: '4px', paddingLeft: '20px' }}>
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
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [isolatingId, setIsolatingId] = useState(null);

    const loadData = useCallback(async () => {
        try {
            const [agentsData, incidentsData, eventsData] = await Promise.all([
                getAgents(),
                getIncidents(),
                getEvents(),
            ]);

            setAgents(Array.isArray(agentsData) ? agentsData : []);
            setIncidents(Array.isArray(incidentsData) ? incidentsData : []);
            setEvents(Array.isArray(eventsData) ? eventsData : []);
            setError(null);
        } catch (err) {
            console.error('[Dashboard] loadData error:', err);
            setError(err);
        } finally {
            setLoading(false);
        }
    }, []);

    // Initial load + Real-time polling every 3s
    useEffect(() => {
        loadData();
        const interval = setInterval(loadData, 3000);
        return () => clearInterval(interval);
    }, [loadData]);

    const handleSocketMessage = useCallback((msg) => {
        const evt = msg.event || msg.type;
        if (
            evt === 'heartbeat' ||
            evt === 'dead_agent' ||
            evt === 'TELEMETRY_RISK' ||
            evt === 'INCIDENT_CREATED' ||
            evt === 'INCIDENT_RESOLVED' ||
            evt === 'INCIDENTS_RESOLVED' ||
            evt === 'AGENT_UNISOLATED' ||
            evt === 'INCIDENT_STATUS_CHANGED'
        ) {
            loadData();
        }
    }, [loadData]);

    const { isConnected } = useDashboardSocket(handleSocketMessage);

    // Urgent active incident for top banner triage (only un-resolved, high/critical, within 24h)
    const criticalActiveIncident = useMemo(() => {
        const now = Date.now();
        const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
        return incidents.find((i) => {
            const st = String(i.status || '').toLowerCase();
            const isResolved = ['resolved', 'false_positive', 'reverted', 'closed'].includes(st);
            if (isResolved) return false;

            const isActive = ['open', 'investigating', 'contained', 'new'].includes(st);
            if (!isActive) return false;

            const score = Number(i.risk_score ?? i.riskScore ?? 0);
            const isCriticalRisk = score >= 70 || i.severity === 'critical' || i.severity === 'high';
            if (!isCriticalRisk) return false;

            // Only consider incidents within 24 hours
            const createdAt = new Date(i.created_at || i.createdAt || 0).getTime();
            if (!isNaN(createdAt) && (now - createdAt) > MAX_AGE_MS) {
                return false;
            }

            return true;
        });
    }, [incidents]);

    const handleQuickIsolate = async (agentId) => {
        if (!agentId) return;
        if (!window.confirm(`Xác nhận cô lập khẩn cấp host ${agentId}? Tất cả kết nối mạng ngoại trừ LARP Server sẽ bị ngắt lập tức.`)) {
            return;
        }
        setIsolatingId(agentId);
        try {
            await isolateAgent(agentId);
            toast.success(`Đã phát lệnh cô lập agent ${agentId} thành công!`);
            loadData();
        } catch (err) {
            toast.error(`Cô lập thất bại: ${err.message || 'Lỗi mạng'}`);
        } finally {
            setIsolatingId(null);
        }
    };

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
    const unresolvedIncidents = incidents.filter((i) => {
        const st = String(i.status || '').toLowerCase();
        return !['resolved', 'closed', 'false_positive'].includes(st);
    }).length;

    return (
        <div>
            <FalsePositiveBanner />

            {/* Zone 0: Urgent Critical Threat Banner OR All Clear Banner */}
            {criticalActiveIncident ? (
                <div
                    style={{
                        background: 'linear-gradient(90deg, rgba(239, 68, 68, 0.2) 0%, rgba(17, 24, 39, 0.95) 100%)',
                        border: '1px solid var(--error)',
                        borderLeft: '5px solid var(--error)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '1rem 1.25rem',
                        marginBottom: '1.25rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '1rem',
                        flexWrap: 'wrap',
                        boxShadow: '0 0 16px rgba(239, 68, 68, 0.25)',
                    }}
                >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                        <div
                            style={{
                                width: 36,
                                height: 36,
                                borderRadius: '50%',
                                background: 'rgba(239, 68, 68, 0.2)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'var(--error)',
                                flexShrink: 0,
                            }}
                        >
                            <FiAlertTriangle size={20} />
                        </div>
                        <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                <span style={{ fontWeight: 800, color: 'var(--error)', fontSize: '0.95rem', letterSpacing: '0.02em' }}>
                                    🔴 CRITICAL THREAT ACTIVE: {criticalActiveIncident.title || 'LOLBin Reverse Shell / C2'}
                                </span>
                                <span style={{
                                    fontSize: '0.75rem',
                                    fontWeight: 700,
                                    padding: '0.1rem 0.5rem',
                                    borderRadius: '999px',
                                    background: 'var(--error)',
                                    color: '#fff',
                                }}>
                                    SCORE {Math.round(criticalActiveIncident.risk_score ?? criticalActiveIncident.riskScore ?? 100)}/100
                                </span>
                            </div>
                            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                                Target Host: <strong style={{ color: 'var(--text-primary)' }}>{criticalActiveIncident.agent_id || criticalActiveIncident.agentId || 'Unknown Host'}</strong>
                                {(criticalActiveIncident.culprit_process?.name || criticalActiveIncident.culpritProcess?.name) && (
                                    <span> • Culprit: <code style={{ color: 'var(--text-primary)' }}>{criticalActiveIncident.culprit_process?.name || criticalActiveIncident.culpritProcess?.name}</code> (PID {criticalActiveIncident.culprit_process?.pid || criticalActiveIncident.culpritProcess?.pid || '—'})</span>
                                )}
                            </div>
                        </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                        <Button
                            variant="primary"
                            size="sm"
                            iconLeft={<FiShield size={14} />}
                            disabled={isolatingId === (criticalActiveIncident.agent_id || criticalActiveIncident.agentId)}
                            onClick={() => handleQuickIsolate(criticalActiveIncident.agent_id || criticalActiveIncident.agentId)}
                            style={{ background: 'var(--error)', borderColor: 'var(--error)', fontWeight: 700 }}
                        >
                            {isolatingId === (criticalActiveIncident.agent_id || criticalActiveIncident.agentId) ? 'Isolating...' : '1-Click Isolate Host'}
                        </Button>
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                                const targetAgent = criticalActiveIncident.agent_id || criticalActiveIncident.agentId || '';
                                const pid = criticalActiveIncident.culprit_process?.pid || criticalActiveIncident.culpritProcess?.pid || '';
                                navigate(`/investigate?tab=process${targetAgent ? `&agent=${encodeURIComponent(targetAgent)}` : ''}${pid ? `&pid=${pid}` : ''}`);
                            }}
                        >
                            🌳 View in Process Tree
                        </Button>
                        <Button
                            variant="ghost"
                            size="sm"
                            iconLeft={<FiEye size={13} />}
                            onClick={() => navigate(`/incidents?id=${criticalActiveIncident.id}`)}
                        >
                            Triage Storyline
                        </Button>
                    </div>
                </div>
            ) : (
                <div
                    style={{
                        background: 'linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(17, 24, 39, 0.7) 100%)',
                        border: '1px solid rgba(16, 185, 129, 0.3)',
                        borderLeft: '5px solid var(--success)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '0.85rem 1.25rem',
                        marginBottom: '1.25rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: '1rem',
                        flexWrap: 'wrap',
                    }}
                >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div
                            style={{
                                width: 32,
                                height: 32,
                                borderRadius: '50%',
                                background: 'rgba(16, 185, 129, 0.2)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                color: 'var(--success)',
                                flexShrink: 0,
                            }}
                        >
                            <FiShield size={18} />
                        </div>
                        <div>
                            <div style={{ fontWeight: 700, color: 'var(--success)', fontSize: '0.9rem' }}>
                                🟢 All Systems Operational — No Active Threats (Last 24h)
                            </div>
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                                Endpoint posture normal. Protection active across {totalOnline} connected {totalOnline === 1 ? 'agent' : 'agents'}.
                            </div>
                        </div>
                    </div>
                    <Button variant="ghost" size="sm" onClick={loadData} iconLeft={<FiRotateCw size={13} />}>
                        Sync Status
                    </Button>
                </div>
            )}

            {/* Header */}
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                        <h1 className="page-title">Security Operations Dashboard</h1>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', padding: '0.2rem 0.6rem', borderRadius: '12px', background: isConnected ? 'rgba(0,192,123,0.12)' : 'rgba(239,68,68,0.12)', color: isConnected ? 'var(--success)' : 'var(--error)' }}>
                            <FiRadio size={12} />
                            <span>{isConnected ? 'LIVE WS' : 'OFFLINE'}</span>
                        </div>
                    </div>
                    <p className="page-subtitle">Real-time threat monitoring, posture scoring, and active endpoint response</p>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <Button variant="outline" size="sm" iconLeft={<FiRotateCw size={13} />} onClick={loadData}>
                        Refresh
                    </Button>
                    <Button variant="primary" size="sm" iconLeft={<FiShield size={14} />} onClick={() => navigate('/incidents')}>
                        Incidents Queue ({unresolvedIncidents})
                    </Button>
                </div>
            </div>

            {/* Zone 1: Health Score Gauge Posture */}
            {loading ? <SkeletonCard /> : <HealthScoreGauge agents={agents} incidents={incidents} loading={loading} />}

            {/* KPI Cards Row (Clean, accurate values without simulated trends) */}
            <div className="grid-4" style={{ marginBottom: '1.25rem' }}>
                <KpiCard type="agents" label="Active Endpoints" value={`${totalOnline}/${agents.length || 0}`} />
                <KpiCard type="alerts" label="Telemetry Alerts Today" value={alertsToday} />
                <KpiCard type="blocked" label="Firewall Blocks Active" value={blockedIps} />
                <KpiCard icon={<FiShield size={20} />} label="Isolated Hosts" color="var(--warning)" value={isolatedAgents} />
            </div>

            {/* Middle Grid: Agents Table + Recent Threats with 1-click links */}
            <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
                <AgentTable agents={agents} onViewAgent={setSelectedAgent} />
                <RecentThreats incidents={incidents} agents={agents} />
            </div>

            {/* Full-width Recent Alerts Stream */}
            <div style={{ marginBottom: '1.25rem' }}>
                <RecentAlerts events={events} />
            </div>

            {selectedAgent && <AgentDetailModal agent={selectedAgent} onClose={() => setSelectedAgent(null)} />}
        </div>
    );
}