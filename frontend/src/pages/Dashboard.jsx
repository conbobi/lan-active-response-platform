import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
    FiRadio,
    FiRotateCw,
    FiShield,
    FiAlertOctagon,
    FiClock,
    FiCheckCircle,
    FiActivity,
    FiArrowRight
} from 'react-icons/fi';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import HealthScoreGauge from '../components/dashboard/HealthScoreGauge';
import RecentThreats from '../components/dashboard/RecentThreats';
import NetworkFindings from '../components/dashboard/NetworkFindings';
import ErrorState from '../components/ui/ErrorState';
import { SkeletonCard } from '../components/ui/Skeleton';
import { cleanupOfflineAgents, deleteAgent, mapAgent } from '../api/agents';
import { mapIncident } from '../api/incidents';
import { mapEvent } from '../api/events';
import IncidentDetailModal from '../components/incidents/IncidentDetailModal';
import { useDashboardSummary } from '../hooks/useDashboardSummary';

function localTime(value) {
    const time = value ? new Date(value) : null;
    return time && Number.isFinite(time.getTime()) ? time.toLocaleString() : '—';
}

export default function Dashboard() {
    const navigate = useNavigate();
    const { summary, error, loading, isConnected, snapshotReady, refresh } = useDashboardSummary();
    const [now, setNow] = useState(Date.now);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [selectedAgentTab, setSelectedAgentTab] = useState('Overview');
    const [selectedIncident, setSelectedIncident] = useState(null);

    useEffect(() => {
        const timer = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(timer);
    }, []);

    if (!summary && error) {
        return <ErrorState title="Không thể kết nối Manager" message={error.message} onRetry={refresh} />;
    }
    if (!summary && loading) return <SkeletonCard />;
    if (!summary) return null;

    const managerNow = now + summary.browserClockOffset;
    const online = summary.health_counts.online || 0;
    const agents = summary.agents.map(mapAgent);
    const incidents = summary.incidents.map(mapIncident).map((incident) => {
        if (incident.detection_activity === 'active' &&
            (!isConnected || !snapshotReady || error || Date.parse(incident.activity_expires_at) <= managerNow)) {
            return { ...incident, detection_activity: 'stale' };
        }
        return incident;
    });
    const networkFindings = summary.network_findings.map(mapIncident);
    const candidate = mapIncident(summary.active_behavior);
    const active = candidate && isConnected && snapshotReady && !error &&
        Date.parse(candidate.activity_expires_at) > managerNow;
    const incident = candidate || incidents.find((entry) =>
        !['closed', 'resolved'].includes(entry.incident_status) && entry.disposition !== 'false_positive'
    ) || incidents[0];
    const uncertain = !isConnected || error || summary.health_counts.stale || summary.health_counts.offline ||
        incident?.detection_activity === 'stale' || incident?.detection_activity === 'unknown' || Boolean(candidate && !active);

    const archiveAgent = async (agentId, hostname) => {
        if (!window.confirm(`Ngừng quản lý Agent "${hostname || agentId}"?`)) return;
        try {
            await deleteAgent(agentId);
            await refresh();
        } catch (err) {
            toast.error(err.message);
        }
    };

    const archiveOffline = async () => {
        if (!window.confirm('Ngừng quản lý các Agent đang offline?')) return;
        try {
            await cleanupOfflineAgents();
            await refresh();
        } catch (err) {
            toast.error(err.message);
        }
    };

    const scoreVal = incident ? (incident.riskScore || incident.risk_score || 0) : 0;
    const isCriticalRisk = scoreVal >= 70;
    const isHighRisk = scoreVal >= 40 && scoreVal < 70;
    const scoreColor = isCriticalRisk ? 'var(--error, #ef4444)' : isHighRisk ? 'var(--warning, #f59e0b)' : 'var(--success, #10b981)';
    const scoreBg = isCriticalRisk ? 'var(--error-dim, rgba(239, 68, 68, 0.15))' : isHighRisk ? 'var(--warning-dim, rgba(245, 158, 11, 0.15))' : 'var(--success-dim, rgba(16, 185, 129, 0.15))';
    const scoreBorder = isCriticalRisk ? 'var(--error, #ef4444)' : isHighRisk ? 'var(--warning, #f59e0b)' : 'var(--success, #10b981)';

    const heroBorder = active
        ? '1px solid rgba(239, 68, 68, 0.45)'
        : incident
            ? '1px solid var(--border-primary)'
            : '1px solid var(--border-subtle)';
    const heroBorderLeft = active
        ? '5px solid var(--error, #ef4444)'
        : incident
            ? '5px solid var(--warning, #f59e0b)'
            : '5px solid var(--success, #10b981)';
    const heroBg = active
        ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(22, 32, 50, 0.98) 100%)'
        : incident
            ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(22, 32, 50, 0.98) 100%)'
            : 'linear-gradient(135deg, rgba(16, 185, 129, 0.06) 0%, rgba(22, 32, 50, 0.98) 100%)';

    return (
        <div>
            {/* 1. Header & Live Status */}
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <div>
                    <h1 className="page-title" style={{ margin: 0, fontSize: '1.4rem', fontWeight: 800 }}>Security Operations Dashboard</h1>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.25rem', fontSize: '0.78rem', color: isConnected ? 'var(--success)' : 'var(--warning)' }}>
                        <FiRadio size={13} />
                        <span>{isConnected ? 'Real-time WebSocket connection active' : 'WebSocket reconnecting...'}</span>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <Button variant="outline" size="sm" iconLeft={<FiRotateCw size={13} />} onClick={refresh}>Làm mới</Button>
                    <Button size="sm" iconLeft={<FiShield size={14} />} onClick={() => navigate('/incidents?status=open')}>
                        Hàng đợi ({summary.incident_queue})
                    </Button>
                </div>
            </div>

            {/* 2. Hero Alert Card (Active Threat / Historical Security Incident) */}
            <div className="card" style={{
                padding: '1.25rem 1.5rem',
                marginBottom: '1.25rem',
                background: heroBg,
                border: heroBorder,
                borderLeft: heroBorderLeft,
                borderRadius: 'var(--radius-md, 10px)',
                boxShadow: active ? '0 4px 20px rgba(239, 68, 68, 0.18)' : 'var(--shadow-sm)',
            }}>
                {/* Header Tag Bar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                        <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            fontWeight: 700,
                            fontSize: '0.75rem',
                            padding: '0.2rem 0.65rem',
                            borderRadius: '9999px',
                            background: active ? 'var(--error-dim)' : incident ? 'var(--warning-dim)' : 'var(--success-dim)',
                            color: active ? 'var(--error)' : incident ? 'var(--warning)' : 'var(--success)',
                            letterSpacing: '0.04em',
                            textTransform: 'uppercase',
                        }}>
                            {active ? <FiAlertOctagon size={13} /> : incident ? <FiClock size={13} /> : <FiCheckCircle size={13} />}
                            {active ? 'Active Threat Detected' : incident ? 'Historical Security Incident' : 'All Systems Normal'}
                        </span>

                        {incident && (
                            <>
                                <span style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '0.75rem',
                                    padding: '0.15rem 0.5rem',
                                    borderRadius: '4px',
                                    background: 'var(--bg-tertiary)',
                                    color: 'var(--text-secondary)',
                                    border: '1px solid var(--border-subtle)',
                                }}>
                                    🖥️ {incident.agent_id}
                                </span>
                                <Badge status={(incident.incident_status || incident.status || 'open').toLowerCase()}
                                       label={incident.incident_status || incident.status || 'Open'} />
                            </>
                        )}
                    </div>

                    {incident && (
                        <Button size="sm" variant={active ? "primary" : "outline"} iconRight={<FiArrowRight size={13} />}
                                onClick={() => setSelectedIncident(incident)}>
                            Xem chi tiết sự cố
                        </Button>
                    )}
                </div>

                {/* Main Split Body */}
                {incident ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
                        {/* Left Details */}
                        <div style={{ flex: '1 1 500px', minWidth: '280px' }}>
                            <h2 style={{
                                fontSize: '1.2rem',
                                fontWeight: 700,
                                color: 'var(--text-primary)',
                                margin: '0 0 0.45rem 0',
                                lineHeight: 1.3,
                            }}>
                                {incident.title}
                            </h2>

                            <div style={{
                                fontSize: '0.8rem',
                                color: 'var(--text-secondary)',
                                marginBottom: '0.75rem',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.6rem',
                                flexWrap: 'wrap',
                            }}>
                                <span>Phân loại: <strong style={{ color: 'var(--text-primary)' }}>{incident.detection_evidence?.classification || 'Host / Endpoint Execution'}</strong></span>
                                {incident.confidence != null && (
                                    <span style={{
                                        background: 'rgba(56, 189, 248, 0.15)',
                                        color: 'var(--primary)',
                                        padding: '0.1rem 0.4rem',
                                        borderRadius: '4px',
                                        fontSize: '0.72rem',
                                        fontWeight: 600,
                                    }}>
                                        Độ tin cậy: {Math.round(incident.confidence * 100)}%
                                    </span>
                                )}
                                {uncertain && !active && (
                                    <span style={{ color: 'var(--warning)', fontSize: '0.75rem', fontWeight: 500 }}>
                                        (Trạng thái cũ / Stale)
                                    </span>
                                )}
                            </div>

                            {/* Metadata Chips Strip */}
                            <div style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '1rem',
                                flexWrap: 'wrap',
                                fontSize: '0.75rem',
                                color: 'var(--text-tertiary)',
                            }}>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                                    <FiClock size={12} /> Bắt đầu: <span style={{ color: 'var(--text-secondary)' }}>{localTime(incident.first_seen)}</span>
                                </span>
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                                    <FiActivity size={12} /> Gần nhất: <span style={{ color: 'var(--text-secondary)' }}>{localTime(incident.last_seen)}</span>
                                </span>
                                {incident.resolved_at && (
                                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', color: 'var(--success)' }}>
                                        <FiCheckCircle size={12} /> Giải quyết: {localTime(incident.resolved_at)}
                                    </span>
                                )}
                            </div>
                        </div>

                        {/* Right Risk Score Gauge Widget */}
                        <div style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '1rem',
                            background: 'rgba(15, 23, 42, 0.7)',
                            padding: '0.75rem 1.25rem',
                            borderRadius: '8px',
                            border: `1px solid ${scoreBorder}`,
                            minWidth: '140px',
                            textAlign: 'center',
                            flexShrink: 0,
                        }}>
                            <div style={{ width: '100%' }}>
                                <div style={{ fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-tertiary)', fontWeight: 600 }}>
                                    {active ? 'Detection Risk' : 'Historical Score'}
                                </div>
                                <div style={{ fontSize: '1.85rem', fontWeight: 800, color: scoreColor, lineHeight: 1.1 }}>
                                    {scoreVal}
                                    <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--text-tertiary)', marginLeft: '2px' }}>/100</span>
                                </div>
                                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: scoreColor, marginTop: '2px' }}>
                                    {scoreVal >= 70 ? 'CRITICAL LEVEL' : scoreVal >= 40 ? 'HIGH SEVERITY' : 'LOW RISK'}
                                </div>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div style={{ padding: '0.5rem 0', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                        Hệ thống hoạt động an toàn. Không có mối đe dọa hoạt động hoặc sự cố an ninh chưa giải quyết.
                    </div>
                )}
            </div>

            {/* 3. Fleet Health Observation Bar */}
            <HealthScoreGauge summary={summary} activityVerified={Boolean(active)} />

            {/* 4. KPI Cards Row (4 Columns Grid) */}
            <div className="grid-4" style={{ marginBottom: '1.25rem' }}>
                <KpiCard type="agents" label="Online Endpoints" value={`${online}/${summary.total_agents}`} />
                <KpiCard type="alerts" label="Telemetry Alerts Today (UTC)" value={summary.alerts_today} />
                <KpiCard type="blocked" label="Block Events Today (UTC)" value={summary.block_events_today} />
                <KpiCard icon={<FiShield size={20} />} label="Open Incident Queue" value={summary.incident_queue} />
            </div>

            {/* 5. Threat Detections & Network Findings (Balanced 2-Columns Grid) */}
            <div className="grid-2" style={{ marginBottom: '1.25rem', alignItems: 'stretch' }}>
                <RecentThreats incidents={incidents} onSelectIncident={setSelectedIncident} />
                <NetworkFindings findings={networkFindings} onSelectFinding={setSelectedIncident} />
            </div>

            {/* 6. Managed Endpoints (Full Width for Spacious Table Layout) */}
            <div style={{ marginBottom: '1.25rem' }}>
                <AgentTable agents={agents} onDeleteAgent={archiveAgent} onCleanupOffline={archiveOffline}
                    onViewAgent={(agent, tab = 'Overview') => { setSelectedAgent(agent); setSelectedAgentTab(tab); }} />
            </div>

            {/* 7. Recent Telemetry Alerts Feed */}
            <RecentAlerts events={summary.events.map(mapEvent)} />

            {/* Modals */}
            {selectedAgent && <AgentDetailModal agent={selectedAgent} initialTab={selectedAgentTab}
                onClose={() => setSelectedAgent(null)} onDeleteAgent={archiveAgent} />}
            {selectedIncident && <IncidentDetailModal incident={selectedIncident} isOpen
                onClose={() => setSelectedIncident(null)} onRefresh={refresh} />}
        </div>
    );
}
