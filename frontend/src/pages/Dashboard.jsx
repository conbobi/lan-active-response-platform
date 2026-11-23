import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { FiRadio, FiRotateCw, FiShield } from 'react-icons/fi';
import KpiCard from '../components/ui/KpiCard';
import AgentTable from '../components/ui/AgentTable';
import RecentAlerts from '../components/ui/RecentAlerts';
import Button from '../components/ui/Button';
import AgentDetailModal from '../components/ui/AgentDetailModal';
import HealthScoreGauge from '../components/dashboard/HealthScoreGauge';
import RecentThreats from '../components/dashboard/RecentThreats';
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

    return (
        <div>
            <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>
                    <h1 className="page-title">Security Operations Dashboard</h1>
                    <span><FiRadio size={13} /> {isConnected ? 'Live updates' : 'WebSocket reconnecting'}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <Button variant="outline" size="sm" iconLeft={<FiRotateCw size={13} />} onClick={refresh}>Refresh</Button>
                    <Button size="sm" iconLeft={<FiShield size={14} />} onClick={() => navigate('/incidents?status=open')}>
                        Incidents Queue ({summary.incident_queue})
                    </Button>
                </div>
            </div>

            <div className="card" style={{
                padding: '1rem 1.25rem', marginBottom: '1.25rem',
                borderLeft: `4px solid var(--${active ? 'error' : 'warning'})`,
            }}>
                <h2>{active ? 'ACTIVE THREAT DETECTED' : incident ? 'Historical Security Incident' :
                    uncertain ? 'Unknown / Stale' : 'No verified active behavior'}</h2>
                {incident && (
                    <>
                        <p>{incident.title} · {incident.agent_id} · {incident.incident_status || incident.status}</p>
                        <p>
                            {active ? 'Detection Risk Score' : 'Historical Risk Score'} {incident.riskScore}/100
                            {incident.confidence != null && ` · Confidence ${Math.round(incident.confidence * 100)}%`}
                            {uncertain && !active && ' · Unknown / Stale'}
                        </p>
                        <p style={{ color: 'var(--text-secondary)' }}>
                            First Seen {localTime(incident.first_seen)} · Last Seen {localTime(incident.last_seen)}
                            {' · '}Last Verified {localTime(incident.last_verified)}
                            {incident.resolved_at && ` · Resolved At ${localTime(incident.resolved_at)}`}
                        </p>
                        <Button size="sm" variant="outline" onClick={() => setSelectedIncident(incident)}>Review incident</Button>
                    </>
                )}
            </div>

            <HealthScoreGauge summary={summary} activityVerified={Boolean(active)} />
            <div className="grid-4" style={{ marginBottom: '1.25rem' }}>
                <KpiCard type="agents" label="Online Endpoints" value={`${online}/${summary.total_agents}`} />
                <KpiCard type="alerts" label="Telemetry Alerts Today (UTC)" value={summary.alerts_today} />
                <KpiCard type="blocked" label="Block Events Today (UTC)" value={summary.block_events_today} />
                <KpiCard icon={<FiShield size={20} />} label="Open Incident Queue" value={summary.incident_queue} />
            </div>

            <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
                <AgentTable agents={agents} onDeleteAgent={archiveAgent} onCleanupOffline={archiveOffline}
                    onViewAgent={(agent, tab = 'Overview') => { setSelectedAgent(agent); setSelectedAgentTab(tab); }} />
                <RecentThreats incidents={incidents} onSelectIncident={setSelectedIncident} />
            </div>
            <section className="card" style={{ marginBottom: '1.25rem' }}>
                <h3>Network Findings</h3>
                {networkFindings.length === 0 && <p>Chưa có network finding trong hàng đợi.</p>}
                {networkFindings.slice(0, 5).map((finding) => (
                    <p key={finding.id}>
                        <Button size="sm" variant="ghost" onClick={() => setSelectedIncident(finding)}>{finding.title}</Button>
                        {' · '}{finding.culprit_process ? 'Process-linked' : 'Network-only Detection'}
                    </p>
                ))}
                <Button size="sm" variant="outline" onClick={() => navigate('/incidents?finding=network')}>View Network Findings</Button>
            </section>
            <RecentAlerts events={summary.events.map(mapEvent)} />
            {selectedAgent && <AgentDetailModal agent={selectedAgent} initialTab={selectedAgentTab}
                onClose={() => setSelectedAgent(null)} onDeleteAgent={archiveAgent} />}
            {selectedIncident && <IncidentDetailModal incident={selectedIncident} isOpen
                onClose={() => setSelectedIncident(null)} onRefresh={refresh} />}
        </div>
    );
}
