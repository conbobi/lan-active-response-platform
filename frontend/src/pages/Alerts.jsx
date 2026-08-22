import React, { useState, useMemo } from 'react';
import { useEvents } from '../hooks/useEvents';
import Badge from '../components/ui/Badge';
import FilterTabs from '../components/ui/FilterTabs';
import SearchBar from '../components/ui/SearchBar';
import Dropdown from '../components/ui/Dropdown';
import Pagination from '../components/ui/Pagination';
import Modal from '../components/ui/Modal';
import { FiAlertTriangle, FiAlertCircle, FiInfo, FiShield } from 'react-icons/fi';

const PAGE_SIZE = 10;
const severityIcon = {
  Critical: <FiAlertCircle size={16} />,
  High: <FiAlertTriangle size={16} />,
  Medium: <FiShield size={16} />,
  Low: <FiInfo size={16} />,
};
const iconCls = { Critical: 'alert-icon-critical', High: 'alert-icon-warning', Medium: 'alert-icon-warning', Low: 'alert-icon-info' };

const TIME_OPTS = [
  { value: 'all', label: 'All Time' },
  { value: 'today', label: 'Today' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
];

const TABS = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

export default function Alerts() {
  const { events } = useEvents();
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [timeRange, setTimeRange] = useState('all');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    const now = Date.now();
    const ranges = { today: 86400000, '7d': 604800000, '30d': 2592000000 };
    return events.filter((e) => {
      const mSev = severity === 'all' || (e.severity && e.severity.toLowerCase() === severity);
      const eTime = e.timestamp ? new Date(e.timestamp).getTime() : Date.now();
      const mTime = timeRange === 'all' || (now - eTime) < ranges[timeRange];
      const mSearch = !search || e.type.includes(search) || (e.sourceIp && e.sourceIp.includes(search)) || (e.description && e.description.includes(search));
      return mSev && mTime && mSearch;
    });
  }, [events, search, severity, timeRange]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE) || 1;
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const tabsWithCount = TABS.map((t) => ({
    ...t,
    count: t.value === 'all' ? events.length : events.filter((e) => e.severity && e.severity.toLowerCase() === t.value).length,
  }));

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">{filtered.length} alerts found</p>
        </div>
        <Dropdown label="Time Range" options={TIME_OPTS} value={timeRange} onChange={(v) => { setTimeRange(v); setPage(1); }} />
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <FilterTabs tabs={tabsWithCount} active={severity} onChange={(v) => { setSeverity(v); setPage(1); }} />
          <div style={{ marginLeft: 'auto' }}>
            <SearchBar value={search} onChange={(v) => { setSearch(v); setPage(1); }} placeholder="Search alerts…" style={{ width: 220 }} />
          </div>
        </div>

        {paginated.map((e) => (
          <div key={e.id} className="alert-item" onClick={() => setSelected(e)}>
            <div className={`alert-icon-wrap ${iconCls[e.severity] || 'alert-icon-info'}`}>
              {severityIcon[e.severity] || <FiInfo size={16} />}
            </div>
            <div className="alert-content">
              <div className="alert-title">{e.type.replace(/_/g, ' ').toUpperCase()}</div>
              <div className="alert-desc">{e.description} — {e.sourceIp}</div>
            </div>
            <div className="alert-meta">
              <Badge status={e.severity.toLowerCase()} label={e.severity} showDot={false} />
              <span className="alert-time">{new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            </div>
          </div>
        ))}

        <div style={{ padding: '1rem 1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Showing {Math.min((page - 1) * PAGE_SIZE + 1, filtered.length)}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
          </span>
          <Pagination current={page} total={totalPages} onChange={setPage} />
        </div>
      </div>

      <Modal isOpen={!!selected} onClose={() => setSelected(null)} title="Alert Detail">
        {selected && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {[
              ['Event ID', selected.id],
              ['Type', selected.type],
              ['Severity', selected.severity],
              ['Source IP', selected.sourceIp],
              ['Agent', selected.agentId],
              ['Risk Score', selected.riskScore],
              ['Description', selected.description],
              ['Timestamp', new Date(selected.timestamp).toLocaleString()],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{k}</span>
                <span style={{ fontWeight: 500 }}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </Modal>
    </div>
  );
}
