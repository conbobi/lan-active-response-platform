import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FiCpu,
  FiShield,
  FiPercent,
  FiClock,
  FiPlus,
  FiRefreshCw,
  FiSearch,
  FiSliders,
  FiExternalLink,
  FiCheck,
  FiX,
  FiPower,
  FiBarChart2,
  FiFilter
} from 'react-icons/fi';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
  BarChart,
  Bar,
  Cell
} from 'recharts';

import MetricsCard from '../components/ai/MetricsCard';
import StatusBadge from '../components/ai/StatusBadge';
import SourceBadge from '../components/ai/SourceBadge';
import MITRETags from '../components/ai/MITRETags';
import './AIDashboard.fallback.css';

export default function AIDashboard() {
  const navigate = useNavigate();

  // Metrics & Rules State
  const [metrics, setMetrics] = useState(null);
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState({});

  // Filter & Search State
  const [statusFilter, setStatusFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedMitre, setSelectedMitre] = useState(null);

  // Sorting
  const [sortBy, setSortBy] = useState('created_at');
  const [sortDesc, setSortDesc] = useState(true);

  // Fetch Dashboard Metrics & Rules
  const fetchData = async () => {
    try {
      setLoading(true);
      const [metricsRes, rulesRes] = await Promise.all([
        fetch('/api/v1/dashboard/ai-metrics?period=7d'),
        fetch('/api/v1/rules?limit=100')
      ]);

      if (metricsRes.ok) {
        const mData = await metricsRes.json();
        setMetrics(mData);
      }

      if (rulesRes.ok) {
        const rData = await rulesRes.json();
        setRules(rData.items || []);
      }
    } catch (err) {
      console.error('Failed to load AI Dashboard data:', err);
      toast.error('Failed to load AI Dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Action Handlers
  const handleValidate = async (ruleId) => {
    try {
      setActionLoading((prev) => ({ ...prev, [ruleId]: 'validating' }));
      const res = await fetch(`/api/v1/rules/${ruleId}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fpr_threshold: 0.05, precision_threshold: 0.95 })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success(`Agent B: Rule ${data.status.toUpperCase()}`);
        fetchData();
      }
    } catch (err) {
      toast.error('Validation request failed');
    } finally {
      setActionLoading((prev) => ({ ...prev, [ruleId]: null }));
    }
  };

  const handleActivate = async (ruleId) => {
    try {
      setActionLoading((prev) => ({ ...prev, [ruleId]: 'activating' }));
      const res = await fetch(`/api/v1/rules/${ruleId}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst_id: 'soc_lead' })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule activated into live detection engine');
        fetchData();
      }
    } catch (err) {
      toast.error('Failed to activate rule');
    } finally {
      setActionLoading((prev) => ({ ...prev, [ruleId]: null }));
    }
  };

  const handleReject = async (ruleId) => {
    const reason = prompt('Enter rejection reason:');
    if (reason === null) return;

    try {
      setActionLoading((prev) => ({ ...prev, [ruleId]: 'rejecting' }));
      const res = await fetch(`/api/v1/rules/${ruleId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason || 'Analyst discretion', analyst_id: 'soc_lead' })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule marked as rejected');
        fetchData();
      }
    } catch (err) {
      toast.error('Failed to reject rule');
    } finally {
      setActionLoading((prev) => ({ ...prev, [ruleId]: null }));
    }
  };

  const handleDisable = async (ruleId) => {
    try {
      setActionLoading((prev) => ({ ...prev, [ruleId]: 'disabling' }));
      const res = await fetch(`/api/v1/rules/${ruleId}/disable`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule disabled');
        fetchData();
      }
    } catch (err) {
      toast.error('Failed to disable rule');
    } finally {
      setActionLoading((prev) => ({ ...prev, [ruleId]: null }));
    }
  };

  // Filter and Sort Rules
  const filteredRules = useMemo(() => {
    let result = [...rules];

    if (statusFilter !== 'all') {
      result = result.filter((r) => (r.status || '').toLowerCase() === statusFilter);
    }
    if (sourceFilter !== 'all') {
      result = result.filter((r) => (r.source || '').toLowerCase() === sourceFilter);
    }
    if (severityFilter !== 'all') {
      result = result.filter((r) => (r.severity || '').toLowerCase() === severityFilter);
    }
    if (selectedMitre) {
      result = result.filter((r) =>
        (r.mitre_techniques || []).some((t) => t.toUpperCase() === selectedMitre.toUpperCase())
      );
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (r) =>
          (r.rule_name || '').toLowerCase().includes(q) ||
          (r.rule_yaml || '').toLowerCase().includes(q)
      );
    }

    result.sort((a, b) => {
      let valA = a[sortBy];
      let valB = b[sortBy];
      if (valA == null) valA = sortDesc ? -Infinity : Infinity;
      if (valB == null) valB = sortDesc ? -Infinity : Infinity;

      if (typeof valA === 'string') {
        return sortDesc ? valB.localeCompare(valA) : valA.localeCompare(valB);
      }
      return sortDesc ? valB - valA : valA - valB;
    });

    return result;
  }, [rules, statusFilter, sourceFilter, severityFilter, selectedMitre, searchQuery, sortBy, sortDesc]);

  // Relative Time helper
  const getRelativeTime = (isoString) => {
    if (!isoString) return 'N/A';
    const date = new Date(isoString);
    const diffSec = Math.floor((new Date() - date) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  };

  const getFprBadgeColor = (val) => {
    if (val == null) return 'text-gray-500';
    if (val < 0.05) return 'text-emerald-400 font-bold';
    if (val <= 0.1) return 'text-amber-400 font-bold';
    return 'text-rose-400 font-bold';
  };

  const getPrecisionBadgeColor = (val) => {
    if (val == null) return 'text-gray-500';
    if (val >= 0.95) return 'text-emerald-400 font-bold';
    if (val >= 0.9) return 'text-amber-400 font-bold';
    return 'text-rose-400 font-bold';
  };

  return (
    <div className="space-y-6 pb-12 min-w-0 w-full ai-dashboard-root">
      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 min-w-0 ai-dashboard-header">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
              <FiCpu className="text-purple-400" />
              AI SOC Detection Studio
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
              3-AGENT PIPELINE
            </span>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Agent A (CTI Harvest) &rarr; Agent B (Statistical Validation) &rarr; Agent C (Agent EDR Engine)
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-gray-800 text-gray-300 hover:bg-gray-700 transition"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.375rem',
              padding: '0.5rem 0.75rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              borderRadius: '0.5rem',
              backgroundColor: '#1f2937',
              color: '#d1d5db',
              border: '1px solid #374151',
              cursor: 'pointer'
            }}
          >
            <FiRefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={() => navigate('/ai-dashboard/harvest')}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-600/20 transition"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.375rem',
              padding: '0.5rem 1rem',
              fontSize: '0.75rem',
              fontWeight: 700,
              borderRadius: '0.5rem',
              backgroundColor: '#9333ea',
              color: '#ffffff',
              border: 'none',
              cursor: 'pointer',
              boxShadow: '0 4px 14px rgba(147, 51, 234, 0.35)'
            }}
          >
            <FiPlus size={14} />
            Harvest from CTI
          </button>
        </div>
      </div>

      {/* ── KHỐI 1: TOP KPI CARDS ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 min-w-0 ai-kpi-grid">
        <MetricsCard
          title="Total AI-Generated Rules"
          value={metrics?.rule_stats?.total ?? 42}
          delta="+14.2%"
          variant="purple"
          subtitle={`${metrics?.rule_stats?.pending ?? 5} pending | ${metrics?.rule_stats?.active ?? 7} active`}
          icon={<FiCpu size={18} />}
        />
        <MetricsCard
          title="Avg FPR (Validated Rules)"
          value={`${((metrics?.accuracy_metrics?.avg_fpr ?? 0.032) * 100).toFixed(1)}%`}
          delta="-0.8%"
          variant={(metrics?.accuracy_metrics?.avg_fpr ?? 0.032) < 0.05 ? 'green' : 'yellow'}
          subtitle="Target < 5.0% False Positives"
          icon={<FiPercent size={18} />}
        />
        <MetricsCard
          title="Avg Detection Precision"
          value={`${((metrics?.accuracy_metrics?.avg_precision ?? 0.941) * 100).toFixed(1)}%`}
          delta="+2.5%"
          variant={(metrics?.accuracy_metrics?.avg_precision ?? 0.941) >= 0.95 ? 'green' : 'blue'}
          subtitle="True Positives / Total Alerts"
          icon={<FiShield size={18} />}
        />
        <MetricsCard
          title="Avg AI Triage Latency"
          value={`${metrics?.ai_triage_stats?.avg_latency_sec ?? 52}s`}
          delta="-6s"
          variant="blue"
          subtitle="LLM inference + validation"
          icon={<FiClock size={18} />}
        />
      </div>

      {/* ── KHỐI 2 & 3: CHARTS ROW ─────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-w-0 ai-charts-grid">
        {/* Khối 2: Line chart "Rule lifecycle 7 ngày" */}
        <div className="lg:col-span-7 rounded-xl border border-gray-800 bg-[#131722] p-5 shadow-sm min-w-0 ai-chart-card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FiBarChart2 className="text-purple-400" />
                Rule Lifecycle (7-Day Trend)
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Volumes of rules generated, validated by Agent B, and rejected
              </p>
            </div>
            <span className="text-xs font-mono text-gray-500">Last 7 Days</span>
          </div>

          <div
            className="h-64 w-full min-w-0 ai-chart-container"
            style={{ height: '260px', minHeight: '260px', position: 'relative' }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics?.trend_last_7_days || []} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
                <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
                <Line
                  type="monotone"
                  dataKey="rules_generated"
                  name="Generated"
                  stroke="#a855f7"
                  strokeWidth={2.5}
                  dot={{ r: 3 }}
                />
                <Line
                  type="monotone"
                  dataKey="validated"
                  name="Validated (Pass)"
                  stroke="#10b981"
                  strokeWidth={2.5}
                  dot={{ r: 3 }}
                />
                <Line
                  type="monotone"
                  dataKey="rejected"
                  name="Rejected (Agent B)"
                  stroke="#f43f5e"
                  strokeWidth={2}
                  strokeDasharray="4 4"
                  dot={{ r: 3 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Khối 3: Bar chart "Top MITRE techniques bị phát hiện" */}
        <div className="lg:col-span-5 rounded-xl border border-gray-800 bg-[#131722] p-5 shadow-sm min-w-0 ai-chart-card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FiSliders className="text-red-400" />
                Top MITRE Techniques
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">
                Click any technique bar to filter the rules table below
              </p>
            </div>
            {selectedMitre && (
              <button
                onClick={() => setSelectedMitre(null)}
                className="text-[11px] text-purple-400 hover:text-purple-300 underline"
              >
                Clear filter
              </button>
            )}
          </div>

          <div
            className="h-64 w-full min-w-0 ai-chart-container"
            style={{ height: '260px', minHeight: '260px', position: 'relative' }}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                layout="vertical"
                data={metrics?.top_mitre_techniques || []}
                margin={{ top: 5, right: 30, left: 35, bottom: 5 }}
                onClick={(e) => {
                  if (e && e.activePayload && e.activePayload[0]) {
                    const techId = e.activePayload[0].payload.id;
                    setSelectedMitre((prev) => (prev === techId ? null : techId));
                  }
                }}
              >
                <CartesianGrid strokeDasharray="3 3" opacity={0.15} horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={10} allowDecimals={false} />
                <YAxis dataKey="id" type="category" stroke="#94a3b8" fontSize={11} width={65} />
                <Tooltip
                  formatter={(val, name, item) => [`${val} rules`, `${item.payload.name}`]}
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {(metrics?.top_mitre_techniques || []).map((entry) => (
                    <Cell
                      key={entry.id}
                      fill={selectedMitre === entry.id ? '#c084fc' : '#e11d48'}
                      className="cursor-pointer hover:opacity-80 transition"
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── KHỐI 4: BẢNG "AI-GENERATED RULES" ────────────────────────────── */}
      <div className="rounded-xl border border-gray-800 bg-[#131722] shadow-sm overflow-hidden min-w-0 ai-table-card">
        {/* Filter Bar */}
        <div className="border-b border-gray-800 p-4 space-y-3 ai-filter-bar">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm" />
              <input
                type="text"
                placeholder="Search rule name or syntax..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
                style={{
                  width: '100%',
                  paddingLeft: '2.25rem',
                  paddingRight: '0.75rem',
                  paddingTop: '0.375rem',
                  paddingBottom: '0.375rem',
                  fontSize: '0.75rem',
                  borderRadius: '0.5rem',
                  backgroundColor: '#0d1319',
                  border: '1px solid #2d3644',
                  color: '#e6edf3'
                }}
              />
            </div>

            {selectedMitre && (
              <div className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-purple-500/15 text-purple-300 border border-purple-500/30">
                <span>Filter: MITRE {selectedMitre}</span>
                <FiX
                  size={13}
                  className="cursor-pointer hover:text-white"
                  onClick={() => setSelectedMitre(null)}
                />
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-4 text-xs pt-1 ai-filter-row">
            {/* Status Tabs */}
            <div className="flex items-center gap-1 ai-filter-group">
              <span className="text-gray-500 font-medium mr-1">Status:</span>
              {['all', 'pending', 'validated', 'active', 'rejected', 'disabled'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`ai-filter-btn ${statusFilter === st ? 'active' : ''} px-2.5 py-1 rounded-md capitalize font-medium transition ${
                    statusFilter === st
                      ? 'bg-purple-600 text-white'
                      : 'bg-gray-800/60 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>

            {/* Source */}
            <div className="flex items-center gap-1 ai-filter-group">
              <span className="text-gray-500 font-medium mr-1">Source:</span>
              {['all', 'ai_harvest', 'human'].map((src) => (
                <button
                  key={src}
                  onClick={() => setSourceFilter(src)}
                  className={`ai-filter-btn ${sourceFilter === src ? 'active-blue' : ''} px-2 py-1 rounded-md capitalize font-medium transition ${
                    sourceFilter === src
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800/60 text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  {src === 'ai_harvest' ? 'AI' : src}
                </button>
              ))}
            </div>

            {/* Severity */}
            <div className="flex items-center gap-1 ai-filter-group">
              <span className="text-gray-500 font-medium mr-1">Severity:</span>
              {['all', 'low', 'medium', 'high', 'critical'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`ai-filter-btn ${severityFilter === sev ? 'active-amber' : ''} px-2 py-1 rounded-md capitalize font-medium transition ${
                    severityFilter === sev
                      ? 'bg-amber-600 text-white'
                      : 'bg-gray-800/60 text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Rules Table */}
        <div className="overflow-x-auto min-w-0 ai-dashboard-table-wrapper" style={{ overflowX: 'auto', width: '100%' }}>
          <table className="w-full text-left text-xs min-w-[1200px]" style={{ minWidth: '1200px', width: '100%' }}>
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 uppercase tracking-wider bg-gray-900/40">
                <th className="py-3 px-4 font-semibold sticky-header">Rule Name & Severity</th>
                <th className="py-3 px-3 font-semibold sticky-header">Source</th>
                <th className="py-3 px-3 font-semibold sticky-header">MITRE ATT&CK</th>
                <th className="py-3 px-3 font-semibold sticky-header">Status</th>
                <th
                  className="py-3 px-3 font-semibold cursor-pointer hover:text-white sticky-header"
                  onClick={() => {
                    if (sortBy === 'fpr') setSortDesc(!sortDesc);
                    else {
                      setSortBy('fpr');
                      setSortDesc(false);
                    }
                  }}
                >
                  FPR {sortBy === 'fpr' && (sortDesc ? '↓' : '↑')}
                </th>
                <th
                  className="py-3 px-3 font-semibold cursor-pointer hover:text-white sticky-header"
                  onClick={() => {
                    if (sortBy === 'precision') setSortDesc(!sortDesc);
                    else {
                      setSortBy('precision');
                      setSortDesc(true);
                    }
                  }}
                >
                  Precision {sortBy === 'precision' && (sortDesc ? '↓' : '↑')}
                </th>
                <th className="py-3 px-3 font-semibold sticky-header">Recall</th>
                <th className="py-3 px-3 font-semibold sticky-header">Model</th>
                <th
                  className="py-3 px-3 font-semibold cursor-pointer hover:text-white sticky-header"
                  onClick={() => {
                    if (sortBy === 'created_at') setSortDesc(!sortDesc);
                    else {
                      setSortBy('created_at');
                      setSortDesc(true);
                    }
                  }}
                >
                  Created {sortBy === 'created_at' && (sortDesc ? '↓' : '↑')}
                </th>
                <th className="py-3 px-4 text-right font-semibold sticky-header">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-gray-500">
                    No rules matched the current filters.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr
                    key={rule.id}
                    onClick={() => navigate(`/ai-dashboard/rules/${rule.id}`)}
                    className="hover:bg-gray-800/40 cursor-pointer transition"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white max-w-xs truncate" title={rule.rule_name}>
                        {rule.rule_name}
                      </div>
                      <span className="inline-block mt-0.5 text-[10px] uppercase font-mono font-bold text-gray-400">
                        {rule.severity || 'medium'}
                      </span>
                    </td>

                    <td className="py-3.5 px-3">
                      <SourceBadge source={rule.source} />
                    </td>

                    <td className="py-3.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <MITRETags
                        techniques={rule.mitre_techniques || []}
                        onTagClick={(t) => setSelectedMitre(t)}
                      />
                    </td>

                    <td className="py-3.5 px-3">
                      <StatusBadge status={rule.status} />
                    </td>

                    <td className={`py-3.5 px-3 font-mono ${getFprBadgeColor(rule.fpr)}`}>
                      {rule.fpr != null ? `${(rule.fpr * 100).toFixed(1)}%` : '—'}
                    </td>

                    <td className={`py-3.5 px-3 font-mono ${getPrecisionBadgeColor(rule.precision)}`}>
                      {rule.precision != null ? `${(rule.precision * 100).toFixed(1)}%` : '—'}
                    </td>

                    <td className="py-3.5 px-3 font-mono text-gray-300">
                      {rule.recall != null ? `${(rule.recall * 100).toFixed(1)}%` : '—'}
                    </td>

                    <td className="py-3.5 px-3 font-mono text-gray-400 text-[11px]">
                      {rule.model_generated || 'harvest-q6'}
                    </td>

                    <td className="py-3.5 px-3 text-gray-400 text-xs">
                      {getRelativeTime(rule.created_at)}
                    </td>

                    <td
                      className="py-3.5 px-4 text-right space-x-1.5 whitespace-nowrap"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {rule.status === 'pending' && (
                        <button
                          onClick={() => handleValidate(rule.id)}
                          disabled={actionLoading[rule.id] === 'validating'}
                          className="ai-action-btn ai-action-btn-validate px-2.5 py-1 text-[11px] font-semibold rounded bg-blue-600/80 hover:bg-blue-600 text-white transition whitespace-nowrap"
                          title="Run Agent B Statistical Validation"
                        >
                          {actionLoading[rule.id] === 'validating' ? 'Validating...' : 'Validate'}
                        </button>
                      )}

                      {rule.status === 'validated' && (
                        <>
                          <button
                            onClick={() => handleActivate(rule.id)}
                            disabled={actionLoading[rule.id] === 'activating'}
                            className="ai-action-btn ai-action-btn-activate px-2.5 py-1 text-[11px] font-semibold rounded bg-emerald-600/80 hover:bg-emerald-600 text-white transition whitespace-nowrap"
                          >
                            Activate
                          </button>
                          <button
                            onClick={() => handleReject(rule.id)}
                            disabled={actionLoading[rule.id] === 'rejecting'}
                            className="ai-action-btn ai-action-btn-reject px-2 py-1 text-[11px] font-semibold rounded bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 transition whitespace-nowrap"
                          >
                            Reject
                          </button>
                        </>
                      )}

                      {rule.status === 'active' && (
                        <button
                          onClick={() => handleDisable(rule.id)}
                          disabled={actionLoading[rule.id] === 'disabling'}
                          className="ai-action-btn ai-action-btn-disable px-2.5 py-1 text-[11px] font-semibold rounded bg-zinc-700 hover:bg-zinc-600 text-zinc-300 transition whitespace-nowrap"
                        >
                          Disable
                        </button>
                      )}

                      <button
                        onClick={() => navigate(`/ai-dashboard/rules/${rule.id}`)}
                        className="ai-action-btn p-1 rounded text-gray-400 hover:text-white transition inline-block align-middle"
                        title="View Rule Details"
                        style={{ background: 'transparent' }}
                      >
                        <FiExternalLink size={13} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

