import React, { useState, useEffect, useMemo, Fragment } from 'react';
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

import api from '../api/api';
import MetricsCard from '../components/ai/MetricsCard';
import StatusBadge from '../components/ai/StatusBadge';
import SourceBadge from '../components/ai/SourceBadge';
import MITRETags from '../components/ai/MITRETags';
import './AIDashboard.fallback.css';

const STATUS_TEXT = {
  pending: 'Chờ kiểm định', validating: 'Đang kiểm định', validated: 'Đã kiểm định',
  monitoring: 'Đang giám sát', active: 'Đang chạy', rejected: 'Bị từ chối', disabled: 'Đã tắt',
};
const SOURCE_TEXT = { all: 'Tất cả', ai_harvest: 'AI', template_fallback: 'Mẫu dự phòng', ai_assistant: 'Trợ lý AI', human: 'Thủ công' };

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
  const [sortBy] = useState('created_at');
  const [sortDesc] = useState(true);

  const [loadError, setLoadError] = useState('');
  const [expanded, setExpanded] = useState(null);

  // Fetch Dashboard Metrics & Rules (shared client: attaches the signed-in JWT)
  const fetchData = async () => {
    setLoading(true);
    const [metricsRes, rulesRes] = await Promise.allSettled([
      api.get('/dashboard/ai-metrics?period=7d'),
      api.get('/rules?limit=100'),
    ]);
    const failed = [metricsRes, rulesRes].find((r) => r.status === 'rejected' || r.value?.error);
    setMetrics(metricsRes.status === 'fulfilled' && !metricsRes.value?.error ? metricsRes.value : null);
    setRules(rulesRes.status === 'fulfilled' && !rulesRes.value?.error ? rulesRes.value.items || [] : []);
    const message = failed ? (failed.reason?.message || failed.value?.error) : '';
    setLoadError(message ? `Không tải được dữ liệu AI SOC Studio: ${message}` : '');
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Backend rule routes answer business errors as {error}; transport/auth errors throw.
  const runAction = async (ruleId, state, path, body, success) => {
    setActionLoading((prev) => ({ ...prev, [ruleId]: state }));
    try {
      const data = await api.post(`/rules/${ruleId}/${path}`, body);
      if (data?.error) {
        toast.error(data.error);
      } else {
        toast.success(success(data));
      }
      await fetchData();
    } catch (err) {
      toast.error(err.message || 'Thao tác thất bại');
    } finally {
      setActionLoading((prev) => ({ ...prev, [ruleId]: null }));
    }
  };

  const VERDICT_TEXT = {
    PASSED: 'Đạt', FAILED: 'Không đạt', INCONCLUSIVE: 'Chưa đủ dữ liệu', UNSUPPORTED_BY_ENGINE: 'Engine không hỗ trợ',
  };

  const handleValidate = (ruleId) => runAction(ruleId, 'validating', 'validate',
    { fpr_threshold: 0.05, precision_threshold: 0.95 },
    (d) => `Kiểm định: ${VERDICT_TEXT[d.validation_result?.verdict] || d.validation_result?.verdict} → ${STATUS_TEXT[d.status] || d.status}`);
  const handleActivate = (ruleId) => runAction(ruleId, 'activating', 'activate', {},
    () => 'Rule đã được nạp vào Detection Engine của Manager');
  const handleReject = (ruleId) => {
    const reason = prompt('Lý do từ chối:');
    if (reason === null) return;
    return runAction(ruleId, 'rejecting', 'reject', { reason: reason || 'Analyst quyết định' }, () => 'Đã từ chối rule');
  };
  const handleDisable = (ruleId) => runAction(ruleId, 'disabling', 'disable', {}, () => 'Đã tắt rule');

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

  const percent = (val) => (val == null ? 'Chưa đủ dữ liệu' : `${(val * 100).toFixed(1)}%`);
  const measuredSubtitle = metrics?.accuracy_metrics?.measured_rules
    ? `Trung bình trên ${metrics.accuracy_metrics.measured_rules} rule có kết quả kiểm định`
    : 'Chưa có rule nào có kết quả kiểm định';

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
            Agent A (sinh Sigma từ CTI) &rarr; Agent B (kiểm định thống kê) &rarr; Detection Engine của Manager (chạy trên telemetry Agent gửi về)
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
            Làm mới
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
            Tạo rule từ CTI
          </button>
        </div>
      </div>

      {loadError && (
        <div role="alert" className="text-xs" style={{ padding: '0.6rem 0.9rem', borderRadius: 8, border: '1px solid rgba(239,68,68,0.4)', color: '#f87171' }}>
          {loadError}
        </div>
      )}

      {/* ── KHỐI 1: TOP KPI CARDS ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 min-w-0 ai-kpi-grid">
        <MetricsCard
          title="Tổng số rule"
          value={metrics ? metrics.rule_stats.total : '—'}
          variant="purple"
          subtitle={metrics ? `${metrics.rule_stats.pending} chờ kiểm định · ${metrics.rule_stats.validated} đạt · ${metrics.rule_stats.active} đang chạy` : 'Chưa tải được'}
          icon={<FiCpu size={18} />}
        />
        <MetricsCard
          title="FPR trung bình (đã kiểm định)"
          value={percent(metrics?.accuracy_metrics?.avg_fpr)}
          variant={metrics?.accuracy_metrics?.avg_fpr == null ? 'blue' : metrics.accuracy_metrics.avg_fpr < 0.05 ? 'green' : 'yellow'}
          subtitle={measuredSubtitle}
          icon={<FiPercent size={18} />}
        />
        <MetricsCard
          title="Precision trung bình"
          value={percent(metrics?.accuracy_metrics?.avg_precision)}
          variant={metrics?.accuracy_metrics?.avg_precision == null ? 'blue' : metrics.accuracy_metrics.avg_precision >= 0.95 ? 'green' : 'yellow'}
          subtitle={measuredSubtitle}
          icon={<FiShield size={18} />}
        />
        <MetricsCard
          title="Độ trễ AI triage trung bình"
          value={metrics?.ai_triage_stats?.avg_latency_sec == null ? 'Chưa đủ dữ liệu' : `${metrics.ai_triage_stats.avg_latency_sec}s`}
          variant="blue"
          subtitle={metrics ? `${metrics.ai_triage_stats.total_analyses} phân tích đã lưu; độ trễ chưa được ghi nhận` : ''}
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
                placeholder="Tìm theo tên rule hoặc nội dung Sigma..."
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
                  backgroundColor: 'var(--bg-input, #111927)',
                  border: '1px solid var(--border-primary, #334155)',
                  color: 'var(--text-primary, #f8fafc)'
                }}
              />
            </div>

            {selectedMitre && (
              <div className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-purple-500/15 text-purple-300 border border-purple-500/30">
                <span>Lọc MITRE: {selectedMitre}</span>
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
              <span className="text-gray-500 font-medium mr-1">Trạng thái:</span>
              {['all', 'pending', 'validated', 'monitoring', 'active', 'rejected', 'disabled'].map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`ai-filter-btn ${statusFilter === st ? 'active' : ''} px-2.5 py-1 rounded-md capitalize font-medium transition ${
                    statusFilter === st
                      ? 'bg-purple-600 text-white'
                      : 'bg-gray-800/60 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                  }`}
                >
                  {st === 'all' ? 'Tất cả' : STATUS_TEXT[st]}
                </button>
              ))}
            </div>

            {/* Source */}
            <div className="flex items-center gap-1 ai-filter-group">
              <span className="text-gray-500 font-medium mr-1">Nguồn:</span>
              {['all', 'ai_harvest', 'template_fallback', 'human'].map((src) => (
                <button
                  key={src}
                  onClick={() => setSourceFilter(src)}
                  className={`ai-filter-btn ${sourceFilter === src ? 'active-blue' : ''} px-2 py-1 rounded-md capitalize font-medium transition ${
                    sourceFilter === src
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800/60 text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  {SOURCE_TEXT[src]}
                </button>
              ))}
            </div>

            {/* Severity */}
            <div className="flex items-center gap-1 ai-filter-group">
              <span className="text-gray-500 font-medium mr-1">Mức độ:</span>
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
                  {sev === 'all' ? 'Tất cả' : sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Rules Table */}
        <div className="overflow-x-auto min-w-0 ai-dashboard-table-wrapper" style={{ overflowX: 'auto', width: '100%' }}>
          <table className="w-full text-left text-xs min-w-[1100px]" style={{ minWidth: '1100px', width: '100%' }}>
            <thead>
              <tr className="border-b border-gray-800 text-gray-400 uppercase tracking-wider bg-gray-900/40">
                <th className="py-3 px-4 font-semibold sticky-header">Rule</th>
                <th className="py-3 px-3 font-semibold sticky-header">Mức độ</th>
                <th className="py-3 px-3 font-semibold sticky-header">Nguồn</th>
                <th className="py-3 px-3 font-semibold sticky-header">MITRE ATT&CK</th>
                <th className="py-3 px-3 font-semibold sticky-header">Trạng thái</th>
                <th className="py-3 px-3 font-semibold sticky-header">Kết quả kiểm định</th>
                <th className="py-3 px-4 text-right font-semibold sticky-header">Thao tác</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-gray-500">
                    {loading ? 'Đang tải…' : rules.length === 0
                      ? 'Chưa có rule nào trong cơ sở dữ liệu. Dùng "Tạo rule từ CTI" để sinh rule Sigma đầu tiên.'
                      : 'Không có rule nào khớp bộ lọc hiện tại.'}
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => {
                  const validation = rule.validation;
                  const isOpen = expanded === rule.id;
                  return (
                  <Fragment key={rule.id}>
                  <tr className="hover:bg-gray-800/40 transition">
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white max-w-xs truncate" title={rule.rule_name}>
                        {rule.rule_name}
                      </div>
                      <div className="text-[10px] text-gray-500 mt-0.5">{getRelativeTime(rule.created_at)}</div>
                    </td>
                    <td className="py-3.5 px-3 text-[11px] uppercase font-mono font-bold text-gray-300">
                      {rule.severity || '—'}
                    </td>
                    <td className="py-3.5 px-3">
                      <SourceBadge source={rule.source} />
                    </td>
                    <td className="py-3.5 px-3">
                      <MITRETags
                        techniques={rule.mitre_techniques || []}
                        onTagClick={(t) => setSelectedMitre(t)}
                      />
                    </td>
                    <td className="py-3.5 px-3">
                      <StatusBadge status={rule.status} />
                    </td>
                    <td className="py-3.5 px-3 text-[11px]">
                      {!validation ? <span className="text-gray-500">Chưa kiểm định</span> : (
                        <div>
                          <strong>{VERDICT_TEXT[validation.verdict] || validation.verdict}</strong>
                          {rule.fpr != null && (
                            <span className="font-mono" style={{ marginLeft: '0.35rem' }}>
                              <span className={getFprBadgeColor(rule.fpr)}>FPR {(rule.fpr * 100).toFixed(1)}%</span>
                              {' · '}
                              <span className={getPrecisionBadgeColor(rule.precision)}>P {(rule.precision * 100).toFixed(1)}%</span>
                            </span>
                          )}
                          {validation.confusion && (
                            <div className="font-mono text-gray-400">
                              TP {validation.confusion.tp} · FP {validation.confusion.fp} · FN {validation.confusion.fn} · TN {validation.confusion.tn}
                            </div>
                          )}
                          {validation.dataset?.total != null && (
                            <div className="text-gray-500" title="Tập kiểm định có nhãn">
                              {validation.dataset.attack} mẫu tấn công · {validation.dataset.benign} mẫu benign
                              {' '}({Object.keys(validation.dataset.by_source || {}).join(', ')})
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-1.5 whitespace-nowrap">
                      <button
                        onClick={() => setExpanded(isOpen ? null : rule.id)}
                        aria-expanded={isOpen}
                        className="ai-action-btn px-2 py-1 text-[11px] rounded bg-gray-800 text-gray-300 hover:bg-gray-700 transition"
                      >
                        {isOpen ? 'Ẩn Sigma' : 'Xem Sigma'}
                      </button>
                      {rule.status === 'pending' && (
                        <button
                          onClick={() => handleValidate(rule.id)}
                          disabled={actionLoading[rule.id] === 'validating'}
                          className="ai-action-btn ai-action-btn-validate px-2.5 py-1 text-[11px] font-semibold rounded bg-blue-600/80 hover:bg-blue-600 text-white transition whitespace-nowrap"
                          title="Kiểm định thống kê (Agent B) và kiểm tra Detection Engine hỗ trợ"
                        >
                          {actionLoading[rule.id] === 'validating' ? 'Đang kiểm định…' : 'Kiểm định'}
                        </button>
                      )}
                      {rule.status === 'validated' && (
                        <>
                          <button
                            onClick={() => handleActivate(rule.id)}
                            disabled={actionLoading[rule.id] === 'activating'}
                            className="ai-action-btn ai-action-btn-activate px-2.5 py-1 text-[11px] font-semibold rounded bg-emerald-600/80 hover:bg-emerald-600 text-white transition whitespace-nowrap"
                          >
                            Duyệt & kích hoạt
                          </button>
                          <button
                            onClick={() => handleReject(rule.id)}
                            disabled={actionLoading[rule.id] === 'rejecting'}
                            className="ai-action-btn ai-action-btn-reject px-2 py-1 text-[11px] font-semibold rounded bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 transition whitespace-nowrap"
                          >
                            Từ chối
                          </button>
                        </>
                      )}
                      {rule.status === 'monitoring' && (
                        <button
                          onClick={() => handleActivate(rule.id)}
                          disabled={actionLoading[rule.id] === 'activating'}
                          className="ai-action-btn ai-action-btn-activate px-2.5 py-1 text-[11px] font-semibold rounded bg-emerald-600/80 hover:bg-emerald-600 text-white transition whitespace-nowrap"
                          title="Chuyển từ giám sát sang tạo incident (cần kiểm định đạt hoặc đủ thời gian giám sát)"
                        >
                          Bật chính thức
                        </button>
                      )}
                      {(rule.status === 'active' || rule.status === 'monitoring') && (
                        <button
                          onClick={() => handleDisable(rule.id)}
                          disabled={actionLoading[rule.id] === 'disabling'}
                          className="ai-action-btn ai-action-btn-disable px-2.5 py-1 text-[11px] font-semibold rounded bg-zinc-700 hover:bg-zinc-600 text-zinc-300 transition whitespace-nowrap"
                        >
                          Tắt
                        </button>
                      )}
                      <button
                        onClick={() => navigate(`/ai-dashboard/rules/${rule.id}`)}
                        className="ai-action-btn p-1 rounded text-gray-400 hover:text-white transition inline-block align-middle"
                        title="Xem chi tiết rule"
                        aria-label="Xem chi tiết rule"
                        style={{ background: 'transparent' }}
                      >
                        <FiExternalLink size={13} />
                      </button>
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-900/40">
                      <td colSpan={7} className="px-4 py-3">
                        {(validation?.reason || rule.notes) && (
                          <div className="text-[11px] mb-2" style={{ color: rule.status === 'rejected' ? '#fb7185' : '#cbd5e1' }}>
                            <strong>{rule.status === 'rejected' ? 'Lý do bị từ chối: ' : 'Ghi chú: '}</strong>
                            {validation?.reason || rule.notes}
                          </div>
                        )}
                        <pre className="text-[11px] font-mono" style={{ whiteSpace: 'pre-wrap', margin: 0, maxHeight: 320, overflow: 'auto' }}>
                          {rule.rule_yaml}
                        </pre>
                      </td>
                    </tr>
                  )}
                  </Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

