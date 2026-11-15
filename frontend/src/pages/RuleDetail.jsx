import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FiArrowLeft,
  FiPlay,
  FiCheckCircle,
  FiXCircle,
  FiPower,
  FiCopy,
  FiCheck,
  FiZap,
  FiClock,
  FiFileText,
  FiActivity,
  FiAlertTriangle,
  FiGitCommit
} from 'react-icons/fi';

import StatusBadge from '../components/ai/StatusBadge';
import SourceBadge from '../components/ai/SourceBadge';
import MITRETags from '../components/ai/MITRETags';
import ValidationResultPanel from '../components/ai/ValidationResultPanel';

export default function RuleDetail() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [rule, setRule] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview'); // overview, validation, fp_samples, versions, actions
  const [copied, setCopied] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [exclusionLoading, setExclusionLoading] = useState(false);
  const [suggestedExclusion, setSuggestedExclusion] = useState(null);

  const fetchRule = async () => {
    try {
      setLoading(true);
      const res = await fetch(`/api/v1/rules/${id}`);
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        setRule(data);
      }
    } catch (err) {
      toast.error('Failed to load rule details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRule();
  }, [id]);

  const handleCopyYaml = () => {
    if (!rule?.rule_yaml) return;
    navigator.clipboard.writeText(rule.rule_yaml);
    setCopied(true);
    toast.success('YAML copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleValidate = async () => {
    try {
      setActionLoading(true);
      const res = await fetch(`/api/v1/rules/${id}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fpr_threshold: 0.05, precision_threshold: 0.95 })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success(`Agent B: Rule ${data.status.toUpperCase()}`);
        fetchRule();
        setActiveTab('validation');
      }
    } catch (err) {
      toast.error('Validation request failed');
    } finally {
      setActionLoading(false);
    }
  };

  const handleActivate = async () => {
    try {
      setActionLoading(true);
      const res = await fetch(`/api/v1/rules/${id}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst_id: 'soc_analyst' })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule successfully activated');
        fetchRule();
      }
    } catch (err) {
      toast.error('Failed to activate rule');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    const reason = prompt('Enter rejection reason:');
    if (reason === null) return;

    try {
      setActionLoading(true);
      const res = await fetch(`/api/v1/rules/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason || 'Manual analyst rejection', analyst_id: 'soc_analyst' })
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule rejected');
        fetchRule();
      }
    } catch (err) {
      toast.error('Failed to reject rule');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDisable = async () => {
    try {
      setActionLoading(true);
      const res = await fetch(`/api/v1/rules/${id}/disable`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule disabled');
        fetchRule();
      }
    } catch (err) {
      toast.error('Failed to disable rule');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSuggestExclusion = async () => {
    try {
      setExclusionLoading(true);
      const res = await fetch(`/api/v1/rules/${id}/suggest-exclusion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        setSuggestedExclusion(data.suggestion);
        toast.success('Agent A generated exclusion suggestion');
      }
    } catch (err) {
      toast.error('Failed to generate exclusion suggestion');
    } finally {
      setExclusionLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-gray-400 text-sm">
        Loading rule candidate...
      </div>
    );
  }

  if (!rule) {
    return (
      <div className="space-y-4">
        <button
          onClick={() => navigate('/ai-dashboard')}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white"
        >
          <FiArrowLeft size={13} /> Back to AI Dashboard
        </button>
        <div className="rounded-xl border border-gray-800 bg-[#131722] p-8 text-center text-gray-400 text-sm">
          Rule candidate not found.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* ── BACK BUTTON & ACTIONS HEADER ───────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <button
          onClick={() => navigate('/ai-dashboard')}
          className="flex items-center gap-1.5 text-xs font-semibold text-gray-400 hover:text-white transition w-fit"
        >
          <FiArrowLeft size={14} /> Back to AI Dashboard
        </button>

        {/* Action Buttons Top Right */}
        <div className="flex items-center gap-2">
          {rule.status === 'pending' && (
            <button
              onClick={handleValidate}
              disabled={actionLoading}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20 transition disabled:opacity-50"
            >
              <FiPlay size={13} />
              {actionLoading ? 'Validating...' : 'Validate Now (Agent B)'}
            </button>
          )}

          {rule.status === 'validated' && (
            <>
              <button
                onClick={handleActivate}
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20 transition disabled:opacity-50"
              >
                <FiCheckCircle size={13} />
                Activate Rule
              </button>
              <button
                onClick={handleReject}
                disabled={actionLoading}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-lg bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 transition disabled:opacity-50"
              >
                <FiXCircle size={13} />
                Reject
              </button>
            </>
          )}

          {rule.status === 'active' && (
            <button
              onClick={handleDisable}
              disabled={actionLoading}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition disabled:opacity-50"
            >
              <FiPower size={13} />
              Disable
            </button>
          )}
        </div>
      </div>

      {/* ── RULE TITLE & METADATA BAR ──────────────────────────────────── */}
      <div className="rounded-xl border border-gray-800 bg-[#131722] p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-xl font-black text-white tracking-tight">
                {rule.rule_name}
              </h2>
              <SourceBadge source={rule.source} />
              <StatusBadge status={rule.status} />
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
                {rule.severity || 'medium'}
              </span>
            </div>
            <p className="text-xs text-gray-400 mt-1 font-mono">ID: {rule.id}</p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-400 font-medium">MITRE:</span>
            <MITRETags techniques={rule.mitre_techniques || []} max={5} />
          </div>
        </div>

        {/* Quick KPI stats strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-gray-800/80 text-xs">
          <div>
            <span className="text-gray-500">False Positive Rate:</span>
            <div className="font-mono font-bold text-sm text-white mt-0.5">
              {rule.fpr != null ? `${(rule.fpr * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div>
            <span className="text-gray-500">Precision:</span>
            <div className="font-mono font-bold text-sm text-white mt-0.5">
              {rule.precision != null ? `${(rule.precision * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div>
            <span className="text-gray-500">Recall:</span>
            <div className="font-mono font-bold text-sm text-white mt-0.5">
              {rule.recall != null ? `${(rule.recall * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div>
            <span className="text-gray-500">Model Engine:</span>
            <div className="font-mono text-sm text-purple-400 mt-0.5">
              {rule.model_generated || 'harvest-q6'}
            </div>
          </div>
        </div>
      </div>

      {/* ── TABS NAVIGATION ────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-gray-800 text-xs font-semibold overflow-x-auto">
        {[
          { key: 'overview', label: 'Overview & YAML', icon: <FiFileText size={13} /> },
          { key: 'validation', label: 'Validation Results', icon: <FiActivity size={13} /> },
          { key: 'fp_samples', label: `FP Samples (${(rule.false_positive_samples || []).length})`, icon: <FiAlertTriangle size={13} /> },
          { key: 'versions', label: `Versions (${(rule.versions || []).length})`, icon: <FiGitCommit size={13} /> },
          { key: 'actions', label: 'Actions Log', icon: <FiClock size={13} /> }
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition whitespace-nowrap ${
              activeTab === tab.key
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── TAB CONTENT ────────────────────────────────────────────────── */}

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* YAML Viewer */}
          <div className="rounded-xl border border-gray-800 bg-[#0d1117] shadow-sm overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-gray-900 border-b border-gray-800 text-xs text-gray-400 font-mono">
              <span>Sigma Rule Definition (YAML)</span>
              <button
                onClick={handleCopyYaml}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 transition"
              >
                {copied ? <FiCheck size={12} className="text-emerald-400" /> : <FiCopy size={12} />}
                <span>{copied ? 'Copied' : 'Copy YAML'}</span>
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-emerald-300 leading-relaxed overflow-x-auto whitespace-pre">
              {rule.rule_yaml}
            </pre>
          </div>

          {/* Metadata Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="rounded-xl border border-gray-800 bg-[#131722] p-4 space-y-2.5">
              <h4 className="font-bold text-gray-300 uppercase tracking-wider text-[11px]">
                Rule Provenance
              </h4>
              <div className="flex justify-between border-b border-gray-800/60 pb-1.5">
                <span className="text-gray-500">Created:</span>
                <span className="text-gray-300 font-mono">{rule.created_at || 'N/A'}</span>
              </div>
              <div className="flex justify-between border-b border-gray-800/60 pb-1.5">
                <span className="text-gray-500">Created By:</span>
                <span className="text-gray-300">{rule.created_by || 'soc_analyst'}</span>
              </div>
              <div className="flex justify-between border-b border-gray-800/60 pb-1.5">
                <span className="text-gray-500">AI Model:</span>
                <span className="text-purple-400 font-mono">{rule.model_generated || 'harvest-q6'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Approved By:</span>
                <span className="text-gray-300">{rule.approved_by || 'None'}</span>
              </div>
            </div>

            <div className="rounded-xl border border-gray-800 bg-[#131722] p-4 space-y-2.5">
              <h4 className="font-bold text-gray-300 uppercase tracking-wider text-[11px]">
                CTI Prompt / Harvest Source
              </h4>
              <p className="text-gray-400 leading-relaxed italic bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                "{rule.harvest_prompt || 'No harvest prompt captured (human-authored).'}"
              </p>
              {rule.notes && (
                <div className="mt-2 text-gray-400 text-[11px]">
                  <strong className="text-gray-300">Notes:</strong> {rule.notes}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: VALIDATION RESULTS */}
      {activeTab === 'validation' && (
        <div className="space-y-6">
          <ValidationResultPanel result={rule.validation_result} />
        </div>
      )}

      {/* TAB 3: FALSE POSITIVE SAMPLES */}
      {activeTab === 'fp_samples' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <h4 className="text-sm font-bold text-white">
                False Positive Samples Captured by Agent B
              </h4>
              <p className="text-xs text-gray-400">
                Telemetry instances where rule alerted on normal baseline behavior (max 20 samples)
              </p>
            </div>

            <button
              onClick={handleSuggestExclusion}
              disabled={exclusionLoading || (rule.false_positive_samples || []).length === 0}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-bold rounded-lg bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-600/20 transition disabled:opacity-50 w-fit"
            >
              <FiZap size={13} />
              {exclusionLoading ? 'Analyzing...' : 'Suggest Exclusion (Agent A)'}
            </button>
          </div>

          {/* AI Exclusion Suggestion Banner */}
          {suggestedExclusion && (
            <div className="rounded-xl border border-purple-500/40 bg-purple-500/10 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-purple-300">
                <FiZap className="text-purple-400" />
                <span>Agent A Recommended Exclusions:</span>
              </div>
              <div className="text-xs font-mono text-gray-200 bg-gray-900/80 p-3 rounded-lg border border-purple-500/20 whitespace-pre-wrap">
                {suggestedExclusion}
              </div>
            </div>
          )}

          {/* FP Samples Table */}
          <div className="rounded-xl border border-gray-800 bg-[#131722] overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-400 bg-gray-900/40 uppercase tracking-wider">
                    <th className="py-2.5 px-4 font-semibold">Process</th>
                    <th className="py-2.5 px-4 font-semibold">Command Line</th>
                    <th className="py-2.5 px-3 font-semibold">Host</th>
                    <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 font-mono text-[11px]">
                  {(rule.false_positive_samples || []).length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-gray-500 font-sans text-xs">
                        No False Positive samples recorded. Rule has 0% FPR on benchmark dataset!
                      </td>
                    </tr>
                  ) : (
                    rule.false_positive_samples.map((s, idx) => (
                      <tr key={idx} className="hover:bg-gray-800/30">
                        <td className="py-2.5 px-4 text-rose-300 font-bold">{s.process}</td>
                        <td className="py-2.5 px-4 text-gray-300 max-w-md truncate" title={s.cmdline}>
                          {s.cmdline}
                        </td>
                        <td className="py-2.5 px-3 text-gray-400">{s.host}</td>
                        <td className="py-2.5 px-3 text-gray-500">{s.timestamp}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: VERSION HISTORY */}
      {activeTab === 'versions' && (
        <div className="space-y-4">
          <h4 className="text-sm font-bold text-white">Rule Version Audit Trail</h4>
          <div className="space-y-3">
            {(rule.versions || []).map((v) => (
              <div
                key={v.id}
                className="rounded-xl border border-gray-800 bg-[#131722] p-4 text-xs space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      v{v.version_number}
                    </span>
                    <span className="font-semibold text-white">{v.change_reason || 'Initial creation'}</span>
                  </div>
                  <span className="text-gray-500 font-mono">{v.created_at}</span>
                </div>
                <div className="text-gray-400">Author: {v.created_by || 'soc_analyst'}</div>
                <pre className="mt-2 p-3 rounded-lg bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-300 max-h-48 overflow-y-auto">
                  {v.yaml_content}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: ACTIONS LOG */}
      {activeTab === 'actions' && (
        <div className="rounded-xl border border-gray-800 bg-[#131722] p-5 text-xs space-y-4">
          <h4 className="font-bold text-white text-sm">Governance & Compliance Trail</h4>
          <div className="space-y-3 font-sans">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-gray-900/60 border border-gray-800">
              <FiCheck className="text-purple-400 mt-0.5" />
              <div>
                <div className="font-bold text-white">Rule Generated by Agent A</div>
                <div className="text-gray-400 text-[11px]">
                  Generated via model {rule.model_generated} at {rule.created_at}
                </div>
              </div>
            </div>

            {rule.validated_at && (
              <div className="flex items-start gap-3 p-3 rounded-lg bg-gray-900/60 border border-gray-800">
                <FiActivity className="text-blue-400 mt-0.5" />
                <div>
                  <div className="font-bold text-white">Agent B Statistical Validation</div>
                  <div className="text-gray-400 text-[11px]">
                    Validated at {rule.validated_at}. FPR: {rule.fpr != null ? `${(rule.fpr * 100).toFixed(2)}%` : 'N/A'}, Precision: {rule.precision != null ? `${(rule.precision * 100).toFixed(2)}%` : 'N/A'}.
                  </div>
                </div>
              </div>
            )}

            {rule.activated_at && (
              <div className="flex items-start gap-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <FiCheckCircle className="text-emerald-400 mt-0.5" />
                <div>
                  <div className="font-bold text-emerald-300">Activated by {rule.approved_by || 'SOC Lead'}</div>
                  <div className="text-emerald-400/80 text-[11px]">
                    Activated into live detection rules at {rule.activated_at}
                  </div>
                </div>
              </div>
            )}

            {rule.disabled_at && (
              <div className="flex items-start gap-3 p-3 rounded-lg bg-zinc-800/40 border border-zinc-700/40">
                <FiPower className="text-zinc-400 mt-0.5" />
                <div>
                  <div className="font-bold text-zinc-300">Rule Disabled</div>
                  <div className="text-zinc-500 text-[11px]">Disabled at {rule.disabled_at}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
