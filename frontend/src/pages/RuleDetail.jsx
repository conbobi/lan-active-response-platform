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
import './RuleDetail.css';

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
      <div className="rule-detail-root" style={{ alignItems: 'center', justifyContent: 'center', minHeight: '300px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#8b949e', fontSize: '0.875rem' }}>
          <div style={{ width: '1rem', height: '1rem', borderRadius: '50%', border: '2px solid #8b949e', borderTopColor: '#c084fc', animation: 'spin 1s linear infinite' }} />
          Loading rule candidate...
        </div>
      </div>
    );
  }

  if (!rule) {
    return (
      <div className="rule-detail-root">
        <button
          onClick={() => navigate('/ai-dashboard')}
          className="rule-detail-back-btn"
        >
          <FiArrowLeft size={14} /> Back to AI SOC Studio
        </button>
        <div className="rule-meta-card" style={{ padding: '2.5rem', textAlign: 'center', color: '#8b949e', fontSize: '0.875rem' }}>
          Rule candidate not found.
        </div>
      </div>
    );
  }

  const sev = (rule.severity || 'medium').toLowerCase();

  return (
    <div className="rule-detail-root">
      {/* ── BACK BUTTON & ACTIONS TOP BAR ───────────────────────────────── */}
      <div className="rule-detail-top-nav">
        <button
          onClick={() => navigate('/ai-dashboard')}
          className="rule-detail-back-btn"
        >
          <FiArrowLeft size={14} /> Back to AI SOC Studio
        </button>

        {/* Action Buttons Top Right */}
        <div className="rule-detail-actions-group">
          {rule.status === 'pending' && (
            <button
              onClick={handleValidate}
              disabled={actionLoading}
              className="btn-action btn-validate"
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
                className="btn-action btn-activate"
              >
                <FiCheckCircle size={13} />
                Activate Rule
              </button>
              <button
                onClick={handleReject}
                disabled={actionLoading}
                className="btn-action btn-reject"
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
              className="btn-action btn-disable"
            >
              <FiPower size={13} />
              Disable
            </button>
          )}
        </div>
      </div>

      {/* ── RULE TITLE & METADATA HERO CARD ────────────────────────────── */}
      <div className="rule-hero-card">
        <div className="rule-hero-header">
          <div className="rule-hero-left">
            <div className="rule-hero-title-row">
              <h2 className="rule-hero-title">
                {rule.rule_name}
              </h2>
              <div className="rule-hero-badges">
                <SourceBadge source={rule.source} />
                <StatusBadge status={rule.status} />
                <span className={`rule-sev-pill sev-${sev}`}>
                  {sev.toUpperCase()}
                </span>
              </div>
            </div>
            <div className="rule-hero-subline">
              <span className="rule-id-badge">ID: {rule.id}</span>
            </div>
          </div>

          <div className="rule-hero-right">
            <span className="rule-mitre-label">MITRE:</span>
            <MITRETags techniques={rule.mitre_techniques || []} max={6} />
          </div>
        </div>

        {/* Quick KPI stats strip */}
        <div className="rule-hero-kpi-grid">
          <div className="rule-kpi-block">
            <span className="rule-kpi-title">False Positive Rate</span>
            <div className={`rule-kpi-metric ${rule.fpr != null ? (rule.fpr < 0.05 ? 'metric-good' : rule.fpr <= 0.10 ? 'metric-warn' : 'metric-bad') : ''}`}>
              {rule.fpr != null ? `${(rule.fpr * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div className="rule-kpi-block">
            <span className="rule-kpi-title">Precision</span>
            <div className={`rule-kpi-metric ${rule.precision != null ? (rule.precision >= 0.95 ? 'metric-good' : rule.precision >= 0.85 ? 'metric-warn' : 'metric-bad') : ''}`}>
              {rule.precision != null ? `${(rule.precision * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div className="rule-kpi-block">
            <span className="rule-kpi-title">Recall</span>
            <div className={`rule-kpi-metric ${rule.recall != null ? (rule.recall >= 0.90 ? 'metric-good' : 'metric-warn') : ''}`}>
              {rule.recall != null ? `${(rule.recall * 100).toFixed(2)}%` : 'Not tested'}
            </div>
          </div>
          <div className="rule-kpi-block">
            <span className="rule-kpi-title">Model Engine</span>
            <div className="rule-kpi-metric metric-engine">
              {rule.model_generated || 'harvest-q6'}
            </div>
          </div>
        </div>
      </div>

      {/* ── TABS NAVIGATION BAR ─────────────────────────────────────────── */}
      <div className="rule-tabs-bar">
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
            className={`rule-tab-button ${activeTab === tab.key ? 'active' : ''}`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── TAB CONTENT ────────────────────────────────────────────────── */}

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="rule-overview-section">
          {/* YAML Viewer */}
          <div className="rule-yaml-card">
            <div className="rule-yaml-header">
              <span>Sigma Rule Definition (YAML)</span>
              <button
                onClick={handleCopyYaml}
                className="btn-copy-yaml"
              >
                {copied ? <FiCheck size={12} style={{ color: '#34d399' }} /> : <FiCopy size={12} />}
                <span>{copied ? 'Copied' : 'Copy YAML'}</span>
              </button>
            </div>
            <pre className="rule-yaml-code">
              {rule.rule_yaml}
            </pre>
          </div>

          {/* Metadata Cards */}
          <div className="rule-meta-columns">
            <div className="rule-meta-card">
              <h4 className="rule-meta-card-title">
                Rule Provenance
              </h4>
              <div className="rule-meta-row">
                <span className="rule-meta-key">Created:</span>
                <span className="rule-meta-val val-mono">{rule.created_at || 'N/A'}</span>
              </div>
              <div className="rule-meta-row">
                <span className="rule-meta-key">Created By:</span>
                <span className="rule-meta-val">{rule.created_by || 'soc_analyst'}</span>
              </div>
              <div className="rule-meta-row">
                <span className="rule-meta-key">AI Model:</span>
                <span className="rule-meta-val val-mono val-purple">{rule.model_generated || 'harvest-q6'}</span>
              </div>
              <div className="rule-meta-row">
                <span className="rule-meta-key">Approved By:</span>
                <span className="rule-meta-val">{rule.approved_by || 'None'}</span>
              </div>
            </div>

            <div className="rule-meta-card">
              <h4 className="rule-meta-card-title">
                CTI Prompt / Harvest Source
              </h4>
              <p className="rule-prompt-quote">
                "{rule.harvest_prompt || 'No harvest prompt captured (human-authored).'}"
              </p>
              {rule.notes && (
                <div style={{ fontSize: '0.75rem', color: '#8b949e', marginTop: '0.25rem' }}>
                  <strong style={{ color: '#e6edf3' }}>Notes:</strong> {rule.notes}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: VALIDATION RESULTS */}
      {activeTab === 'validation' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%' }}>
          <ValidationResultPanel result={rule.validation_result} />
        </div>
      )}

      {/* TAB 3: FALSE POSITIVE SAMPLES */}
      {activeTab === 'fp_samples' && (
        <div className="rule-fp-section">
          <div className="rule-fp-top">
            <div>
              <h4 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>
                False Positive Samples Captured by Agent B
              </h4>
              <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.75rem', color: '#8b949e' }}>
                Telemetry instances where rule alerted on normal baseline behavior (max 20 samples)
              </p>
            </div>

            <button
              onClick={handleSuggestExclusion}
              disabled={exclusionLoading || (rule.false_positive_samples || []).length === 0}
              className="btn-suggest-exclusion"
            >
              <FiZap size={13} />
              {exclusionLoading ? 'Analyzing...' : 'Suggest Exclusion (Agent A)'}
            </button>
          </div>

          {/* AI Exclusion Suggestion Banner */}
          {suggestedExclusion && (
            <div className="rule-exclusion-box">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', fontWeight: 700, color: '#d8b4fe' }}>
                <FiZap style={{ color: '#c084fc' }} />
                <span>Agent A Recommended Exclusions:</span>
              </div>
              <pre className="rule-exclusion-pre">
                {suggestedExclusion}
              </pre>
            </div>
          )}

          {/* FP Samples Table */}
          <div className="rule-table-card">
            <div style={{ overflowX: 'auto' }}>
              <table className="rule-data-table">
                <thead>
                  <tr>
                    <th>Process</th>
                    <th>Command Line</th>
                    <th>Host</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody style={{ fontFamily: "'JetBrains Mono', ui-monospace, monospace", fontSize: '0.75rem' }}>
                  {(rule.false_positive_samples || []).length === 0 ? (
                    <tr>
                      <td colSpan={4} style={{ padding: '2.5rem', textAlign: 'center', color: '#8b949e', fontFamily: 'inherit' }}>
                        No False Positive samples recorded. Rule has 0% FPR on benchmark dataset!
                      </td>
                    </tr>
                  ) : (
                    rule.false_positive_samples.map((s, idx) => (
                      <tr key={idx}>
                        <td style={{ color: '#fda4af', fontWeight: 700 }}>{s.process}</td>
                        <td style={{ color: '#cbd5e1', maxWidth: '380px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.cmdline}>
                          {s.cmdline}
                        </td>
                        <td style={{ color: '#94a3b8' }}>{s.host}</td>
                        <td style={{ color: '#64748b' }}>{s.timestamp}</td>
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h4 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>Rule Version Audit Trail</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {(rule.versions || []).map((v) => (
              <div key={v.id} className="rule-version-card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className="rule-version-chip">v{v.version_number}</span>
                    <span style={{ fontWeight: 600, color: '#ffffff' }}>{v.change_reason || 'Initial creation'}</span>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: '#8b949e', fontFamily: 'monospace' }}>{v.created_at}</span>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>Author: {v.created_by || 'soc_analyst'}</div>
                <pre style={{ margin: 0, padding: '0.75rem', borderRadius: '0.5rem', background: '#0f172a', border: '1px solid #334155', fontSize: '0.75rem', fontFamily: "'JetBrains Mono', monospace", color: '#cbd5e1', maxHeight: '12rem', overflowY: 'auto' }}>
                  {v.yaml_content}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: ACTIONS LOG */}
      {activeTab === 'actions' && (
        <div className="rule-meta-card" style={{ padding: '1.25rem', gap: '1rem' }}>
          <h4 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 700, color: '#ffffff' }}>Governance & Compliance Trail</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div className="rule-log-row">
              <FiCheck style={{ color: '#c084fc', marginTop: '0.2rem', flexShrink: 0 }} />
              <div>
                <div style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.8125rem' }}>Rule Generated by Agent A</div>
                <div style={{ color: '#8b949e', fontSize: '0.75rem' }}>
                  Generated via model {rule.model_generated} at {rule.created_at}
                </div>
              </div>
            </div>

            {rule.validated_at && (
              <div className="rule-log-row">
                <FiActivity style={{ color: '#60a5fa', marginTop: '0.2rem', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 700, color: '#ffffff', fontSize: '0.8125rem' }}>Agent B Statistical Validation</div>
                  <div style={{ color: '#8b949e', fontSize: '0.75rem' }}>
                    Validated at {rule.validated_at}. FPR: {rule.fpr != null ? `${(rule.fpr * 100).toFixed(2)}%` : 'N/A'}, Precision: {rule.precision != null ? `${(rule.precision * 100).toFixed(2)}%` : 'N/A'}.
                  </div>
                </div>
              </div>
            )}

            {rule.activated_at && (
              <div className="rule-log-row log-active">
                <FiCheckCircle style={{ color: '#34d399', marginTop: '0.2rem', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 700, color: '#6ee7b7', fontSize: '0.8125rem' }}>Activated by {rule.approved_by || 'SOC Lead'}</div>
                  <div style={{ color: '#34d399', fontSize: '0.75rem' }}>
                    Activated into live detection rules at {rule.activated_at}
                  </div>
                </div>
              </div>
            )}

            {rule.disabled_at && (
              <div className="rule-log-row">
                <FiPower style={{ color: '#94a3b8', marginTop: '0.2rem', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: '0.8125rem' }}>Rule Disabled</div>
                  <div style={{ color: '#64748b', fontSize: '0.75rem' }}>Disabled at {rule.disabled_at}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
