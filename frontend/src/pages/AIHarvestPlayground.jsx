import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FiArrowLeft,
  FiCpu,
  FiPlay,
  FiSave,
  FiCopy,
  FiCheck,
  FiRefreshCw,
  FiAlertTriangle,
  FiLayers,
  FiCode,
  FiEdit3,
  FiCheckCircle,
  FiExternalLink
} from 'react-icons/fi';

import api from '../api/api';
import { harvestRule } from '../api/rules';
import ValidationResultPanel from '../components/ai/ValidationResultPanel';
import './AIHarvestPlayground.css';

const SAMPLE_CTI_REPORTS = [
  {
    name: 'FIN7 PowerShell Memory Scraper',
    text: `Threat Actor FIN7 (Carbanak) conducts targeted intrusions using PowerShell execution.
The actor executes obfuscated PowerShell with -ExecutionPolicy Bypass and -nop switches,
downloading second-stage payloads via DownloadString or Invoke-WebRequest from external IP addresses.
Culprit commands frequently invoke IEX(New-Object Net.WebClient).DownloadString to load reflective DLLs.`
  },
  {
    name: 'Ransomware Shadow Copy Deletion',
    text: `Before deploying disk encryption routines, modern ransomware operators (LockBit, BlackCat)
inhibit system recovery by executing vssadmin.exe delete shadows /all /quiet
or wmic.exe shadowcopy delete /nointeractive to permanently purge volume shadow copies.`
  },
  {
    name: 'LSASS Credential Dumping (Mimikatz)',
    text: `Adversaries utilize Mimikatz or procdump to dump credentials from Local Security Authority Subsystem Service (LSASS).
Typical execution involves running mimikatz.exe with arguments 'privilege::debug' 'sekurlsa::logonpasswords'
or procdump.exe -ma lsass.exe to extract cleartext passwords and NTLM hashes.`
  },
  {
    name: 'Web Server Spawning Shell (T1059.004)',
    text: `Adversaries exploit web application vulnerabilities (RCE, command injection) on web servers
(python3 app.py, nginx, apache2, gunicorn, uwsgi) to spawn interactive command shells (/bin/sh, /bin/bash, /bin/dash, zsh).
The resulting child shell executes reconnaissance commands like whoami, id, or curl to retrieve second-stage payloads.`
  },
  {
    name: 'Web Shell File Upload Execution',
    text: `Threat actors upload malicious webshell scripts (.php, .py, .sh, .jsp) into public web upload directories
(/home/webuser/vulnerable_web/uploads, /var/www/uploads, /tmp).
The web server subsequently executes the uploaded file or invokes bash/sh to execute commands passed via HTTP parameters.`
  }
];

export default function AIHarvestPlayground() {
  const navigate = useNavigate();

  const [ctiText, setCtiText] = useState('');
  const [analystId, setAnalystId] = useState('soc_analyst');
  const [generating, setGenerating] = useState(false);
  const [generatedYaml, setGeneratedYaml] = useState('');
  const [ruleCandidateId, setRuleCandidateId] = useState(null);
  const [ruleName, setRuleName] = useState('');
  const [ruleStatus, setRuleStatus] = useState('pending');
  const [ruleSeverity, setRuleSeverity] = useState('medium');
  const [validationResult, setValidationResult] = useState(null);
  const [validating, setValidating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [activating, setActivating] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [copied, setCopied] = useState(false);

  // 1. Generate Rule from CTI (Agent A)
  const handleGenerate = async () => {
    if (!ctiText.trim()) {
      toast.error('Please enter a CTI report or threat intelligence text');
      return;
    }

    try {
      setGenerating(true);
      setValidationResult(null);
      setGeneratedYaml('');
      setRuleCandidateId(null);

      const data = await harvestRule({ cti_text: ctiText.trim(), analyst_id: analystId });
      if (data.error) {
        toast.error(data.error);
      } else {
        setGeneratedYaml(data.rule_yaml || '');
        setRuleCandidateId(data.rule_id);
        setRuleName(data.rule_name || 'AI Harvested Rule');
        setRuleStatus(data.status || 'pending');
        setRuleSeverity(data.severity || 'medium');
        toast.success(`Agent A: Generated Sigma rule '${data.rule_name}'`);
      }
    } catch (err) {
      toast.error(`Harvest request failed: ${err.message || 'Network error'}`);
    } finally {
      setGenerating(false);
    }
  };

  // 2. Save Edited YAML
  const handleSaveYaml = async () => {
    if (!ruleCandidateId) {
      toast.error('No rule candidate loaded to save');
      return;
    }

    try {
      setSaving(true);
      const data = await api.put(`/rules/${ruleCandidateId}`, {
        rule_yaml: generatedYaml,
        analyst_id: analystId,
      });
      if (data.error) {
        toast.error(data.error);
      } else {
        toast.success('Rule YAML updated and new version saved');
        setIsEditing(false);
      }
    } catch (err) {
      toast.error(err.message || 'Failed to save rule changes');
    } finally {
      setSaving(false);
    }
  };

  // 3. Validate Generated Rule (Agent B)
  const handleValidate = async () => {
    if (!ruleCandidateId) {
      toast.error('Please generate or save a rule candidate first');
      return;
    }

    try {
      setValidating(true);
      const data = await api.post(`/rules/${ruleCandidateId}/validate`, {
        fpr_threshold: 0.05,
        precision_threshold: 0.95,
      });
      if (data.error) {
        toast.error(data.error);
      } else {
        setValidationResult(data.validation_result);
        setRuleStatus(data.status);
        if (data.validation_result?.passed) {
          toast.success('Agent B: Rule PASSED statistical validation!');
        } else {
          toast.error('Agent B: Rule FAILED validation (high FPR or low Precision)');
        }
      }
    } catch (err) {
      toast.error(err.message || 'Validation request failed');
    } finally {
      setValidating(false);
    }
  };

  // 4. Activate Rule
  const handleActivate = async () => {
    if (!ruleCandidateId) return;

    try {
      setActivating(true);
      const data = await api.post(`/rules/${ruleCandidateId}/activate`, { analyst_id: analystId });
      if (data.error) {
        toast.error(data.error);
      } else {
        setRuleStatus('active');
        toast.success('Rule successfully activated into detection pipeline!');
      }
    } catch (err) {
      toast.error(err.message || 'Failed to activate rule');
    } finally {
      setActivating(false);
    }
  };

  const handleCopyYaml = () => {
    if (!generatedYaml) return;
    navigator.clipboard.writeText(generatedYaml);
    setCopied(true);
    toast.success('YAML copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleGoToRule = () => {
    if (ruleCandidateId) {
      navigate(`/ai-dashboard/rules/${ruleCandidateId}`);
    }
  };

  return (
    <div className="harvest-playground-root">
      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="harvest-header">
        <button
          onClick={() => navigate('/ai-dashboard')}
          className="harvest-back-btn"
        >
          <FiArrowLeft size={13} /> Back to AI Dashboard
        </button>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h1 className="harvest-title">
              <FiCpu className="harvest-title-icon" />
              AI Harvest Playground
            </h1>
            <p className="harvest-subtitle">
              Synthesize production-grade Sigma detection rules from Cyber Threat Intelligence with Agent A,
              and statistically validate against historical baseline telemetry with Agent B.
            </p>
          </div>
          {ruleCandidateId && (
            <button
              onClick={handleGoToRule}
              className="harvest-btn-secondary"
            >
              <span>Candidate Detail #{ruleCandidateId.slice(0, 8)}</span>
              <FiExternalLink size={12} />
            </button>
          )}
        </div>
      </div>

      {/* ── MAIN 2-COLUMN PLAYGROUND ────────────────────────────────────── */}
      <div className="harvest-grid">
        {/* Left Column: CTI Input */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="harvest-card">
            <div className="harvest-card-header">
              <div className="harvest-card-title">
                <FiLayers color="#c084fc" />
                Raw CTI / Threat Report
              </div>
              <span className="harvest-agent-badge">Agent A: harvest-q6</span>
            </div>

            {/* Quick Templates */}
            <div className="harvest-templates-box">
              <span className="harvest-templates-label">Load sample threat report:</span>
              <div className="harvest-templates-list">
                {SAMPLE_CTI_REPORTS.map((sample, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => setCtiText(sample.text)}
                    className="harvest-template-pill"
                  >
                    {sample.name}
                  </button>
                ))}
              </div>
            </div>

            <textarea
              rows={12}
              value={ctiText}
              onChange={(e) => setCtiText(e.target.value)}
              placeholder="Paste CTI report, threat advisory, blog post excerpt, or list of adversary techniques here..."
              className="harvest-textarea"
            />

            <div className="harvest-bottom-bar">
              <div className="harvest-analyst-input-group">
                <span>Analyst:</span>
                <input
                  type="text"
                  value={analystId}
                  onChange={(e) => setAnalystId(e.target.value)}
                  className="harvest-analyst-input"
                />
              </div>

              <button
                onClick={handleGenerate}
                disabled={generating || !ctiText.trim()}
                className="harvest-btn-generate"
              >
                {generating ? (
                  <>
                    <FiRefreshCw size={14} className="animate-spin" />
                    Synthesizing Sigma Rule...
                  </>
                ) : (
                  <>
                    <FiCpu size={15} />
                    Generate Sigma Rule
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Generated Rule & Validation */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* YAML Output Panel */}
          <div className="harvest-yaml-container">
            <div className="harvest-yaml-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: '#e6edf3' }}>
                <FiCode color="#34d399" />
                <span>Generated Sigma Rule</span>
                {ruleStatus && (
                  <span style={{
                    fontSize: '0.6875rem',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '0.15rem 0.5rem',
                    borderRadius: '0.25rem',
                    background: ruleStatus === 'active' ? 'rgba(16, 185, 129, 0.2)' : ruleStatus === 'validated' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                    color: ruleStatus === 'active' ? '#34d399' : ruleStatus === 'validated' ? '#60a5fa' : '#fbbf24'
                  }}>
                    {ruleStatus}
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {generatedYaml && (
                  <>
                    <button
                      onClick={() => setIsEditing(!isEditing)}
                      className="harvest-btn-secondary"
                      title={isEditing ? 'Switch to View mode' : 'Edit Rule YAML'}
                    >
                      <FiEdit3 size={12} />
                      <span>{isEditing ? 'Preview' : 'Edit'}</span>
                    </button>

                    {isEditing && (
                      <button
                        onClick={handleSaveYaml}
                        disabled={saving}
                        className="harvest-btn-secondary"
                        style={{ borderColor: '#34d399', color: '#34d399' }}
                      >
                        <FiSave size={12} />
                        <span>{saving ? 'Saving...' : 'Save'}</span>
                      </button>
                    )}

                    <button
                      onClick={handleCopyYaml}
                      className="harvest-btn-secondary"
                    >
                      {copied ? <FiCheck size={12} color="#34d399" /> : <FiCopy size={12} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </>
                )}
              </div>
            </div>

            <div className="harvest-yaml-content">
              {generating ? (
                <div className="harvest-loading-state">
                  <FiRefreshCw size={28} className="animate-spin" />
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#ffffff' }}>
                      Agent A is analyzing CTI threat indicators...
                    </div>
                    <div style={{ fontSize: '0.6875rem', color: '#8b949e', marginTop: '0.25rem' }}>
                      Synthesizing Sigma YAML detection criteria & mapping MITRE ATT&CK techniques
                    </div>
                  </div>
                </div>
              ) : generatedYaml ? (
                isEditing ? (
                  <textarea
                    value={generatedYaml}
                    onChange={(e) => setGeneratedYaml(e.target.value)}
                    className="harvest-yaml-editor"
                    spellCheck="false"
                  />
                ) : (
                  <pre style={{ margin: 0, color: '#7ee787', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {generatedYaml}
                  </pre>
                )
              ) : (
                <div className="harvest-empty-state">
                  <FiCpu size={36} color="#30363d" />
                  <div style={{ fontSize: '0.8125rem', color: '#8b949e' }}>
                    Select a sample report on the left or paste threat advisory text, then click{' '}
                    <strong style={{ color: '#c084fc' }}>"Generate Sigma Rule"</strong> to start.
                  </div>
                </div>
              )}
            </div>

            {/* Validation & Activation Action Bar */}
            {generatedYaml && (
              <div className="harvest-yaml-actions-bar">
                <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>
                  Rule status:{' '}
                  <strong style={{
                    color: ruleStatus === 'active' ? '#34d399' : ruleStatus === 'validated' ? '#60a5fa' : '#fbbf24'
                  }}>
                    {ruleStatus}
                  </strong>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                  <button
                    onClick={handleValidate}
                    disabled={validating}
                    className="harvest-btn-validate"
                  >
                    <FiPlay size={13} />
                    {validating ? 'Running Agent B Validation...' : 'Validate on Historical Logs'}
                  </button>

                  {ruleStatus === 'validated' && (
                    <button
                      onClick={handleActivate}
                      disabled={activating}
                      className="harvest-btn-activate"
                    >
                      <FiCheckCircle size={13} />
                      {activating ? 'Activating...' : 'Activate Rule'}
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Validation Results Panel */}
          {validationResult && (
            <div className="harvest-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <h3 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <FiPlay color="#60a5fa" />
                  Statistical Benchmark (Agent B Evaluation)
                </h3>
              </div>
              <ValidationResultPanel result={validationResult} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
