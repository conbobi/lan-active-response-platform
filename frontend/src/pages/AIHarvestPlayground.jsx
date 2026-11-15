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
  FiCode
} from 'react-icons/fi';

import ValidationResultPanel from '../components/ai/ValidationResultPanel';

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
  }
];

export default function AIHarvestPlayground() {
  const navigate = useNavigate();

  const [ctiText, setCtiText] = useState('');
  const [analystId, setAnalystId] = useState('soc_analyst');
  const [generating, setGenerating] = useState(false);
  const [generatedYaml, setGeneratedYaml] = useState('');
  const [ruleCandidateId, setRuleCandidateId] = useState(null);
  const [validationResult, setValidationResult] = useState(null);
  const [validating, setValidating] = useState(false);
  const [copied, setCopied] = useState(false);

  // 1. Generate Rule from CTI (Agent A)
  const handleGenerate = async () => {
    if (!ctiText.trim()) {
      toast.error('Please enter CTI report or threat intelligence text');
      return;
    }

    try {
      setGenerating(true);
      setValidationResult(null);
      setGeneratedYaml('');

      const res = await fetch('/api/v1/rules/harvest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cti_text: ctiText, analyst_id: analystId })
      });

      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        setGeneratedYaml(data.rule_yaml);
        setRuleCandidateId(data.rule_id);
        toast.success(`Agent A: Generated Sigma rule '${data.rule_name}'`);
      }
    } catch (err) {
      toast.error('Harvest request failed');
    } finally {
      setGenerating(false);
    }
  };

  // 2. Validate Generated Rule (Agent B)
  const handleValidate = async () => {
    if (!ruleCandidateId) {
      toast.error('Please generate or save a rule candidate first');
      return;
    }

    try {
      setValidating(true);
      const res = await fetch(`/api/v1/rules/${ruleCandidateId}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fpr_threshold: 0.05, precision_threshold: 0.95 })
      });

      const data = await res.json();
      if (data.error) {
        toast.error(data.error);
      } else {
        setValidationResult(data.validation_result);
        if (data.validation_result?.passed) {
          toast.success('Agent B: Rule PASSED statistical validation!');
        } else {
          toast.error('Agent B: Rule FAILED validation (high FPR or low Precision)');
        }
      }
    } catch (err) {
      toast.error('Validation request failed');
    } finally {
      setValidating(false);
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
    <div className="space-y-6 pb-12">
      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <button
            onClick={() => navigate('/ai-dashboard')}
            className="flex items-center gap-1.5 text-xs font-semibold text-gray-400 hover:text-white transition w-fit mb-2"
          >
            <FiArrowLeft size={13} /> Back to AI Dashboard
          </button>
          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
            <FiCpu className="text-purple-400" />
            AI Harvest Playground
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Feed raw Cyber Threat Intelligence into Agent A, auto-generate Sigma detection rules,
            and statistically benchmark them with Agent B before deployment.
          </p>
        </div>
      </div>

      {/* ── MAIN 2-COLUMN PLAYGROUND ────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: CTI Input */}
        <div className="lg:col-span-5 space-y-4">
          <div className="rounded-xl border border-gray-800 bg-[#131722] p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                <FiLayers className="text-purple-400" />
                Raw CTI / Threat Report
              </label>
              <span className="text-[11px] text-gray-500">Agent A: harvest-q6</span>
            </div>

            {/* Quick Templates */}
            <div>
              <span className="text-[11px] text-gray-400 block mb-1.5">Or load sample threat report:</span>
              <div className="flex flex-wrap gap-1.5">
                {SAMPLE_CTI_REPORTS.map((sample, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => setCtiText(sample.text)}
                    className="px-2 py-1 text-[11px] rounded bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700/60 transition"
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
              className="w-full rounded-lg bg-gray-900 border border-gray-700 p-3 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 font-sans leading-relaxed"
            />

            <div className="flex items-center justify-between pt-2">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-400">Analyst:</span>
                <input
                  type="text"
                  value={analystId}
                  onChange={(e) => setAnalystId(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-gray-900 border border-gray-700 text-white w-28 focus:outline-none focus:border-purple-500"
                />
              </div>

              <button
                onClick={handleGenerate}
                disabled={generating || !ctiText.trim()}
                className="flex items-center gap-2 px-4 py-2.5 text-xs font-bold rounded-lg bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-600/20 transition disabled:opacity-50"
              >
                {generating ? (
                  <>
                    <FiRefreshCw size={13} className="animate-spin" />
                    Generating Sigma Rule...
                  </>
                ) : (
                  <>
                    <FiCpu size={14} />
                    Generate Sigma Rule
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Generated Rule & Validation */}
        <div className="lg:col-span-7 space-y-6">
          {/* YAML Output Panel */}
          <div className="rounded-xl border border-gray-800 bg-[#131722] shadow-sm overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 bg-gray-900 border-b border-gray-800 text-xs">
              <span className="font-bold text-gray-300 flex items-center gap-2">
                <FiCode className="text-emerald-400" />
                Generated Sigma Rule (YAML)
              </span>

              <div className="flex items-center gap-2">
                {generatedYaml && (
                  <button
                    onClick={handleCopyYaml}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 transition"
                  >
                    {copied ? <FiCheck size={12} className="text-emerald-400" /> : <FiCopy size={12} />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                )}

                {ruleCandidateId && (
                  <button
                    onClick={handleGoToRule}
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 transition font-semibold"
                  >
                    View Candidate &rarr;
                  </button>
                )}
              </div>
            </div>

            <div className="p-4 bg-[#0d1117] min-h-[280px]">
              {generating ? (
                <div className="flex flex-col items-center justify-center h-64 gap-3 text-purple-400">
                  <FiRefreshCw size={24} className="animate-spin" />
                  <span className="text-xs font-medium text-gray-400">
                    Agent A is parsing CTI and synthesizing Sigma detection logic...
                  </span>
                </div>
              ) : generatedYaml ? (
                <pre className="text-xs font-mono text-emerald-300 leading-relaxed overflow-x-auto whitespace-pre">
                  {generatedYaml}
                </pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-64 text-gray-500 text-xs text-center px-4">
                  <FiCpu size={32} className="mb-2 text-gray-600" />
                  Click "Generate Sigma Rule" on the left to invoke Agent A and synthesize a detection rule.
                </div>
              )}
            </div>

            {/* Validation Action Bar */}
            {generatedYaml && (
              <div className="p-3 bg-gray-900/60 border-t border-gray-800 flex items-center justify-between">
                <span className="text-xs text-gray-400">
                  Candidate saved with status <strong className="text-amber-400">pending</strong>.
                </span>
                <button
                  onClick={handleValidate}
                  disabled={validating}
                  className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-lg bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20 transition disabled:opacity-50"
                >
                  <FiPlay size={13} />
                  {validating ? 'Running Agent B Validation...' : 'Validate on Historical Logs'}
                </button>
              </div>
            )}
          </div>

          {/* Validation Results Panel */}
          {validationResult && (
            <div className="rounded-xl border border-gray-800 bg-[#131722] p-5 shadow-sm space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                Statistical Benchmark (Agent B Evaluation)
              </h3>
              <ValidationResultPanel result={validationResult} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

