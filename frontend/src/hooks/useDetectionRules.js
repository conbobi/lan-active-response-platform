// src/hooks/useDetectionRules.js
import { useState, useEffect, useCallback } from 'react';
import {
  getDetectionRules,
  createDetectionRule,
  updateDetectionRule,
  deleteDetectionRule,
} from '../api/detectionRules';

const DEFAULT_13_RULES = [
  { rule_id: 'R-01', name: 'Process Chain Analysis', description: 'Detects suspicious parent-child process relationships (cmd.exe, powershell spawning certutil, wmic)', enabled: true, weight: 25, config: { max_depth: 4 } },
  { rule_id: 'R-02', name: 'Volume Shadow Copy Deletion', description: 'Detects vssadmin or wmic shadowcopy delete commands commonly used by Ransomware', enabled: true, weight: 35, config: { command_patterns: ['vssadmin delete shadows', 'wmic shadowcopy delete'] } },
  { rule_id: 'R-03', name: 'Abnormal CPU Anomaly', description: 'Monitors sustained CPU utilization spikes above baseline threshold', enabled: true, weight: 15, config: { threshold_pct: 85 } },
  { rule_id: 'R-04', name: 'Registry Run Key Modification', description: 'Monitors persistence mechanisms in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', enabled: true, weight: 20, config: { hive: 'HKLM' } },
  { rule_id: 'R-05', name: 'Credential Access Detection', description: 'Detects LSASS memory dumping or access via Mimikatz / ProcDump signature', enabled: true, weight: 30, config: { target_process: 'lsass.exe' } },
  { rule_id: 'R-06', name: 'Lateral Movement Monitor', description: 'Detects Remote Execution via PsExec, WMI, WinRM or SMB spread across LAN', enabled: true, weight: 25, config: { ports: [445, 135, 5985] } },
  { rule_id: 'R-07', name: 'Mass File Modification', description: 'Detects rapid encryption or renaming of files indicating active ransomware burst', enabled: true, weight: 40, config: { max_files_per_sec: 50 } },
  { rule_id: 'R-08', name: 'Suspicious Command Line Input', description: 'Detects encoded PowerShell scripts (-Enc), obfuscated commands, or web shells', enabled: true, weight: 20, config: { check_encoded: true } },
  { rule_id: 'R-09', name: 'C2 External Network Connection', description: 'Detects egress traffic to known malicious C2 IP addresses or untrusted ports', enabled: true, weight: 25, config: { block_c2: true } },
  { rule_id: 'R-10', name: 'Rapid File Creation/Deletion', description: 'Monitors high rate of temporary payload drops or log wipe attempts', enabled: true, weight: 15, config: { file_change_limit: 100 } },
  { rule_id: 'R-11', name: 'DGA DNS Query Monitoring', description: 'Detects DNS queries to Algorithmically Generated Domains (DGA) or suspicious TLDs', enabled: true, weight: 20, config: { entropy_threshold: 3.8 } },
  { rule_id: 'R-12', name: 'Probe Agent Telemetry', description: 'Monitors probe eBPF telemetry packet loss and port scan probes', enabled: true, weight: 10, config: { probe_interval_ms: 1000 } },
  { rule_id: 'R-13', name: 'Dead Agent Heartbeat Failure', description: 'Triggers alert when an agent fails to check-in within timeout interval', enabled: true, weight: 15, config: { heartbeat_timeout_s: 30 } },
];

export const useDetectionRules = () => {
  const [rules, setRules] = useState(DEFAULT_13_RULES);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getDetectionRules();
      if (Array.isArray(data) && data.length > 0) {
        setRules(data);
      } else {
        setRules(DEFAULT_13_RULES);
      }
      setError(null);
    } catch (err) {
      console.warn('Using baseline 13 detection rules');
      setRules(DEFAULT_13_RULES);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleToggleRule = async (ruleId) => {
    const target = rules.find((r) => r.rule_id === ruleId);
    if (!target) return;
    const newStatus = !target.enabled;
    setRules((prev) => prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: newStatus } : r)));
    try {
      await updateDetectionRule(ruleId, { ...target, enabled: newStatus });
    } catch (err) {
      console.warn(`Local toggle state updated for ${ruleId}`);
    }
  };

  const handleUpdateWeight = async (ruleId, newWeight) => {
    setRules((prev) => prev.map((r) => (r.rule_id === ruleId ? { ...r, weight: Number(newWeight) } : r)));
    const target = rules.find((r) => r.rule_id === ruleId);
    if (target) {
      try {
        await updateDetectionRule(ruleId, { ...target, weight: Number(newWeight) });
      } catch (err) {
        console.warn(`Weight local update for ${ruleId}`);
      }
    }
  };

  const handleCreateRule = async (ruleData) => {
    try {
      const created = await createDetectionRule(ruleData);
      setRules((prev) => [...prev, created || ruleData]);
      return created || ruleData;
    } catch (err) {
      const fallbackRule = { ...ruleData, rule_id: ruleData.rule_id || `R-${rules.length + 1}` };
      setRules((prev) => [...prev, fallbackRule]);
      return fallbackRule;
    }
  };

  const handleDeleteRule = async (ruleId) => {
    setRules((prev) => prev.filter((r) => r.rule_id !== ruleId));
    try {
      await deleteDetectionRule(ruleId);
    } catch (err) {
      console.warn(`Deleted local rule ${ruleId}`);
    }
  };

  return {
    rules,
    loading,
    error,
    refreshRules: loadRules,
    handleToggleRule,
    handleUpdateWeight,
    handleCreateRule,
    handleDeleteRule,
  };
};

export default useDetectionRules;
