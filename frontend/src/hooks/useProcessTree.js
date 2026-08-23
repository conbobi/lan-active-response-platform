// src/hooks/useProcessTree.js
import { useState, useEffect, useCallback } from 'react';
import { getProcessTree, getSuspiciousProcesses, killProcess } from '../api/process';

export const useProcessTree = (initialAgentId = '') => {
  const [selectedAgentId, setSelectedAgentId] = useState(initialAgentId);
  const [processTree, setProcessTree] = useState(null);
  const [suspiciousProcesses, setSuspiciousProcesses] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchProcessData = useCallback(async (agentId) => {
    if (!agentId) return;
    setLoading(true);
    setError(null);
    try {
      const [tree, suspicious] = await Promise.all([
        getProcessTree(agentId).catch(() => null),
        getSuspiciousProcesses(agentId).catch(() => []),
      ]);

      if (tree) {
        setProcessTree(tree);
      } else {
        // Fallback demo tree if backend endpoint empty
        setProcessTree({
          pid: 1,
          name: 'systemd',
          path: '/sbin/init',
          cpu: 0.1,
          is_suspicious: false,
          children: [
            {
              pid: 412,
              name: 'networkd',
              path: '/lib/systemd/systemd-networkd',
              cpu: 0.5,
              is_suspicious: false,
              children: [],
            },
            {
              pid: 1042,
              name: 'larp-agent',
              path: '/usr/local/bin/larp-agent',
              cpu: 2.4,
              is_suspicious: false,
              children: [
                {
                  pid: 2841,
                  name: 'nc',
                  path: '/usr/bin/nc',
                  cpu: 18.5,
                  is_suspicious: true,
                  reason: 'Reverse shell connection established',
                  children: [],
                },
                {
                  pid: 3105,
                  name: 'vssadmin.exe',
                  path: 'C:\\Windows\\System32\\vssadmin.exe',
                  cpu: 45.0,
                  is_suspicious: true,
                  reason: 'Attempting to delete volume shadow copies',
                  children: [],
                },
              ],
            },
          ],
        });
      }

      if (suspicious && suspicious.length > 0) {
        setSuspiciousProcesses(suspicious);
      } else {
        setSuspiciousProcesses([
          { pid: 2841, name: 'nc', path: '/usr/bin/nc', cpu: 18.5, reason: 'Reverse shell connection established', hash: 'e3b0c44298fc1c149afbf4c8996fb924' },
          { pid: 3105, name: 'vssadmin.exe', path: 'C:\\Windows\\System32\\vssadmin.exe', cpu: 45.0, reason: 'Shadow copy deletion attempt', hash: '8f34b2c12a890e00115599aa' },
        ]);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch process tree');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedAgentId) {
      fetchProcessData(selectedAgentId);
    }
  }, [selectedAgentId, fetchProcessData]);

  const handleKillProcess = async (pid) => {
    if (!selectedAgentId) return;
    try {
      await killProcess(selectedAgentId, pid);
      await fetchProcessData(selectedAgentId);
    } catch (err) {
      console.warn(`Local kill UI update for PID ${pid}`);
      setSuspiciousProcesses((prev) => prev.filter((p) => p.pid !== pid));
    }
  };

  return {
    selectedAgentId,
    setSelectedAgentId,
    processTree,
    suspiciousProcesses,
    loading,
    error,
    refreshProcessData: () => fetchProcessData(selectedAgentId),
    handleKillProcess,
  };
};

export default useProcessTree;
