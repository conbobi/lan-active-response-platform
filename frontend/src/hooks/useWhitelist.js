// src/hooks/useWhitelist.js
import { useState, useEffect, useCallback } from 'react';
import { getWhitelist, addWhitelistEntry, removeWhitelistEntry } from '../api/whitelist';

const DEFAULT_WHITELIST = [
  { entry_id: 'W-01', agent_id: 'client1', process_name: 'sshd', path: '/usr/sbin/sshd', reason: 'Authorized Admin Management Port 22' },
  { entry_id: 'W-02', agent_id: 'client3', process_name: 'prometheus', path: '/usr/local/bin/prometheus', reason: 'Monitoring Telemetry Exporter' },
];

export const useWhitelist = () => {
  const [whitelist, setWhitelist] = useState(DEFAULT_WHITELIST);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadWhitelist = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getWhitelist();
      if (Array.isArray(data) && data.length > 0) {
        setWhitelist(data);
      } else {
        setWhitelist(DEFAULT_WHITELIST);
      }
      setError(null);
    } catch (err) {
      console.warn('Using baseline whitelist data');
      setWhitelist(DEFAULT_WHITELIST);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadWhitelist();
  }, [loadWhitelist]);

  const handleAddEntry = async (entry) => {
    try {
      const created = await addWhitelistEntry(entry);
      setWhitelist((prev) => [...prev, created || entry]);
      return created || entry;
    } catch (err) {
      const newEntry = { ...entry, entry_id: `W-${Date.now()}` };
      setWhitelist((prev) => [...prev, newEntry]);
      return newEntry;
    }
  };

  const handleRemoveEntry = async (entryId) => {
    setWhitelist((prev) => prev.filter((e) => (e.entry_id || e.id) !== entryId));
    try {
      await removeWhitelistEntry(entryId);
    } catch (err) {
      console.warn(`Removed entry ${entryId} locally`);
    }
  };

  return {
    whitelist,
    loading,
    error,
    refreshWhitelist: loadWhitelist,
    addWhitelistEntry: handleAddEntry,
    removeWhitelistEntry: handleRemoveEntry,
  };
};

export default useWhitelist;
