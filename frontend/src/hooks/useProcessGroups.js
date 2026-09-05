// src/hooks/useProcessGroups.js
import { useState, useEffect, useCallback } from 'react';
import {
  getProcessGroups,
  createProcessGroup,
  updateProcessGroup,
  deleteProcessGroup,
} from '../api/processGroups';

export const useProcessGroups = () => {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadGroups = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getProcessGroups();
      setGroups(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Error fetching process groups:', err);
      setError(err.message || 'Failed to load process groups');
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadGroups();
  }, [loadGroups]);

  const handleCreateGroup = async (payload) => {
    try {
      const created = await createProcessGroup(payload);
      setGroups((prev) => [...prev, created]);
      return created;
    } catch (err) {
      console.error('Failed to create process group:', err);
      throw err;
    }
  };

  const handleUpdateGroup = async (id, payload) => {
    try {
      const updated = await updateProcessGroup(id, payload);
      setGroups((prev) =>
        prev.map((g) => (g.id === id ? { ...g, ...updated } : g))
      );
      return updated;
    } catch (err) {
      console.error(`Failed to update process group ${id}:`, err);
      throw err;
    }
  };

  const handleDeleteGroup = async (id) => {
    const previous = [...groups];
    setGroups((prev) => prev.filter((g) => g.id !== id));
    try {
      await deleteProcessGroup(id);
    } catch (err) {
      setGroups(previous);
      console.error(`Failed to delete process group ${id}:`, err);
      throw err;
    }
  };

  return {
    groups,
    loading,
    error,
    refreshGroups: loadGroups,
    handleCreateGroup,
    handleUpdateGroup,
    handleDeleteGroup,
  };
};

export default useProcessGroups;
