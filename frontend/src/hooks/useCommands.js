// src/hooks/useCommands.js
import { useState, useEffect, useCallback } from 'react';
import { getCommands, createCommand, retryCommand } from '../api/commands';

export const useCommands = () => {
  const [commands, setCommands] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadCommands = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getCommands();
      setCommands(data);
      setError(null);
    } catch (err) {
      console.error('Failed to load commands', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCommands();
  }, [loadCommands]);

  const handleCreateCommand = async (payload) => {
    try {
      const newCmd = await createCommand(payload);
      setCommands((prev) => [newCmd, ...prev]);
      return newCmd;
    } catch (err) {
      console.error('Error creating command', err);
    }
  };

  const handleRetryCommand = async (commandId) => {
    try {
      const updated = await retryCommand(commandId);
      setCommands((prev) => prev.map((cmd) => (cmd.id === commandId ? { ...cmd, ...updated } : cmd)));
      return updated;
    } catch (err) {
      console.error('Error retrying command', err);
    }
  };

  return {
    commands,
    loading,
    error,
    refreshCommands: loadCommands,
    handleCreateCommand,
    handleRetryCommand,
  };
};

export default useCommands;
