// src/api/commands.js
import api from './api';

export const mapCommand = (cmd) => {
  if (!cmd) return null;
  return {
    id: cmd.id,
    agentId: cmd.agent_id || cmd.agentId || 'ALL',
    command: cmd.command || cmd.action || 'isolate_agent',
    parameters: typeof cmd.parameters === 'object' ? JSON.stringify(cmd.parameters) : (cmd.parameters || '{}'),
    status: (cmd.status || 'PENDING').toUpperCase(), // PENDING, EXECUTING, SUCCESS, FAILED
    result: cmd.result || cmd.response || null,
    createdAt: cmd.created_at || cmd.createdAt || new Date().toISOString(),
    executedAt: cmd.executed_at || cmd.executedAt || null,
  };
};

export const getCommands = async () => {
  try {
    const data = await api.get('/commands/');
    return Array.isArray(data) ? data.map(mapCommand) : [];
  } catch (err) {
    console.error('API /commands/ error:', err);
    throw err;
  }
};

export const createCommand = async (payload) => {
  try {
    const data = await api.post('/commands/', payload);
    return mapCommand(data);
  } catch (err) {
    console.error('API Error in createCommand:', err);
    throw err;
  }
};

export const retryCommand = async (commandId) => {
  try {
    const data = await api.post(`/commands/${commandId}/retry`);
    return mapCommand(data);
  } catch (err) {
    console.error(`API Error retrying command ${commandId}:`, err);
    return {
      id: commandId,
      status: 'EXECUTING',
      executedAt: new Date().toISOString(),
    };
  }
};
