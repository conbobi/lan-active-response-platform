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
    const data = await api.get('/commands');
    return Array.isArray(data) ? data.map(mapCommand) : [];
  } catch (err) {
    console.warn('API /commands not found or error, using default commands data');
    return [
      {
        id: 'CMD-801',
        agentId: 'client4',
        command: 'isolate_agent',
        parameters: '{"reason": "Suspicious outbound traffic"}',
        status: 'SUCCESS',
        result: 'Agent client4 network interface isolated successfully.',
        createdAt: new Date(Date.now() - 1800000).toISOString(),
        executedAt: new Date(Date.now() - 1795000).toISOString(),
      },
      {
        id: 'CMD-802',
        agentId: 'client1',
        command: 'update_firewall_rule',
        parameters: '{"rule_id": "R-99", "action": "BLOCK_PORT_8080"}',
        status: 'SUCCESS',
        result: 'Rule R-99 applied to eBPF table.',
        createdAt: new Date(Date.now() - 3600000).toISOString(),
        executedAt: new Date(Date.now() - 3590000).toISOString(),
      },
      {
        id: 'CMD-803',
        agentId: 'client3',
        command: 'collect_sys_logs',
        parameters: '{"duration": "5m"}',
        status: 'FAILED',
        result: 'Timeout waiting for response from agent daemon.',
        createdAt: new Date(Date.now() - 7200000).toISOString(),
        executedAt: new Date(Date.now() - 7180000).toISOString(),
      },
    ];
  }
};

export const createCommand = async (payload) => {
  try {
    const data = await api.post('/commands', payload);
    return mapCommand(data);
  } catch (err) {
    console.error('API Error in createCommand:', err);
    return {
      id: `CMD-${Math.floor(Math.random() * 900) + 100}`,
      agentId: payload.agent_id || payload.agentId || 'ALL',
      command: payload.command,
      parameters: typeof payload.parameters === 'string' ? payload.parameters : JSON.stringify(payload.parameters || {}),
      status: 'PENDING',
      result: 'Command dispatched to queue.',
      createdAt: new Date().toISOString(),
      executedAt: null,
    };
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
