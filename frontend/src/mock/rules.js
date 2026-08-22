// src/mock/rules.js
// Enhanced Security Rules Database with Audit Log and Simulation logic

export let rules = [
  {
    id: 'rule-001',
    name: 'DNS Spoofing Detection',
    description: 'Alert when internal device queries external DNS server directly',
    type: 'dns',
    severity: 'high',
    status: 'active',
    conditions: {
      protocol: 'DNS',
      dest_port: 53,
      internal_dns_servers: ['192.168.1.1', '10.0.0.2'],
    },
    action: 'alert',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-15T10:00:00Z',
    updated_at: '2025-01-20T14:30:00Z',
  },
  {
    id: 'rule-002',
    name: 'Unauthorized Proxy Connection',
    description: 'Detect HTTP/HTTPS traffic originating from non-approved proxy servers',
    type: 'proxy',
    severity: 'medium',
    status: 'active',
    conditions: {
      protocol: 'HTTP/S',
      proxy_server_ip: ['10.0.0.254', '192.168.1.254'],
    },
    action: 'log',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'soc_analyst',
    created_at: '2025-01-16T11:20:00Z',
    updated_at: '2025-01-22T09:15:00Z',
  },
  {
    id: 'rule-003',
    name: 'IRC Botnet C2 Channel Detection',
    description: 'Detect internal hosts connecting to IRC ports commonly used by Botnet C2',
    type: 'botnet',
    severity: 'critical',
    status: 'active',
    conditions: {
      pattern: 'IRC_JOIN_CHANNEL',
      signature_hash: 'c2_irc_beacon_v1',
    },
    action: 'isolate',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-18T08:45:00Z',
    updated_at: '2025-01-25T16:00:00Z',
  },
  {
    id: 'rule-004',
    name: 'SYN Flood Rate Limiter',
    description: 'Block IP addresses sending over 5000 SYN packets per second',
    type: 'rate_limit',
    severity: 'high',
    status: 'active',
    conditions: {
      max_connections: 5000,
      time_window: 1,
    },
    action: 'block',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'system',
    created_at: '2025-01-19T14:10:00Z',
    updated_at: '2025-02-01T12:00:00Z',
  },
  {
    id: 'rule-005',
    name: 'Known Malicious Threat IP Blacklist',
    description: 'Drop connections to known malicious C2 and threat actor IP ranges',
    type: 'blacklist',
    severity: 'critical',
    status: 'active',
    conditions: {
      blocked_ips: ['198.51.100.45', '203.0.113.88'],
      blocked_domains: ['malware-c2-domain.com', 'badactor-phish.net'],
    },
    action: 'block',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-20T09:00:00Z',
    updated_at: '2025-02-03T18:20:00Z',
  },
  {
    id: 'rule-006',
    name: 'Restrict Inbound SSH Access (Port 22)',
    description: 'Restrict SSH access on critical host servers to administrative VLAN only',
    type: 'firewall',
    severity: 'medium',
    status: 'active',
    conditions: {
      allowed_ports: [22],
      protocols: ['TCP'],
      direction: 'inbound',
    },
    action: 'block',
    scope: 'selected_agents',
    agent_ids: ['agent-001', 'agent-003', 'agent-006'],
    created_by: 'soc_analyst',
    created_at: '2025-01-21T13:30:00Z',
    updated_at: '2025-02-05T10:45:00Z',
  },
  {
    id: 'rule-007',
    name: 'LSASS Memory Injection (EDR)',
    description: 'Detect process attempting memory dump or injection into lsass.exe',
    type: 'edr',
    severity: 'critical',
    status: 'active',
    conditions: {
      pattern: 'lsass_access_0x1F0FFF',
      signature_hash: 'edr_lsass_dump_hash_99',
    },
    action: 'quarantine',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-23T15:00:00Z',
    updated_at: '2025-02-08T11:10:00Z',
  },
  {
    id: 'rule-008',
    name: 'YARA Ransomware Dropper Signature',
    description: 'Match binary patterns corresponding to LockBit 3.0 ransomware droppers',
    type: 'signature',
    severity: 'critical',
    status: 'active',
    conditions: {
      pattern: 'LockBit3_Header_Sig',
      signature_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    action: 'quarantine',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-25T17:15:00Z',
    updated_at: '2025-02-09T14:50:00Z',
  },
  {
    id: 'rule-009',
    name: 'Rogue External DNS Tunneling',
    description: 'Detect high-volume TXT record queries indicating DNS data exfiltration',
    type: 'dns',
    severity: 'medium',
    status: 'inactive',
    conditions: {
      protocol: 'DNS',
      dest_port: 53,
      internal_dns_servers: ['192.168.1.1'],
    },
    action: 'log',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'soc_analyst',
    created_at: '2025-01-27T10:00:00Z',
    updated_at: '2025-02-10T08:30:00Z',
  },
  {
    id: 'rule-010',
    name: 'Outbound Reverse Shell Behavior',
    description: 'Detect cmd.exe or powershell.exe establishing outbound TCP connection',
    type: 'edr',
    severity: 'critical',
    status: 'active',
    conditions: {
      pattern: 'cmd_powershell_reverse_shell',
      signature_hash: 'edr_revshell_tcp_outbound',
    },
    action: 'isolate',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-01-28T12:40:00Z',
    updated_at: '2025-02-11T15:20:00Z',
  },
  {
    id: 'rule-011',
    name: 'HTTP POST Burst Rate Limit',
    description: 'Throttle excessive HTTP POST requests targeting login endpoints',
    type: 'rate_limit',
    severity: 'high',
    status: 'active',
    conditions: {
      max_connections: 200,
      time_window: 5,
    },
    action: 'block',
    scope: 'selected_agents',
    agent_ids: ['agent-001', 'agent-004'],
    created_by: 'soc_analyst',
    created_at: '2025-01-30T14:00:00Z',
    updated_at: '2025-02-12T09:40:00Z',
  },
  {
    id: 'rule-012',
    name: 'TOR Exit Node Connection Block',
    description: 'Block all inbound/outbound communication with TOR anonymizing exit nodes',
    type: 'proxy',
    severity: 'high',
    status: 'active',
    conditions: {
      protocol: 'ANY',
      proxy_server_ip: ['185.220.101.5', '185.220.101.7'],
    },
    action: 'block',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-02-01T16:20:00Z',
    updated_at: '2025-02-12T11:00:00Z',
  },
  {
    id: 'rule-013',
    name: 'Cobalt Strike Beacon Pattern',
    description: 'Detect HTTP/HTTPS heartbeat telemetry matching Cobalt Strike default Malleable C2 profile',
    type: 'botnet',
    severity: 'critical',
    status: 'active',
    conditions: {
      pattern: 'CobaltStrike_Beacon_URI',
      signature_hash: 'cs_malleable_c2_hash_88',
    },
    action: 'isolate',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-02-03T11:15:00Z',
    updated_at: '2025-02-12T13:10:00Z',
  },
  {
    id: 'rule-014',
    name: 'Block SMB Port 445 Cross-Subnet',
    description: 'Prevent lateral movement by blocking inter-workstation SMB port 445 traffic',
    type: 'firewall',
    severity: 'high',
    status: 'inactive',
    conditions: {
      allowed_ports: [445],
      protocols: ['TCP'],
      direction: 'inbound',
    },
    action: 'block',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'admin',
    created_at: '2025-02-04T09:30:00Z',
    updated_at: '2025-02-12T14:00:00Z',
  },
  {
    id: 'rule-015',
    name: 'Phishing Domain Blacklist Filter',
    description: 'Alert and redirect traffic attempting to reach recognized phishing domain hashes',
    type: 'blacklist',
    severity: 'medium',
    status: 'active',
    conditions: {
      blocked_ips: ['192.0.2.14'],
      blocked_domains: ['secure-verify-account.com', 'login-update-auth.org'],
    },
    action: 'alert',
    scope: 'all_agents',
    agent_ids: [],
    created_by: 'soc_analyst',
    created_at: '2025-02-06T15:45:00Z',
    updated_at: '2025-02-12T16:30:00Z',
  },
];

export let auditLogs = [
  {
    id: 'audit-001',
    rule_id: 'rule-001',
    rule_name: 'DNS Spoofing Detection',
    action: 'CREATE',
    user: 'admin',
    timestamp: '2025-01-15T10:00:00Z',
    details: 'Initial rule created with DNS port 53 monitoring.',
  },
  {
    id: 'audit-002',
    rule_id: 'rule-005',
    rule_name: 'Known Malicious Threat IP Blacklist',
    action: 'UPDATE',
    user: 'admin',
    timestamp: '2025-02-03T18:20:00Z',
    details: 'Added blocked IP 203.0.113.88 to blacklist conditions.',
  },
  {
    id: 'audit-003',
    rule_id: 'rule-009',
    rule_name: 'Rogue External DNS Tunneling',
    action: 'TOGGLE_STATUS',
    user: 'soc_analyst',
    timestamp: '2025-02-10T08:30:00Z',
    details: 'Changed status from active to inactive.',
  },
];

// Add audit log helper
const logAudit = (ruleId, ruleName, action, user = 'admin', details = '') => {
  auditLogs = [
    {
      id: `audit-${String(auditLogs.length + 1).padStart(3, '0')}`,
      rule_id: ruleId,
      rule_name: ruleName,
      action,
      user,
      timestamp: new Date().toISOString(),
      details,
    },
    ...auditLogs,
  ];
};

export const getRules = () => Promise.resolve([...rules]);

export const getAuditLogs = () => Promise.resolve([...auditLogs]);

export const addRule = (newRule, user = 'admin') => {
  const id = `rule-${String(rules.length + 1).padStart(3, '0')}`;
  const rule = {
    id,
    name: newRule.name || 'Untitled Rule',
    description: newRule.description || '',
    type: newRule.type || 'dns',
    severity: newRule.severity || 'medium',
    status: newRule.status || 'active',
    conditions: newRule.conditions || {},
    action: newRule.action || 'alert',
    scope: newRule.scope || 'all_agents',
    agent_ids: newRule.agent_ids || [],
    created_by: user,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  rules = [rule, ...rules];
  logAudit(id, rule.name, 'CREATE', user, `Rule created with type '${rule.type}' and action '${rule.action}'.`);
  return Promise.resolve(rule);
};

export const updateRule = (id, updatedFields, user = 'admin') => {
  let oldRule = null;
  rules = rules.map((r) => {
    if (r.id === id) {
      oldRule = r;
      return {
        ...r,
        ...updatedFields,
        updated_at: new Date().toISOString(),
      };
    }
    return r;
  });
  const updatedRule = rules.find((r) => r.id === id);
  if (updatedRule) {
    logAudit(id, updatedRule.name, 'UPDATE', user, `Updated rule configuration.`);
  }
  return Promise.resolve(updatedRule);
};

export const deleteRule = (id, user = 'admin') => {
  const target = rules.find((r) => r.id === id);
  rules = rules.filter((r) => r.id !== id);
  if (target) {
    logAudit(id, target.name, 'DELETE', user, `Deleted rule permanently.`);
  }
  return Promise.resolve(true);
};

export const toggleRuleStatus = (id, user = 'admin') => {
  let target = null;
  rules = rules.map((r) => {
    if (r.id === id) {
      target = { ...r, status: r.status === 'active' ? 'inactive' : 'active', updated_at: new Date().toISOString() };
      return target;
    }
    return r;
  });
  if (target) {
    logAudit(id, target.name, 'TOGGLE_STATUS', user, `Status changed to '${target.status}'.`);
  }
  return Promise.resolve(target);
};

// Conflict detection logic
export const checkRuleConflicts = (candidateRule) => {
  const conflicts = [];

  for (const existing of rules) {
    // Skip self if editing
    if (candidateRule.id && existing.id === candidateRule.id) continue;

    // Check duplicate name
    if (existing.name.trim().toLowerCase() === candidateRule.name.trim().toLowerCase()) {
      conflicts.push(`Duplicate Rule Name: "${existing.name}" already exists (${existing.id}).`);
    }

    // Check firewall port conflicts with different actions
    if (existing.type === 'firewall' && candidateRule.type === 'firewall') {
      const existingPorts = existing.conditions?.allowed_ports || [];
      const newPorts = candidateRule.conditions?.allowed_ports || [];
      const overlap = existingPorts.filter((p) => newPorts.includes(p));

      if (overlap.length > 0 && existing.action !== candidateRule.action) {
        conflicts.push(
          `Firewall Conflict: Port(s) ${overlap.join(', ')} configured in "${existing.name}" (${existing.id}) with action '${existing.action}', but candidate has action '${candidateRule.action}'.`
        );
      }
    }

    // Check blacklist conflict
    if (existing.type === 'blacklist' && candidateRule.type === 'blacklist') {
      const existingIps = existing.conditions?.blocked_ips || [];
      const newIps = candidateRule.conditions?.blocked_ips || [];
      const ipOverlap = existingIps.filter((ip) => newIps.includes(ip));

      if (ipOverlap.length > 0) {
        conflicts.push(
          `Blacklist Overlap: IP(s) ${ipOverlap.join(', ')} are already blacklisted in rule "${existing.name}" (${existing.id}).`
        );
      }
    }
  }

  return conflicts;
};

// Simulation testing logic
export const simulateRuleTest = (payload) => {
  // payload: { ip, domain, port, protocol, process, hash }
  const activeRules = rules.filter((r) => r.status === 'active');
  const matchedRules = [];

  for (const rule of activeRules) {
    let isMatch = false;
    const cond = rule.conditions || {};

    if (rule.type === 'dns') {
      if ((payload.protocol === 'DNS' || payload.port === 53) && payload.ip) {
        const internalDns = cond.internal_dns_servers || [];
        if (internalDns.length > 0 && !internalDns.includes(payload.ip)) {
          isMatch = true;
        }
      }
    } else if (rule.type === 'proxy') {
      const proxyIps = cond.proxy_server_ip || [];
      if (proxyIps.includes(payload.ip)) {
        isMatch = true;
      }
    } else if (rule.type === 'rate_limit') {
      if (payload.rate && payload.rate > (cond.max_connections || 100)) {
        isMatch = true;
      }
    } else if (rule.type === 'blacklist') {
      const bIps = cond.blocked_ips || [];
      const bDomains = cond.blocked_domains || [];
      if ((payload.ip && bIps.includes(payload.ip)) || (payload.domain && bDomains.includes(payload.domain))) {
        isMatch = true;
      }
    } else if (rule.type === 'firewall') {
      const ports = cond.allowed_ports || [];
      if (payload.port && ports.includes(Number(payload.port))) {
        isMatch = true;
      }
    } else if (rule.type === 'edr' || rule.type === 'signature' || rule.type === 'botnet') {
      if (
        (payload.hash && cond.signature_hash && payload.hash.toLowerCase() === cond.signature_hash.toLowerCase()) ||
        (payload.process && cond.pattern && payload.process.toLowerCase().includes(cond.pattern.toLowerCase()))
      ) {
        isMatch = true;
      }
    }

    if (isMatch) {
      matchedRules.push(rule);
    }
  }

  return matchedRules;
};

// Import/Export helpers
export const importRulesList = (newRulesList, user = 'admin') => {
  if (!Array.isArray(newRulesList)) {
    throw new Error('Invalid JSON format: Expected an array of rules.');
  }

  let importedCount = 0;
  newRulesList.forEach((r) => {
    if (r.name && r.type) {
      const id = `rule-${String(rules.length + 1).padStart(3, '0')}`;
      const newR = {
        id,
        name: r.name,
        description: r.description || '',
        type: r.type,
        severity: r.severity || 'medium',
        status: r.status || 'active',
        conditions: r.conditions || {},
        action: r.action || 'alert',
        scope: r.scope || 'all_agents',
        agent_ids: r.agent_ids || [],
        created_by: user,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      rules = [newR, ...rules];
      importedCount++;
    }
  });

  logAudit('ALL', 'BATCH_IMPORT', 'IMPORT', user, `Imported ${importedCount} rules from JSON file.`);
  return Promise.resolve(importedCount);
};

export default rules;
