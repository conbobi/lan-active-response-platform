// src/mock/events.js
// 30 mock alert events
export const events = Array.from({ length: 30 }, (_, i) => {
  const severityOptions = ['Low', 'Medium', 'High', 'Critical'];
  const typeOptions = ['block_ip', 'isolate', 'alert', 'malware', 'login_failure'];
  const random = (arr) => arr[Math.floor(Math.random() * arr.length)];
  return {
    id: `event-${i + 1}`.padStart(4, '0'),
    timestamp: Date.now() - i * 60000, // 1 min apart
    type: random(typeOptions),
    severity: random(severityOptions),
    sourceIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
    agentId: `agent-00${Math.floor(Math.random() * 10) + 1}`,
    description: `Mock ${random(typeOptions)} event`,
    riskScore: Math.floor(Math.random() * 101),
  };
});
export default events;
