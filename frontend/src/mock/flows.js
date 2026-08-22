// src/mock/flows.js
// Sample network flow data points (timestamp, syn, udp, total)
export const flows = Array.from({ length: 20 }, (_, i) => {
  const timestamp = Date.now() - (20 - i) * 5000; // 5‑second intervals
  return {
    timestamp,
    syn: Math.floor(Math.random() * 100),
    udp: Math.floor(Math.random() * 80),
    total: Math.floor(Math.random() * 180),
  };
});
export default flows;