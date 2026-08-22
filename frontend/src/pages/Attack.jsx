import React, { useState, useRef, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler } from 'chart.js';
import Button from '../components/ui/Button';
import { FiZap, FiSquare, FiTerminal } from 'react-icons/fi';
import api from '../api/api';
import { useAgents } from '../hooks/useAgents';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler);

const makeLog = (msg, type = 'normal') => ({
  id: Date.now() + Math.random(),
  msg,
  type,
  time: new Date().toLocaleTimeString(),
});

export default function Attack() {
  const { agents } = useAgents();

  // State chính
  const [status, setStatus] = useState('idle'); // idle | running | stopped
  const [logs, setLogs] = useState([makeLog('Attack Simulation ready. Select target and launch.', 'ok')]);
  const [packets, setPackets] = useState([0]);
  const [labels, setLabels] = useState(['0s']);
  const [targetAgentId, setTargetAgentId] = useState('');
  const [targetIp, setTargetIp] = useState('');
  const [port, setPort] = useState('80');
  const [duration, setDuration] = useState('10');
  const [loading, setLoading] = useState(false);

  const intervalRef = useRef(null);
  const logRef = useRef(null);
  const t = useRef(0);

  const addLog = (msg, type) => setLogs((p) => [...p.slice(-60), makeLog(msg, type)]);

  // Khi chọn agent, tự động điền IP
  const handleAgentSelect = (e) => {
    const agentId = e.target.value;
    setTargetAgentId(agentId);
    const agent = agents.find((a) => a.id === agentId);
    setTargetIp(agent ? agent.ip : '');
  };

  const launch = async () => {
    if (!targetAgentId || !targetIp) {
      addLog('Please select a target agent.', 'warn');
      return;
    }
    setLoading(true);
    setStatus('running');
    addLog(`[SYN Flood] Targeting ${targetIp}:${port} — LAUNCHING`, 'warn');
    try {
      await api.post('/attack/syn-flood', {
        target_agent_id: targetAgentId,
        target_ip: targetIp,
        target_port: Number(port),
        duration: Number(duration),
      });
      addLog('Attack command sent successfully.', 'ok');
    } catch (err) {
      addLog(`Error: ${err.message}`, 'err');
    } finally {
      setLoading(false);
      setStatus('stopped');
    }
  };

  const stop = () => {
    clearInterval(intervalRef.current);
    setStatus('stopped');
    addLog('[STOPPED] Attack terminated by operator.', 'ok');
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => () => clearInterval(intervalRef.current), []);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'Packets/s',
        data: packets,
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239,68,68,0.1)',
        tension: 0.4,
        fill: true,
        pointRadius: 2,
        borderWidth: 2,
      },
    ],
  };
  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      y: { beginAtZero: true, grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8', font: { size: 10 } } },
      x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 10 }, maxTicksLimit: 8 } },
    },
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Simulation</h1>
          <p className="page-subtitle">Controlled SYN Flood simulation for testing defenses</p>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
        <div className="card">
          <h3 style={{ fontWeight: 700, marginBottom: '1rem', fontSize: '0.95rem' }}>Target Configuration</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {/* Dropdown chọn agent mục tiêu */}
            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                Target Agent
              </label>
              <select
                value={targetAgentId}
                onChange={handleAgentSelect}
                disabled={status === 'running'}
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.875rem',
                  background: 'var(--bg)',
                  color: 'var(--text-primary)',
                  outline: 'none',
                  fontFamily: 'inherit',
                }}
              >
                <option value="">-- Select Agent --</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.hostname} ({agent.ip})
                  </option>
                ))}
              </select>
            </div>

            {/* Hiển thị IP đã chọn (read-only) */}
            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                Target IP
              </label>
              <input
                value={targetIp}
                readOnly
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.875rem',
                  background: 'var(--bg)',
                  color: 'var(--text-primary)',
                  outline: 'none',
                  fontFamily: 'inherit',
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                Port
              </label>
              <input
                value={port}
                onChange={(e) => setPort(e.target.value)}
                disabled={status === 'running'}
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.875rem',
                  background: 'var(--bg)',
                  color: 'var(--text-primary)',
                  outline: 'none',
                  fontFamily: 'inherit',
                }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.3rem' }}>
                Duration (seconds)
              </label>
              <input
                value={duration}
                onChange={(e) => setDuration(e.target.value)}
                disabled={status === 'running'}
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.875rem',
                  background: 'var(--bg)',
                  color: 'var(--text-primary)',
                  outline: 'none',
                  fontFamily: 'inherit',
                }}
              />
            </div>
          </div>

          <div className={`attack-status ${status}`} style={{ marginTop: '1rem' }}>
            <span className={`attack-dot ${status}`} />
            {status === 'idle' ? 'Ready to launch' : status === 'running' ? 'Attack in progress...' : 'Attack stopped'}
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.75rem' }}>
            <Button
              variant="danger"
              size="md"
              iconLeft={<FiZap size={14} />}
              onClick={launch}
              disabled={status === 'running' || loading}
            >
              Launch SYN Flood
            </Button>
            <Button
              variant="outline"
              size="md"
              iconLeft={<FiSquare size={14} />}
              onClick={stop}
              disabled={status !== 'running'}
            >
              Stop
            </Button>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <FiZap size={16} color="var(--error)" />
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Packets/sec</span>
          </div>
          <div style={{ height: 180 }}>
            <Line data={chartData} options={chartOpts} />
          </div>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <FiTerminal size={16} color="var(--primary)" />
          <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Attack Log</span>
        </div>
        <div className="log-terminal" ref={logRef}>
          {logs.map((l) => (
            <div
              key={l.id}
              className={`log-line ${l.type === 'err' ? 'log-err' : l.type === 'ok' ? 'log-ok' : l.type === 'warn' ? 'log-warn' : ''}`}
            >
              <span style={{ opacity: 0.5, marginRight: '0.75rem' }}>[{l.time}]</span>{l.msg}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}