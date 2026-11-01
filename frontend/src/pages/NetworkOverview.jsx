import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ConnectionRow from '../components/network/ConnectionRow';
import ConnectionDetail from '../components/network/ConnectionDetail';
import { getSuspiciousConnections, getTopTalkers, getProtocols } from '../api/network';
import { getAgents } from '../api/agents';

export default function NetworkOverview() {
  const navigate = useNavigate();
  const [suspicious, setSuspicious] = useState([]);
  const [topTalkers, setTopTalkers] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [agents, setAgents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ agent: 'all', time: '1h', risk: 'all' });
  
  useEffect(() => {
    getAgents().then(setAgents).catch(() => []);
  }, []);
  
  const load = useCallback(async () => {
    try {
      const [s, t, p] = await Promise.all([
        getSuspiciousConnections(filters),
        getTopTalkers(filters),
        getProtocols(filters),
      ]);
      setSuspicious(s);
      setTopTalkers(t);
      setProtocols(p);
    } catch (e) {
      console.error('Load network error:', e);
    } finally {
      setLoading(false);
    }
  }, [filters]);
  
  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);
  
  return (
    <div style={{ display: 'flex', gap: '1.25rem', width: '100%', minHeight: '600px' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
            <h1 className="page-title" style={{ margin: 0 }}>🌐 Network Flow Monitor</h1>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--success)' }}>
              <span className="live-dot" />
              Live Telemetry (5s)
            </span>
          </div>
          
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
            <select
              value={filters.agent}
              onChange={e => setFilters({...filters, agent: e.target.value})}
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-primary)',
                color: 'var(--text-primary)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
              }}
            >
              <option value="all">Tất cả agents</option>
              {agents.map(a => (
                <option key={a.id} value={a.id}>{a.name || a.hostname || a.id}</option>
              ))}
            </select>
            <select
              value={filters.time}
              onChange={e => setFilters({...filters, time: e.target.value})}
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-primary)',
                color: 'var(--text-primary)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
              }}
            >
              <option value="1h">1 giờ qua</option>
              <option value="24h">24 giờ qua</option>
              <option value="7d">7 ngày qua</option>
            </select>
            <select
              value={filters.risk}
              onChange={e => setFilters({...filters, risk: e.target.value})}
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border-primary)',
                color: 'var(--text-primary)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.45rem 0.75rem',
                fontSize: '0.85rem',
              }}
            >
              <option value="all">Tất cả mức độ</option>
              <option value="high">🔴 High Risk</option>
              <option value="medium">🟠 Medium Risk</option>
              <option value="low">🟢 Low Risk</option>
            </select>
          </div>
          
          <div className="card" style={{ padding: '1.25rem', marginBottom: '1.25rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-primary)' }}>
              🚨 Suspicious Egress & Ingress Connections
              <span style={{ background: 'var(--critical-dim)', color: 'var(--critical)', border: '1px solid var(--critical)', padding: '0.1rem 0.5rem', borderRadius: 'var(--radius-full)', fontSize: '0.75rem' }}>
                {suspicious.length}
              </span>
            </h2>
            
            {loading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {[1,2,3].map(i => (
                  <div key={i} className="card skeleton" style={{ height: '70px' }} />
                ))}
              </div>
            ) : suspicious.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--success)', padding: '2rem 0' }}>
                <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>✅</div>
                <div style={{ fontWeight: 600 }}>Không có kết nối mạng đáng ngờ</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {filters.time === '1h' ? 'trong 1 giờ qua' : `trong ${filters.time}`}
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {suspicious.map(conn => (
                  <ConnectionRow
                    key={conn.id}
                    conn={conn}
                    isActive={selected?.id === conn.id}
                    onClick={() => setSelected(conn)}
                  />
                ))}
              </div>
            )}
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
            <div className="card" style={{ padding: '1.25rem' }}>
              <h2 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--text-primary)' }}>📊 Top Talkers</h2>
              {topTalkers.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: '1rem 0', fontSize: '0.85rem' }}>Không có dữ liệu</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {topTalkers.map((t, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem', padding: '0.35rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
                      <span className="pid-mono" style={{ maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.process_name}</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', whiteSpace: 'nowrap', marginLeft: '0.5rem' }}>
                        {t.connections} conn · {t.unique_destinations} dest
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            
            <div className="card" style={{ padding: '1.25rem' }}>
              <h2 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '0.75rem', color: 'var(--text-primary)' }}>🌐 L7 Protocols</h2>
              {protocols.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: '1rem 0', fontSize: '0.85rem' }}>Không có dữ liệu</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {protocols.map((p, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem', padding: '0.35rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
                      <span className="pid-mono">{p.protocol}</span>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{p.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {selected && (
        <ConnectionDetail
          conn={selected}
          onClose={() => setSelected(null)}
          onBlockIP={() => alert(`Block IP ${selected.dst_ip}: Đang gửi lệnh cách ly firewall`)}
          onKillProcess={() => navigate(`/investigate?tab=process&agent=${encodeURIComponent(selected.agent_id)}&pid=${selected.pid}`)}
          onInvestigate={() => navigate(`/investigate?tab=process&agent=${encodeURIComponent(selected.agent_id)}&pid=${selected.pid}`)}
        />
      )}
    </div>
  );
}
