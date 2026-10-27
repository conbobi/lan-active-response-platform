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
    <div className="flex h-screen bg-gray-50">
      <div className="flex-1 overflow-y-auto">
        <div className="p-6 max-w-6xl">
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-2xl font-bold">🌐 Network Monitor</h1>
            <span className="flex items-center gap-2 text-sm text-green-600">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              Live · 5s
            </span>
          </div>
          
          <div className="flex gap-3 mb-6 flex-wrap">
            <select
              value={filters.agent}
              onChange={e => setFilters({...filters, agent: e.target.value})}
              className="border border-gray-300 rounded px-3 py-1.5 text-sm"
            >
              <option value="all">Tất cả agents</option>
              {agents.map(a => (
                <option key={a.id} value={a.id}>{a.id}</option>
              ))}
            </select>
            <select
              value={filters.time}
              onChange={e => setFilters({...filters, time: e.target.value})}
              className="border border-gray-300 rounded px-3 py-1.5 text-sm"
            >
              <option value="1h">1 giờ qua</option>
              <option value="24h">24 giờ qua</option>
              <option value="7d">7 ngày qua</option>
            </select>
            <select
              value={filters.risk}
              onChange={e => setFilters({...filters, risk: e.target.value})}
              className="border border-gray-300 rounded px-3 py-1.5 text-sm"
            >
              <option value="all">Tất cả mức độ</option>
              <option value="high">🔴 High</option>
              <option value="medium">🟠 Medium</option>
              <option value="low">🟢 Low</option>
            </select>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 mb-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              🚨 Suspicious Connections
              <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded text-sm font-normal">
                {suspicious.length}
              </span>
            </h2>
            
            {loading ? (
              <div className="space-y-3">
                {[1,2,3].map(i => (
                  <div key={i} className="bg-gray-100 rounded-lg p-4 animate-pulse h-24" />
                ))}
              </div>
            ) : suspicious.length === 0 ? (
              <div className="text-center text-green-600 py-8">
                <div className="text-4xl mb-2">✅</div>
                <div className="font-medium">Không có kết nối đáng ngờ</div>
                <div className="text-sm text-gray-500 mt-1">
                  {filters.time === '1h' ? 'trong 1 giờ qua' : `trong ${filters.time}`}
                </div>
              </div>
            ) : (
              <div className="space-y-3">
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
          
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
              <h2 className="font-semibold mb-4">📊 Top Talkers</h2>
              {topTalkers.length === 0 ? (
                <div className="text-center text-gray-400 py-4 text-sm">Không có dữ liệu</div>
              ) : (
                <div className="space-y-2">
                  {topTalkers.map((t, i) => (
                    <div key={i} className="flex justify-between items-center text-sm py-1">
                      <span className="font-mono truncate">{t.process_name}</span>
                      <span className="text-gray-600 whitespace-nowrap ml-2">
                        {t.connections} conn · {t.unique_destinations} dest
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
              <h2 className="font-semibold mb-4">🌐 L7 Protocols</h2>
              {protocols.length === 0 ? (
                <div className="text-center text-gray-400 py-4 text-sm">Không có dữ liệu</div>
              ) : (
                <div className="space-y-2">
                  {protocols.map((p, i) => (
                    <div key={i} className="flex justify-between items-center text-sm py-1">
                      <span className="font-mono">{p.protocol}</span>
                      <span className="text-gray-600">{p.count}</span>
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
          onBlockIP={() => alert('Block IP: chưa implement — roadmap Phase 2')}
          onKillProcess={() => navigate(`/network/${selected.id}/investigate`)}
          onInvestigate={() => navigate(`/network/${selected.id}/investigate`)}
        />
      )}
    </div>
  );
}
