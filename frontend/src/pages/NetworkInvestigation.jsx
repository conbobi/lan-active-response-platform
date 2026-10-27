import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getFlowDetail } from '../api/network';

export default function NetworkInvestigation() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [flow, setFlow] = useState(null);
  
  useEffect(() => {
    getFlowDetail(id).then(setFlow).catch(console.error);
  }, [id]);
  
  if (!flow) {
    return (
      <div className="p-6 text-center text-gray-500">
        Đang tải...
      </div>
    );
  }
  
  return (
    <div className="p-6 max-w-5xl mx-auto">
      <button
        onClick={() => navigate('/network')}
        className="text-blue-600 hover:underline mb-4 flex items-center gap-1"
      >
        ← Quay lại Network
      </button>
      
      <h1 className="text-2xl font-bold mb-6">
        🔍 Điều tra: {flow.process_name} → {flow.dst_ip}:{flow.dst_port}
      </h1>
      
      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="bg-white rounded-xl shadow-sm border p-5">
          <h2 className="font-semibold mb-4">📦 Process</h2>
          <div className="space-y-2 text-sm">
            <div><b>Name:</b> <span className="font-mono">{flow.process_name}</span></div>
            <div><b>PID:</b> <span className="font-mono">{flow.pid}</span></div>
            <div><b>Agent:</b> {flow.agent_id}</div>
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-sm border p-5">
          <h2 className="font-semibold mb-4">🎯 Destination</h2>
          <div className="space-y-2 text-sm">
            <div><b>IP:</b> <span className="font-mono">{flow.dst_ip}</span></div>
            <div><b>Port:</b> <span className="font-mono">{flow.dst_port}</span></div>
            <div><b>Protocol:</b> {flow.protocol}</div>
          </div>
        </div>
      </div>
      
      <div className="bg-white rounded-xl shadow-sm border p-5">
        <h2 className="font-semibold mb-4">📊 Traffic</h2>
        <div className="space-y-2 text-sm">
          <div><b>Bytes sent:</b> {flow.bytes_sent?.toLocaleString() || 0}</div>
          <div><b>Packets sent:</b> {flow.packets_sent?.toLocaleString() || 0}</div>
          <div><b>Detected at:</b> {new Date(flow.created_at).toLocaleString('vi-VN')}</div>
        </div>
      </div>
      
      <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg text-sm text-yellow-800">
        ⚠ Timeline + MITRE + Similar connections: Roadmap Phase 2
      </div>
    </div>
  );
}
