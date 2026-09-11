// src/components/RiskScoreChart.jsx
import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid
} from 'recharts';

export function RiskScoreChart({ data }) {
  const chartData = (data || [])
    .slice()
    .reverse()
    .map((r) => ({
      time: new Date(r.timestamp).toLocaleTimeString('vi-VN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      raw: Number(Number(r.score).toFixed(2)),
      smoothed: Number(Number(r.smoothed_score ?? r.score).toFixed(2)),
    }));

  return (
    <div style={{ width: '100%', height: 320, marginTop: '16px' }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.25} />
          <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
          <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={11} />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              borderColor: '#334155',
              color: '#f8fafc',
              borderRadius: '6px',
              fontSize: '12px'
            }}
          />
          <Legend wrapperStyle={{ paddingTop: '10px' }} />
          <Line
            type="monotone"
            dataKey="raw"
            stroke="#818cf8"
            name="Raw Score"
            dot={false}
            strokeWidth={1.5}
          />
          <Line
            type="monotone"
            dataKey="smoothed"
            stroke="#10b981"
            name="Smoothed (EMA)"
            strokeWidth={2.5}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export default RiskScoreChart;
