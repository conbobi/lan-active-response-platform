import { useEffect, useState } from 'react';
import { FiDatabase } from 'react-icons/fi';
import { threatMemoryMetrics } from '../../api/threatMemory';

// Real Threat Memory observability from recorded analysis decisions; nothing is shown without data.
const pct = (v) => (v == null ? 'Chưa đủ dữ liệu' : `${Math.round(v * 100)}%`);
const dur = (v) => (v == null ? 'Chưa đủ dữ liệu' : v >= 1000 ? `${(v / 1000).toFixed(1)} giây` : `${Math.round(v)} ms`);

export default function ThreatMemoryMetrics() {
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    threatMemoryMetrics(7).then(setM).catch((err) => setError(err.message));
  }, []);
  const cells = m ? [
    ['Dùng lại mẫu đã kiểm chứng', pct(m.exact_hit_rate)], ['Tham khảo mẫu tương tự', pct(m.semantic_rate)],
    ['Phân tích mới bằng AI', pct(m.miss_rate)], ['Phân tích dự phòng', pct(m.fallback_rate)],
    ['Thời gian khi dùng lại mẫu', dur(m.avg_total_ms_exact)], ['Thời gian khi gọi AI', dur(m.avg_total_ms_llm)],
    ['Thời gian tra cứu bộ nhớ', dur(m.avg_lookup_ms)], ['Mẫu bị loại vì không còn hợp lệ', pct(m.stale_rejection_rate)],
    ['Lỗi bộ nhớ', pct(m.error_rate)], ['Mẫu hết hiệu lực / thu hồi', m.entries ? String(m.invalidated_entries) : 'Chưa đủ dữ liệu'],
  ] : [];
  return (
    <div className="rounded-xl p-4 min-w-0" style={{ border: '1px solid #30363d', background: '#0d1117' }}>
      <h3 className="text-sm font-bold text-white flex items-center gap-2" style={{ marginBottom: '0.6rem' }}>
        <FiDatabase /> AI Threat Memory (7 ngày) {m && <span style={{ color: '#8b949e', fontWeight: 400 }}>· {m.analyses} lượt phân tích · {m.entries} mẫu</span>}
      </h3>
      {error && <div style={{ color: '#fb7185', fontSize: '0.8rem' }}>Không tải được chỉ số: {error}</div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: '0.5rem' }}>
        {cells.map(([label, value]) => (
          <div key={label} style={{ background: '#161b22', borderRadius: '0.4rem', padding: '0.5rem 0.65rem' }}>
            <div style={{ fontSize: '0.72rem', color: '#8b949e' }}>{label}</div>
            <div style={{ fontSize: '0.95rem', color: value === 'Chưa đủ dữ liệu' ? '#6e7681' : '#e6edf3', fontWeight: 600 }}>{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
