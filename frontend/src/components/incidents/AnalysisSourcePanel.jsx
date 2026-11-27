import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { FiCpu, FiDatabase, FiRefreshCw, FiZap, FiAlertTriangle } from 'react-icons/fi';
import Button from '../ui/Button';
import { getAnalysisSource, markAnalysisIncorrect } from '../../api/threatMemory';
import { formatDateTimeVN } from '../../i18n/viVN';

// Where the current AI analysis came from; cached knowledge is never presented as a fresh model inference.
const SOURCES = {
  FRESH_LLM: { label: 'Phân tích mới', color: '#60a5fa', icon: <FiCpu size={13} />,
               note: 'Mô hình AI vừa phân tích bằng chứng của sự cố này.' },
  EXACT_CACHE: { label: 'Từ mẫu đã kiểm chứng', color: '#34d399', icon: <FiDatabase size={13} />,
                 note: 'Không gọi mô hình: dùng lại mẫu phân tích đã kiểm chứng cho cùng kỹ thuật, gắn lại vào bằng chứng hiện tại và kiểm tra lại.' },
  SEMANTIC_ASSISTED: { label: 'Tham khảo sự cố tương tự', color: '#a78bfa', icon: <FiCpu size={13} />,
                       note: 'Mô hình AI phân tích bằng chứng hiện tại; các mẫu tương tự chỉ là ngữ cảnh tham khảo.' },
  RULE_BASED_FALLBACK: { label: 'Phân tích dự phòng', color: '#fbbf24', icon: <FiAlertTriangle size={13} />,
                         note: 'Kết quả theo quy tắc cố định (mô hình không được dùng hoặc không trả kết quả hợp lệ).' },
};
const VALIDATION = {
  auto_validated: 'Tự động kiểm định', soc_verified: 'SOC đã xác nhận', revoked: 'Đã bị SOC thu hồi',
  incorrect: 'SOC đánh dấu không chính xác', invalidated: 'Hết hiệu lực (rule thay đổi)', low_quality: 'Chất lượng thấp',
};
const REASONS = {
  expired: 'mẫu đã hết hạn', status_revoked: 'mẫu đã bị thu hồi', status_incorrect: 'mẫu bị đánh dấu sai',
  model_or_prompt_version: 'mẫu thuộc phiên bản mô hình/prompt cũ', playbook_unsupported: 'playbook của mẫu không còn hỗ trợ',
  evidence_incomplete: 'sự cố hiện tại thiếu bằng chứng mà mẫu yêu cầu', contradicted_by_evidence: 'bằng chứng mới mâu thuẫn với mẫu',
  forced_fresh: 'người dùng yêu cầu làm mới bằng AI', lookup_timeout: 'tra cứu bộ nhớ quá thời gian',
  lookup_error: 'bộ nhớ tạm thời lỗi', ambiguous_evidence_role: 'không gắn được bằng chứng một cách chắc chắn',
};
const ms = (value) => (value == null ? null : value >= 1000 ? `${(value / 1000).toFixed(1)} giây` : `${Math.round(value)} ms`);

export default function AnalysisSourcePanel({ incidentId, analysisId, busy, onRun }) {
  const [info, setInfo] = useState(null);
  const [marking, setMarking] = useState(false);

  useEffect(() => {
    let alive = true;
    getAnalysisSource(incidentId).then((data) => alive && setInfo(data)).catch(() => alive && setInfo(null));
    return () => { alive = false; };
  }, [incidentId, analysisId]);

  if (!info?.analysis_source) return null;
  const source = SOURCES[info.analysis_source] || SOURCES.RULE_BASED_FALLBACK;
  const latency = info.latency_ms || {};
  const markWrong = async () => {
    const reason = window.prompt('Lý do kết quả phân tích không chính xác?');
    if (reason === null) return;
    setMarking(true);
    try {
      const res = await markAnalysisIncorrect(incidentId, reason);
      toast.success(res.memory_invalidated?.length ? 'Đã ghi nhận; mẫu liên quan sẽ không được dùng lại' : 'Đã ghi nhận đánh giá');
      setInfo(await getAnalysisSource(incidentId));
    } catch (err) {
      toast.error(err.status === 403 ? 'Bạn không có quyền đánh dấu kết quả' : err.message);
    } finally {
      setMarking(false);
    }
  };

  return (
    <div style={{ border: `1px solid ${source.color}55`, borderRadius: '0.6rem', padding: '0.85rem 1rem',
                  background: `${source.color}10`, marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', color: source.color, fontWeight: 700 }}>
          {source.icon} Nguồn phân tích: {source.label}
        </span>
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => onRun('reuse')} iconLeft={<FiRefreshCw size={12} />}>Phân tích lại</Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => onRun('fresh')} iconLeft={<FiZap size={12} />}>Làm mới bằng AI</Button>
          <Button size="sm" variant="ghost" disabled={marking || info.analyst_rating === 'wrong'} onClick={markWrong}
                  iconLeft={<FiAlertTriangle size={12} />}>{info.analyst_rating === 'wrong' ? 'Đã đánh dấu không chính xác' : 'Đánh dấu kết quả không chính xác'}</Button>
        </div>
      </div>
      <div style={{ fontSize: '0.8rem', color: '#c9d1d9', marginTop: '0.4rem' }}>{source.note}</div>
      <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap', fontSize: '0.78rem', color: '#8b949e', marginTop: '0.5rem' }}>
        {info.memory && <span>Mẫu: <strong style={{ color: '#e6edf3' }}>{info.memory.attack_pattern}</strong></span>}
        {info.memory && <span>Kiểm chứng: {VALIDATION[info.memory.validation_status] || info.memory.validation_status}</span>}
        {info.memory?.updated_at && <span>Tri thức cập nhật: {formatDateTimeVN(info.memory.updated_at)}</span>}
        {info.model_called && info.model_name && <span>Mô hình: {info.model_name}</span>}
        {ms(latency.total) && <span>Thời gian phân tích: {ms(latency.total)}</span>}
        {ms(latency.llm) && <span>Mô hình AI: {ms(latency.llm)}</span>}
        {ms(latency.lookup) && <span>Tra cứu bộ nhớ: {ms(latency.lookup)}</span>}
        {info.cache_reason && info.analysis_source !== 'EXACT_CACHE' && (
          <span>Không dùng lại mẫu vì {REASONS[info.cache_reason] || 'mẫu không đủ điều kiện'}</span>
        )}
        {info.learned_memory_id && <span>Kết quả đã được lưu làm mẫu cho sự cố tương tự</span>}
      </div>
      {info.similar_cases?.length > 0 && (
        <div style={{ marginTop: '0.6rem' }}>
          <div style={{ fontSize: '0.78rem', color: '#8b949e', marginBottom: '0.25rem' }}>Mẫu tấn công tương tự (chỉ để tham khảo, không phải bằng chứng)</div>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', fontSize: '0.8rem', color: '#c9d1d9' }}>
            {info.similar_cases.map((c) => (
              <li key={c.id}>
                {c.attack_pattern} · mức tương đồng {Math.round((c.similarity || 0) * 100)}% · {VALIDATION[c.validation_status] || c.validation_status}
                {c.source_incident_id && <> · sự cố gốc {c.source_incident_id}</>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
