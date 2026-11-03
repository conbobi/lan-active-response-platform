import React, { useState, useEffect, useRef } from 'react';
import { getAIAnalysis, regenerateAIAnalysis, rateAIAnalysis } from '../../api/incidents';
import Button from "../ui/Button";
import Badge from "../ui/Badge";
import toast from "react-hot-toast";
import AISuggestionPanel from './AISuggestionPanel';
export default function AIAnalysisTab({ incidentId }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [error, setError] = useState(null);
  const [ratingLoading, setRatingLoading] = useState(false);
  const pollTimerRef = useRef(null);

  const fetchAnalysis = async (isRetry = false) => {
    try {
      if (!isRetry) setLoading(true);
      setError(null);
      const data = await getAIAnalysis(incidentId);
      setAnalysis(data);
    } catch (err) {
      if (err.response?.status === 404 || err.message?.includes('404')) {
        setAnalysis(null);
        setError('pending');
      } else {
        setError(err.message || 'Lỗi khi tải kết quả phân tích AI');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (incidentId) {
      fetchAnalysis();
    }
    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [incidentId]);

  const handleRegenerate = async () => {
    try {
      setRegenerating(true);
      setError(null);
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);

      // Baseline: ghi nhận analysis_id cũ để biết khi có record mới
      const oldAnalysisId = analysis?.id || null;
      const startTime = Date.now();

      // 1. POST — trả về ngay lập tức (~1s)
      await regenerateAIAnalysis(incidentId);
      toast.success('AI đang phân tích (~2-4 phút). Bạn có thể rời trang.', {
        duration: 5000,
      });

      // 2. Poll GET mỗi 5s, tối đa 5 phút (60 lần)
      const POLL_INTERVAL = 5000;
      const MAX_ATTEMPTS = 60;
      let attempts = 0;

      pollTimerRef.current = setInterval(async () => {
        attempts++;
        if (attempts > MAX_ATTEMPTS) {
          clearInterval(pollTimerRef.current);
          setRegenerating(false);
          pollTimerRef.current = null;
          setError('AI timeout sau 5 phút. Thử lại sau.');
          toast.error('AI timeout — thử lại sau');
          return;
        }

        try {
          const data = await getAIAnalysis(incidentId);
          // Check: có record mới không?
          const isNewRecord = data && data.id && data.id !== oldAnalysisId;
          const isFresh = data?.created_at && new Date(data.created_at).getTime() > startTime;

          if (isNewRecord && isFresh) {
            clearInterval(pollTimerRef.current);
            setAnalysis(data);
            setRegenerating(false);
            if (data.error_message || data.summary === '[AI analysis failed]') {
              toast.error('AI phân tích thất bại — xem chi tiết bên dưới');
            } else {
              toast.success('AI analysis hoàn tất!');
            }
          }
          // Nếu chưa có record mới → tiếp tục poll
        } catch (err) {
          // 404 → đang chạy, tiếp tục poll
          // Các lỗi khác → log nhưng vẫn tiếp tục
          console.debug(`Poll ${attempts}: ${err.message}`);
        }
      }, POLL_INTERVAL);

    } catch (err) {
      setRegenerating(false);
      const msg = err.response?.data?.detail || err.message || 'Lỗi khi trigger AI';
      setError(msg);
      toast.error(msg);
    }
  };

  const handleRate = async (rating) => {
    if (ratingLoading || !analysis) return;
    try {
      setRatingLoading(true);
      await rateAIAnalysis(incidentId, rating);
      setAnalysis((prev) => ({ ...prev, analyst_rating: rating }));
      toast.success(
        rating === 'helpful'
          ? 'Đã lưu đánh giá: Hữu ích'
          : 'Đã lưu đánh giá: Sai lệch'
      );
    } catch (err) {
      toast.error(`Không thể lưu đánh giá: ${err.message}`);
    } finally {
      setRatingLoading(false);
    }
  };

  // Skeleton Loader State
  if (loading || regenerating) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', padding: '1rem 0' }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          background: 'var(--bg-secondary)', padding: '1rem',
          borderRadius: 'var(--radius-md)', border: '1px solid var(--border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{ fontSize: '1.5rem', animation: 'spin 2s linear infinite' }}>🤖</span>
            <div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {regenerating ? 'Đang phân tích bằng Foundation-Sec-8B...' : 'Đang tải kết quả AI...'}
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                {regenerating
                  ? 'Quá trình mất khoảng 2-4 phút trên CPU. Bạn có thể rời trang — kết quả sẽ được lưu.'
                  : 'Mô hình suy luận cục bộ bảo mật.'}
              </div>
              {regenerating && (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginTop: '0.35rem' }}>
                  Tự động kiểm tra kết quả mỗi 5 giây...
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Skeleton blocks (giữ nguyên 3 khối cũ) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '30%', height: '18px', background: 'var(--border)', borderRadius: '4px', opacity: 0.5 }} />
          <div style={{ width: '100%', height: '60px', background: 'var(--border)', borderRadius: '6px', opacity: 0.3 }} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '40%', height: '18px', background: 'var(--border)', borderRadius: '4px', opacity: 0.5 }} />
          <div style={{ width: '100%', height: '80px', background: 'var(--border)', borderRadius: '6px', opacity: 0.3 }} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ width: '25%', height: '18px', background: 'var(--border)', borderRadius: '4px', opacity: 0.5 }} />
          <div style={{ width: '100%', height: '40px', background: 'var(--border)', borderRadius: '6px', opacity: 0.3 }} />
        </div>
      </div>
    );
  }

  // Pending State (Incident mới tạo chưa có kết quả)
  if (loading) return <Skeleton />;

  // Error thật (không phải 'pending')
  if (error && error !== 'pending' && !analysis) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--error)' }}>
        <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>⚠️</div>
        <div style={{ color: 'var(--error)', fontWeight: 700, marginBottom: '0.5rem' }}>
          Không thể tải AI Analysis
        </div>
        <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1rem' }}>
          {error}
        </div>
        <Button variant="outline" size="sm" onClick={() => { setError(null); fetchAnalysis(); }}>
          🔄 Thử lại
        </Button>
      </div>
    );
  }

  // Pending — chưa có analysis, chưa có error
  if (!analysis) {
    return <PendingState onRegenerate={handleRegenerate} onRetry={() => fetchAnalysis(true)} />;
  }

  // Error State from AI
  if (analysis.error_message || analysis.summary === '[AI analysis failed]') {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          padding: '1.5rem',
          background: 'rgba(239, 68, 68, 0.08)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--error)', fontWeight: 700 }}>
          <span>⚠️</span> Phân tích AI gặp sự cố
        </div>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
          {analysis.error_message || 'Mô hình không phản hồi đúng định dạng JSON hoặc bị gián đoạn.'}
        </div>
        <div>
          <Button variant="primary" size="sm" onClick={handleRegenerate}>
            🔄 Thử phân tích lại
          </Button>
        </div>
      </div>
    );
  }

  const confidencePct = Math.round((analysis.confidence || 0) * 100);
  const confidenceColor =
    confidencePct >= 80 ? 'var(--success)' : confidencePct >= 60 ? 'var(--warning)' : 'var(--text-secondary)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '0.5rem 0' }}>
      {/* Header bar: Model & Confidence & Regenerate */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          background: 'var(--bg-secondary)',
          padding: '0.85rem 1.15rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem' }}>🤖</span>
            <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              AI Incident Triage
            </span>
            <span
              style={{
                fontSize: '0.72rem',
                padding: '2px 6px',
                borderRadius: '4px',
                background: 'rgba(59, 130, 246, 0.15)',
                color: 'var(--primary)',
                fontWeight: 600,
              }}
            >
              {analysis.model_name || 'foundation-sec'}
            </span>
          </div>

          {/* Confidence Meter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Độ tin cậy:</span>
            <div
              style={{
                width: '80px',
                height: '8px',
                background: 'var(--bg-tertiary, #1e293b)',
                borderRadius: '4px',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${confidencePct}%`,
                  height: '100%',
                  background: confidenceColor,
                  borderRadius: '4px',
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
            <span style={{ fontSize: '0.82rem', fontWeight: 700, color: confidenceColor }}>
              {confidencePct}%
            </span>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={handleRegenerate}
          disabled={regenerating}
          title="Yêu cầu AI phân tích lại từ đầu"
        >
          🔄 Regenerate
        </Button>
      </div>

      {/* 1. Tóm tắt diễn biến (Incident Summary) */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          padding: '1.15rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.88rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: '0.65rem',
          }}
        >
          <span>📝</span> TÓM TẮT DIỄN BIẾN
        </div>
        <div
          style={{
            fontSize: '0.9rem',
            lineHeight: 1.65,
            color: 'var(--text-secondary)',
            whiteSpace: 'pre-wrap',
          }}
        >
          {analysis.summary}
        </div>
      </div>

      {/* 2. MITRE ATT&CK Mapping */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          padding: '1.15rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.88rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: '0.75rem',
          }}
        >
          <span>🎯</span> KỸ THUẬT MITRE ATT&CK PHÁT HIỆN
        </div>

        {analysis.mitre_techniques && analysis.mitre_techniques.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {analysis.mitre_techniques.map((t, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem',
                  padding: '0.65rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span
                    style={{
                      fontFamily: 'monospace',
                      fontWeight: 700,
                      fontSize: '0.82rem',
                      color: 'var(--primary)',
                      background: 'rgba(59, 130, 246, 0.1)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                    }}
                  >
                    {t.id}
                  </span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {t.name}
                  </span>
                  {t.tactic && (
                    <span
                      style={{
                        fontSize: '0.72rem',
                        color: 'var(--text-tertiary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.5px',
                      }}
                    >
                      ({t.tactic})
                    </span>
                  )}
                </div>
                {t.evidence && (
                  <div
                    style={{
                      fontSize: '0.8rem',
                      color: 'var(--text-secondary)',
                      marginTop: '0.2rem',
                      paddingLeft: '0.5rem',
                      borderLeft: '2px solid var(--border)',
                    }}
                  >
                    <strong style={{ color: 'var(--text-primary)' }}>Bằng chứng:</strong> {t.evidence}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
            Không phát hiện kỹ thuật MITRE cụ thể nào trong dữ liệu telemetry.
          </div>
        )}
      </div>

      {/* 3. Nguyên nhân gốc (Root Cause) */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          padding: '1.15rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.88rem',
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: '0.65rem',
          }}
        >
          <span>🔍</span> NGUYÊN NHÂN GỐC (ROOT CAUSE)
        </div>
        <div
          style={{
            fontSize: '0.9rem',
            lineHeight: 1.65,
            color: 'var(--text-secondary)',
          }}
        >
          {analysis.root_cause || 'Chưa xác định được nguyên nhân gốc rõ ràng.'}
        </div>
      </div>

      {/* 3.5. Đề xuất phản ứng (Response AI Assist) */}
      <AISuggestionPanel
        incidentId={incidentId}
        onRefresh={() => fetchAnalysis(true)}
      />

      {/* 4. Analyst Feedback & Rating */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          padding: '0.85rem 1.15rem',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
          <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Đánh giá nhận định của AI:
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
            Phản hồi này giúp cải thiện chất lượng AI Triage ở các phiên bản tiếp theo.
          </span>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem' }}>
          <Button
            variant={analysis.analyst_rating === 'helpful' ? 'primary' : 'outline'}
            size="sm"
            disabled={ratingLoading}
            onClick={() => handleRate('helpful')}
            title="Đánh giá kết quả này chính xác và hữu ích"
          >
            👍 Hữu ích (Helpful)
          </Button>

          <Button
            variant={analysis.analyst_rating === 'wrong' ? 'danger' : 'outline'}
            size="sm"
            disabled={ratingLoading}
            onClick={() => handleRate('wrong')}
            title="Đánh giá kết quả này sai lệch hoặc gây nhiễu"
          >
            👎 Sai lệch (Wrong)
          </Button>
        </div>
      </div>
    </div>
  );
}
