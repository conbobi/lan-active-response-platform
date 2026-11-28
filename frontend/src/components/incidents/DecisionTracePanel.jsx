import { useMemo, useState } from 'react';
import {
  FiAlertTriangle,
  FiCheckCircle,
  FiChevronDown,
  FiChevronRight,
  FiClock,
  FiCpu,
  FiDatabase,
  FiLoader,
  FiShield,
  FiSkipForward,
  FiTag,
} from 'react-icons/fi';
import { formatDateTimeVN, shortenId } from '../../i18n/viVN';

const STAGE_ORDER = [
  'INCIDENT_LOADED',
  'EVIDENCE_RETRIEVAL',
  'RISK_RULE_EXPLANATION',
  'PROCESS_NETWORK_CORRELATION',
  'CACHE_LOOKUP',
  'MODEL_INFERENCE',
  'DETERMINISTIC_FALLBACK',
  'CLAIM_VERIFICATION',
  'ANALYSIS_PERSISTENCE',
  'RESPONSE_RECOMMENDATION',
];

const STAGE_LABELS = {
  INCIDENT_LOADED: '1. Nạp hồ sơ sự cố',
  EVIDENCE_RETRIEVAL: '2. Thu thập & phân nguồn bằng chứng',
  RISK_RULE_EXPLANATION: '3. Giải thích phân rã điểm rủi ro',
  PROCESS_NETWORK_CORRELATION: '4. Liên kết tiến trình & kết nối mạng',
  CACHE_LOOKUP: '5. Tra cứu Threat Memory & cache',
  MODEL_INFERENCE: '6. Suy luận mô hình AI (JSON chuẩn hóa)',
  DETERMINISTIC_FALLBACK: '6b. Dự phòng xác định (Deterministic Fallback)',
  CLAIM_VERIFICATION: '7. Kiểm chứng bằng chứng & giới hạn khẳng định',
  ANALYSIS_PERSISTENCE: '8. Lưu kết quả phân tích',
  RESPONSE_RECOMMENDATION: '9. Đối chiếu Policy ứng phó (Chỉ đọc)',
};

const SOURCE_LABELS = {
  ENDPOINT_AGENT: 'Endpoint Agent',
  MANAGER_STORE: 'Kho Manager',
  ANALYST_INPUT: 'Phân tích viên',
  AI_INFERENCE: 'Mô hình AI',
  DETERMINISTIC: 'Rule / Mã xác định',
  HYBRID: 'Kết hợp',
};

const CERTAINTY_LABELS = {
  OBSERVED: { label: 'Quan sát trực tiếp', color: '#10b981' },
  CORRELATED: { label: 'Liên kết đa nguồn', color: '#3b82f6' },
  INFERRED: { label: 'Suy luận', color: '#a855f7' },
  UNKNOWN: { label: 'Chưa xác minh', color: '#94a3b8' },
};

const RUN_STATUS_META = {
  CREATED: { label: 'Đang xếp hàng', color: '#60a5fa', bg: 'rgba(59,130,246,0.14)' },
  RUNNING: { label: 'Đang suy luận trực tiếp', color: '#38bdf8', bg: 'rgba(56,189,248,0.15)' },
  COMPLETED: { label: 'Hoàn tất', color: '#10b981', bg: 'rgba(16,185,129,0.14)' },
  TIMEOUT: { label: 'Hết thời gian AI (Đã Fallback)', color: '#f59e0b', bg: 'rgba(245,158,11,0.16)' },
  FAILED: { label: 'Thất bại', color: '#ef4444', bg: 'rgba(239,68,68,0.14)' },
  CANCELLED: { label: 'Đã hủy', color: '#94a3b8', bg: 'rgba(148,163,184,0.14)' },
};

const STAGE_STATUS_META = {
  RUNNING: { label: 'Đang chạy', color: '#38bdf8' },
  COMPLETED: { label: 'Hoàn tất', color: '#10b981' },
  SKIPPED: { label: 'Bỏ qua', color: '#94a3b8' },
  TIMEOUT: { label: 'Hết thời gian', color: '#f59e0b' },
  FAILED: { label: 'Thất bại', color: '#ef4444' },
  CANCELLED: { label: 'Đã hủy', color: '#94a3b8' },
  PENDING: { label: 'Chờ', color: '#64748b' },
};

function formatDurationMs(ms) {
  if (typeof ms !== 'number' || Number.isNaN(ms)) return null;
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} giây`;
}

function StageIcon({ status }) {
  if (status === 'RUNNING') {
    return <FiLoader size={14} color="#38bdf8" className="animate-spin" />;
  }
  if (status === 'COMPLETED') {
    return <FiCheckCircle size={14} color="#10b981" />;
  }
  if (status === 'SKIPPED') {
    return <FiSkipForward size={14} color="#94a3b8" />;
  }
  if (status === 'TIMEOUT') {
    return <FiClock size={14} color="#f59e0b" />;
  }
  if (status === 'FAILED' || status === 'CANCELLED') {
    return <FiAlertTriangle size={14} color="#ef4444" />;
  }
  return <FiCpu size={14} color="#64748b" />;
}

function RiskBreakdownBlock({ data, onSelectEvidenceRef, highlightRule }) {
  if (!data) return null;
  if (!data.breakdown_available) {
    return (
      <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
        {data.message || 'Chưa có dữ liệu phân rã điểm'}
      </div>
    );
  }
  const rules = Array.isArray(data.rule_breakdown) ? data.rule_breakdown : [];
  const matched = rules.filter((r) => r.matched);
  const shown = matched.length > 0 ? matched : rules.slice(0, 6);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
      <div style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap', fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
        <span>Điểm tổng cuối: <strong style={{ color: 'var(--text-primary)' }}>{data.final_score ?? '—'}/100</strong></span>
        {data.raw_score != null && <span>· Điểm gốc (raw): <strong>{data.raw_score}</strong></span>}
        {data.previous_smoothed != null && <span>· Trước EMA: <strong>{data.previous_smoothed}</strong></span>}
        <span>
          · Làm mượt EMA:{' '}
          <strong>
            {data.security_attack_bypass
              ? 'Bỏ qua EMA (Critical / Security Attack)'
              : data.ema_applied === true
                ? 'Có áp dụng'
                : data.ema_applied === false
                  ? 'Không áp dụng'
                  : 'Không có snapshot'}
          </strong>
        </span>
      </div>

      {shown.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.74rem' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-tertiary)', borderBottom: '1px solid rgba(148,163,184,0.2)' }}>
                <th style={{ padding: '0.3rem 0.4rem' }}>Rule / Điều kiện</th>
                <th style={{ padding: '0.3rem 0.4rem' }}>Gốc</th>
                <th style={{ padding: '0.3rem 0.4rem' }}>Sau debounce</th>
                <th style={{ padding: '0.3rem 0.4rem' }}>Trọng số</th>
                <th style={{ padding: '0.3rem 0.4rem' }}>Đóng góp</th>
                <th style={{ padding: '0.3rem 0.4rem' }}>Bằng chứng</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r, i) => {
                const isHighlighted = highlightRule && highlightRule === r.rule_id;
                return (
                  <tr
                    key={`${r.rule_id || i}`}
                    style={{
                      borderBottom: '1px solid rgba(148,163,184,0.1)',
                      background: isHighlighted ? 'rgba(59,130,246,0.12)' : 'transparent',
                    }}
                  >
                    <td style={{ padding: '0.35rem 0.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      <div>{r.label || r.rule_id}</div>
                      {r.reason && <div style={{ fontWeight: 400, color: 'var(--text-tertiary)', fontSize: '0.7rem' }}>{r.reason}</div>}
                    </td>
                    <td style={{ padding: '0.35rem 0.4rem', fontFamily: 'monospace' }}>{r.raw_score ?? '—'}</td>
                    <td style={{ padding: '0.35rem 0.4rem', fontFamily: 'monospace' }}>{r.debounced_score ?? '—'}</td>
                    <td style={{ padding: '0.35rem 0.4rem', fontFamily: 'monospace' }}>{r.weight ?? '—'}</td>
                    <td style={{ padding: '0.35rem 0.4rem', fontFamily: 'monospace', color: '#60a5fa', fontWeight: 600 }}>
                      +{r.weighted_contribution ?? '—'}
                    </td>
                    <td style={{ padding: '0.35rem 0.4rem' }}>
                      {(r.evidence_ids || []).length === 0 ? (
                        <span style={{ color: 'var(--text-tertiary)' }}>—</span>
                      ) : (
                        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                          {r.evidence_ids.slice(0, 3).map((eid) => (
                            <button
                              key={eid}
                              type="button"
                              onClick={() => onSelectEvidenceRef?.(eid)}
                              style={{
                                background: 'rgba(59,130,246,0.12)',
                                border: '1px solid rgba(59,130,246,0.3)',
                                color: '#93c5fd',
                                borderRadius: '4px',
                                padding: '0.08rem 0.35rem',
                                fontSize: '0.68rem',
                                fontFamily: 'monospace',
                                cursor: 'pointer',
                              }}
                            >
                              {shortenId(eid)}
                            </button>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StageSafeBody({ stage, item, deltas, onSelectEvidenceRef, onSelectRuleRef, highlightRule }) {
  const sr = item.safe_result;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginTop: '0.4rem' }}>
      {stage === 'EVIDENCE_RETRIEVAL' && sr?.counts && (
        <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', fontSize: '0.73rem' }}>
          {Object.entries({
            'HTTP Logs': sr.counts.http_events,
            'Xác thực': sr.counts.auth_events,
            'Tiến trình': sr.counts.processes,
            'Flow mạng': sr.counts.network_flows,
            'Ghi chú SOC': sr.counts.analyst_notes,
            'Hành động cũ': sr.counts.containment_artifacts,
          }).map(([label, val]) => (
            <span
              key={label}
              style={{
                padding: '0.15rem 0.45rem',
                borderRadius: '4px',
                background: 'rgba(148,163,184,0.1)',
                color: 'var(--text-secondary)',
              }}
            >
              {label}: <strong>{val ?? 0}</strong>
            </span>
          ))}
        </div>
      )}

      {stage === 'RISK_RULE_EXPLANATION' && sr && (
        <RiskBreakdownBlock data={sr} onSelectEvidenceRef={onSelectEvidenceRef} highlightRule={highlightRule} />
      )}

      {stage === 'PROCESS_NETWORK_CORRELATION' && sr && (
        <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          <span>
            Mức độ xác nhận:{' '}
            <strong style={{ color: (CERTAINTY_LABELS[sr.status] || CERTAINTY_LABELS.UNKNOWN).color }}>
              {(CERTAINTY_LABELS[sr.status] || CERTAINTY_LABELS.UNKNOWN).label}
            </strong>
          </span>
          {Array.isArray(sr.matched_pids) && sr.matched_pids.length > 0 && (
            <span>· PID liên quan: <code style={{ fontSize: '0.73rem' }}>{sr.matched_pids.join(', ')}</code></span>
          )}
        </div>
      )}

      {stage === 'CACHE_LOOKUP' && sr && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
          <span>Trạng thái: <strong>{sr.cache_hit ? 'Trúng bộ nhớ (Reuse)' : 'Không khớp (Miss)'}</strong></span>
          {sr.memory_id && <span>· Mẫu: <code>{shortenId(sr.memory_id)}</code></span>}
          {sr.similar_count > 0 && <span>· Ca tương tự tham khảo: <strong>{sr.similar_count}</strong></span>}
          {sr.lookup_ms != null && <span>· Độ trễ tra cứu: {sr.lookup_ms} ms</span>}
        </div>
      )}

      {stage === 'MODEL_INFERENCE' && (deltas.length > 0 || sr) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {sr && (
            <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
              {sr.model && <span>Mô hình: <code>{sr.model}</code></span>}
              {sr.route && <span>· Lộ trình: <code>{sr.route}</code></span>}
              {sr.llm_ms != null && <span>· Thời gian gọi mô hình: <strong>{formatDurationMs(Math.round(sr.llm_ms))}</strong></span>}
            </div>
          )}
          {deltas.map((d) => (
            <div
              key={d.sequence}
              style={{
                padding: '0.3rem 0.5rem',
                borderRadius: '4px',
                background: 'rgba(56, 189, 248, 0.08)',
                borderLeft: '2px solid #38bdf8',
                color: 'var(--text-primary)',
                fontSize: '0.75rem',
              }}
            >
              {d.summary}
            </div>
          ))}
        </div>
      )}

      {stage === 'CLAIM_VERIFICATION' && Array.isArray(sr?.checks) && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '0.35rem' }}>
          {sr.checks.map((chk) => {
            const cert = CERTAINTY_LABELS[chk.certainty] || CERTAINTY_LABELS.UNKNOWN;
            return (
              <div
                key={chk.check_id}
                style={{
                  padding: '0.35rem 0.5rem',
                  borderRadius: '4px',
                  background: chk.passed ? 'rgba(16,185,129,0.07)' : 'rgba(245,158,11,0.12)',
                  border: `1px solid ${chk.passed ? 'rgba(16,185,129,0.25)' : 'rgba(245,158,11,0.35)'}`,
                  fontSize: '0.73rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.35rem', alignItems: 'center' }}>
                  <strong style={{ color: chk.passed ? '#10b981' : '#f59e0b' }}>
                    {chk.passed ? '✓' : '⚠'} {chk.label}
                  </strong>
                  <span style={{ fontSize: '0.67rem', color: cert.color }}>{cert.label}</span>
                </div>
                <div style={{ color: 'var(--text-secondary)', marginTop: '0.15rem' }}>{chk.detail}</div>
              </div>
            );
          })}
        </div>
      )}

      {stage === 'RESPONSE_RECOMMENDATION' && sr && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#93c5fd', fontWeight: 600 }}>
            <FiShield size={13} /> Chế độ chỉ đọc — không tự động thực thi ngăn chặn khi chưa phê duyệt
          </div>
          {Array.isArray(sr.matching_policies) && sr.matching_policies.length > 0 && (
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              {sr.matching_policies.map((pol) => (
                <span
                  key={pol.policy_id}
                  style={{
                    padding: '0.15rem 0.45rem',
                    borderRadius: '4px',
                    background: 'rgba(168,85,247,0.12)',
                    border: '1px solid rgba(168,85,247,0.3)',
                    color: '#d8b4fe',
                    fontSize: '0.72rem',
                  }}
                >
                  Policy: {pol.name} ({pol.action_type})
                </span>
              ))}
            </div>
          )}
          {Array.isArray(sr.ip_candidates) && sr.ip_candidates.length > 0 && (
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              {sr.ip_candidates.map((cand) => (
                <span
                  key={cand.ip}
                  style={{
                    padding: '0.15rem 0.45rem',
                    borderRadius: '4px',
                    background: cand.allowed ? 'rgba(16,185,129,0.1)' : 'rgba(245,158,11,0.12)',
                    border: `1px solid ${cand.allowed ? 'rgba(16,185,129,0.3)' : 'rgba(245,158,11,0.35)'}`,
                    color: 'var(--text-secondary)',
                    fontSize: '0.72rem',
                  }}
                >
                  IP <code>{cand.ip}</code>:{' '}
                  {cand.allowed ? 'Đủ điều kiện đề xuất chặn' : `Được bảo vệ (${cand.protected_reason || 'Allowlist'})`}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {(item.rule_refs?.length > 0 || item.evidence_refs?.length > 0) && stage !== 'RISK_RULE_EXPLANATION' && (
        <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap', alignItems: 'center' }}>
          {(item.rule_refs || []).slice(0, 6).map((rid) => (
            <button
              key={`r-${rid}`}
              type="button"
              onClick={() => onSelectRuleRef?.(rid)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.2rem',
                padding: '0.1rem 0.4rem',
                borderRadius: '4px',
                background: 'rgba(168,85,247,0.12)',
                border: '1px solid rgba(168,85,247,0.3)',
                color: '#d8b4fe',
                fontSize: '0.69rem',
                cursor: 'pointer',
              }}
            >
              <FiTag size={10} /> {rid}
            </button>
          ))}
          {(item.evidence_refs || []).slice(0, 6).map((eid) => (
            <button
              key={`e-${eid}`}
              type="button"
              onClick={() => onSelectEvidenceRef?.(eid)}
              style={{
                padding: '0.1rem 0.4rem',
                borderRadius: '4px',
                background: 'rgba(59,130,246,0.1)',
                border: '1px solid rgba(59,130,246,0.28)',
                color: '#93c5fd',
                fontSize: '0.69rem',
                fontFamily: 'monospace',
                cursor: 'pointer',
              }}
              title={`Xem hoặc sao chép bằng chứng ${eid}`}
            >
              {shortenId(eid)}
            </button>
          ))}
          {item.evidence_refs?.length > 6 && (
            <span style={{ fontSize: '0.69rem', color: 'var(--text-tertiary)' }}>
              +{item.evidence_refs.length - 6} bằng chứng khác
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function DecisionTracePanel({
  runs = [],
  activeRun = null,
  events = [],
  loading = false,
  streaming = false,
  expanded = false,
  onToggleExpand,
  onSelectRun,
  onSelectEvidenceRef,
}) {
  const [openStages, setOpenStages] = useState({});
  const [highlightRule, setHighlightRule] = useState(null);

  const stageItems = useMemo(() => {
    const byStage = new Map();
    const deltas = [];
    for (const ev of events) {
      if (ev.event_type === 'model_answer_delta') {
        deltas.push(ev);
        continue;
      }
      if (ev.event_type === 'analysis_started' || ev.event_type === 'analysis_completed' || ev.event_type === 'analysis_failed') {
        if (ev.event_type === 'analysis_started' && !byStage.has('INCIDENT_LOADED')) {
          byStage.set('INCIDENT_LOADED', ev);
        }
        continue;
      }
      if (!ev.stage) continue;
      byStage.set(ev.stage, ev);
    }
    const ordered = [];
    for (const st of STAGE_ORDER) {
      if (byStage.has(st)) {
        ordered.push(byStage.get(st));
        byStage.delete(st);
      }
    }
    for (const leftover of byStage.values()) {
      ordered.push(leftover);
    }
    return { ordered, deltas };
  }, [events]);

  const runStatus = activeRun?.status || (streaming ? 'RUNNING' : null);
  const statusMeta = RUN_STATUS_META[runStatus] || { label: 'Chưa chạy trace', color: '#94a3b8', bg: 'rgba(148,163,184,0.12)' };

  const hasTimeoutFallback = useMemo(
    () =>
      runStatus === 'TIMEOUT' ||
      stageItems.ordered.some((it) => it.stage === 'MODEL_INFERENCE' && (it.status === 'TIMEOUT' || it.status === 'FAILED')),
    [runStatus, stageItems],
  );

  const handleRuleClick = (ruleId) => {
    setHighlightRule((prev) => (prev === ruleId ? null : ruleId));
    setOpenStages((prev) => ({ ...prev, RISK_RULE_EXPLANATION: true }));
  };

  return (
    <div
      data-testid="decision-trace-panel"
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        padding: '0.9rem 1.05rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.7rem',
      }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.6rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
          <FiDatabase size={15} color="#38bdf8" />
          <strong style={{ fontSize: '0.92rem', color: 'var(--text-primary)' }}>
            Quá trình suy luận và kiểm chứng (AI Decision Trace)
          </strong>
          {activeRun && (
            <span
              data-testid="trace-run-status"
              style={{
                padding: '0.16rem 0.55rem',
                borderRadius: '999px',
                fontSize: '0.72rem',
                fontWeight: 700,
                color: statusMeta.color,
                background: statusMeta.bg,
                border: `1px solid ${statusMeta.color}44`,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              {(runStatus === 'RUNNING' || runStatus === 'CREATED' || streaming) && (
                <FiLoader size={11} className="animate-spin" />
              )}
              {statusMeta.label}
            </span>
          )}
          {activeRun?.analysis_run_id && (
            <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
              {shortenId(activeRun.analysis_run_id)} · {activeRun.mode === 'fresh' ? 'Phân tích mới' : 'Tái sử dụng bộ nhớ'}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {runs.length > 1 && (
            <select
              aria-label="Chọn phiên phân tích"
              value={activeRun?.analysis_run_id || ''}
              onChange={(e) => onSelectRun?.(e.target.value)}
              style={{
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)',
                borderRadius: '6px',
                padding: '0.25rem 0.5rem',
                fontSize: '0.74rem',
              }}
            >
              {runs.map((r) => (
                <option key={r.analysis_run_id} value={r.analysis_run_id}>
                  {shortenId(r.analysis_run_id)} · {r.status} · {formatDateTimeVN(r.created_at)}
                </option>
              ))}
            </select>
          )}
          <button
            type="button"
            data-testid="toggle-trace-details"
            onClick={onToggleExpand}
            style={{
              background: 'rgba(59,130,246,0.1)',
              border: '1px solid rgba(59,130,246,0.35)',
              color: '#93c5fd',
              borderRadius: '6px',
              padding: '0.3rem 0.65rem',
              fontSize: '0.76rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.3rem',
            }}
          >
            {expanded ? <FiChevronDown size={13} /> : <FiChevronRight size={13} />}
            {expanded ? 'Ẩn chi tiết' : 'Hiện chi tiết'}
          </button>
        </div>
      </div>

      {!activeRun && !loading && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', lineHeight: 1.5 }}>
          Sự cố này chưa có lịch sử Decision Trace (có thể được tạo trước khi bật ghi vết theo từng bước). Nhấn{' '}
          <strong>Phân tích lại bằng AI</strong> để theo dõi quá trình nạp dữ liệu, tính điểm, tương quan và kiểm chứng thời gian thực.
        </div>
      )}

      {activeRun && !expanded && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Đã ghi nhận {stageItems.ordered.length} bước xử lý backend
          {activeRun.started_at ? ` · Bắt đầu ${formatDateTimeVN(activeRun.started_at)}` : ''}. Nhấn{' '}
          <strong>Hiện chi tiết</strong> để xem bảng phân rã điểm, bằng chứng và kiểm chứng từng bước.
        </div>
      )}

      {expanded && activeRun && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
          {hasTimeoutFallback && (
            <div
              data-testid="trace-timeout-fallback-banner"
              style={{
                padding: '0.6rem 0.8rem',
                borderRadius: '6px',
                background: 'rgba(245, 158, 11, 0.12)',
                border: '1px solid rgba(245, 158, 11, 0.45)',
                color: '#fbbf24',
                fontSize: '0.78rem',
                fontWeight: 600,
              }}
            >
              Mô hình AI gặp timeout hoặc lỗi gọi mô hình — kết luận cuối cùng bên dưới được tạo bởi bước{' '}
              <strong>Dự phòng xác định (DETERMINISTIC_FALLBACK)</strong> từ telemetry thực tế, không giả danh AI thành công.
            </div>
          )}

          {stageItems.ordered.length === 0 && (
            <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <FiLoader size={13} className="animate-spin" /> Đang chờ sự kiện backend đầu tiên...
            </div>
          )}

          {stageItems.ordered.map((item) => {
            const meta = STAGE_STATUS_META[item.status] || STAGE_STATUS_META.PENDING;
            const durText = formatDurationMs(item.duration_ms);
            const hasRich =
              item.stage === 'RISK_RULE_EXPLANATION' ||
              item.stage === 'CLAIM_VERIFICATION' ||
              item.stage === 'EVIDENCE_RETRIEVAL' ||
              item.stage === 'RESPONSE_RECOMMENDATION' ||
              item.stage === 'MODEL_INFERENCE' ||
              (item.evidence_refs && item.evidence_refs.length > 0) ||
              (item.rule_refs && item.rule_refs.length > 0);
            const stageOpen = openStages[item.stage] ?? (item.status === 'RUNNING' || item.stage === 'RISK_RULE_EXPLANATION' || item.stage === 'CLAIM_VERIFICATION');

            return (
              <div
                key={`${item.stage}-${item.sequence}`}
                data-testid={`trace-stage-${item.stage}`}
                style={{
                  border: '1px solid rgba(148,163,184,0.2)',
                  borderLeft: `3px solid ${meta.color}`,
                  borderRadius: '6px',
                  padding: '0.55rem 0.75rem',
                  background: 'rgba(15, 23, 42, 0.35)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                    <StageIcon status={item.status} />
                    <strong style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                      {STAGE_LABELS[item.stage] || item.stage}
                    </strong>
                    <span
                      style={{
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        color: meta.color,
                        padding: '0.08rem 0.4rem',
                        borderRadius: '4px',
                        background: `${meta.color}18`,
                      }}
                    >
                      {meta.label}
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)' }}>
                      · Nguồn: {SOURCE_LABELS[item.source_type] || item.source_type}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {durText && (
                      <span style={{ fontSize: '0.71rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                        {durText}
                      </span>
                    )}
                    {hasRich && (
                      <button
                        type="button"
                        onClick={() => setOpenStages((prev) => ({ ...prev, [item.stage]: !stageOpen }))}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-tertiary)',
                          fontSize: '0.72rem',
                          cursor: 'pointer',
                        }}
                      >
                        {stageOpen ? 'Thu gọn' : 'Chi tiết'}
                      </button>
                    )}
                  </div>
                </div>

                {item.summary && (
                  <div style={{ fontSize: '0.79rem', color: 'var(--text-secondary)', marginTop: '0.28rem', lineHeight: 1.45 }}>
                    {item.summary}
                  </div>
                )}

                {stageOpen && (
                  <StageSafeBody
                    stage={item.stage}
                    item={item}
                    deltas={item.stage === 'MODEL_INFERENCE' ? stageItems.deltas : []}
                    onSelectEvidenceRef={onSelectEvidenceRef}
                    onSelectRuleRef={handleRuleClick}
                    highlightRule={highlightRule}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
