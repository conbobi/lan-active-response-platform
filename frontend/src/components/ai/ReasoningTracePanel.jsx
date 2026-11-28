import { useMemo, useState } from 'react';
import {
  FiAlertTriangle,
  FiCheckCircle,
  FiChevronDown,
  FiChevronRight,
  FiClock,
  FiCpu,
  FiDatabase,
  FiHelpCircle,
  FiLoader,
  FiRefreshCw,
  FiShield,
  FiSkipForward,
  FiTag,
} from 'react-icons/fi';
import { formatDateTimeVN, shortenId } from '../../i18n/viVN';
import { buildStageCards, CERTAINTY_LABELS, mergeEvents, runStatus as traceRunStatus } from './traceModel';
import CertaintyBadge from './CertaintyBadge';

// Labels for the stages the backend emits. Order on screen is the order the backend ran them.
const STAGE_LABELS = {
  // AI Risk Analyst
  INCIDENT_LOADED: 'Truy xuất incident',
  EVIDENCE_RETRIEVAL: 'Đọc evidence',
  MATCHED_RULES: 'Lấy matched rules',
  RISK_RULE_EXPLANATION: 'Đối chiếu score contributions',
  PROCESS_NETWORK_CORRELATION: 'Kiểm tra process/network correlation',
  ALTERNATIVE_EXPLANATIONS: 'Tìm các giải thích hợp lệ khác',
  CACHE_LOOKUP: 'Tra cứu Threat Memory (cache)',
  MODEL_INFERENCE: 'Suy luận mô hình AI (JSON có schema)',
  ANSWER_GENERATION: 'Tạo bản phân tích',
  DETERMINISTIC_FALLBACK: 'Dự phòng xác định (không phải AI)',
  CLAIM_VERIFICATION: 'Kiểm chứng kết luận',
  ANSWER_VERIFICATION: 'Kiểm chứng kết luận',
  ANALYSIS_PERSISTENCE: 'Lưu kết quả phân tích',
  RESPONSE_RECOMMENDATION: 'Đối chiếu policy ứng phó (chỉ đọc)',
  RESULT_SYNTHESIS: 'Tổng hợp kết quả',
  // AI Rule Generator
  REQUEST_UNDERSTANDING: 'Hiểu yêu cầu',
  PLATFORM_LOGSOURCE: 'Xác định nền tảng và logsource',
  TELEMETRY_FIELDS: 'Kiểm tra Agent telemetry fields',
  CLARIFICATION: 'Cần làm rõ',
  SIGMA_GENERATION: 'Tạo Sigma',
  SCHEMA_RUNTIME_CHECK: 'Kiểm tra schema/runtime support',
  HISTORICAL_VALIDATION: 'Historical validation (Agent B)',
  RESULT_EXPLANATION: 'Giải thích kết quả',
};

const PHASE_LABELS = {
  CONTEXT_RETRIEVAL: 'Ngữ cảnh',
  REQUIREMENT_CHECK: 'Yêu cầu',
  EVIDENCE_ANALYSIS: 'Phân tích bằng chứng',
  MODEL_GENERATION: 'Sinh kết quả',
  TOOL_VALIDATION: 'Kiểm chứng',
  RESULT_SYNTHESIS: 'Tổng hợp',
};

const SOURCE_LABELS = {
  ENDPOINT_AGENT: 'Endpoint Agent',
  MANAGER_STORE: 'Kho Manager',
  ANALYST_INPUT: 'Phân tích viên',
  AI_INFERENCE: 'Mô hình AI',
  DETERMINISTIC: 'Rule / Mã xác định',
  HYBRID: 'Kết hợp',
};


const RUN_STATUS_META = {
  CREATED: { label: 'Đang xếp hàng', color: '#60a5fa', bg: 'rgba(59,130,246,0.14)' },
  RUNNING: { label: 'Đang suy luận trực tiếp', color: '#38bdf8', bg: 'rgba(56,189,248,0.15)' },
  COMPLETED: { label: 'Hoàn tất', color: '#10b981', bg: 'rgba(16,185,129,0.14)' },
  TIMEOUT: { label: 'Hết thời gian AI (Đã Fallback)', color: '#f59e0b', bg: 'rgba(245,158,11,0.16)' },
  FAILED: { label: 'Thất bại', color: '#ef4444', bg: 'rgba(239,68,68,0.14)' },
  CANCELLED: { label: 'Đã hủy', color: '#94a3b8', bg: 'rgba(148,163,184,0.14)' },
  NEEDS_CLARIFICATION: { label: 'Cần làm rõ', color: '#d29922', bg: 'rgba(210,153,34,0.15)' },
};

const STAGE_STATUS_META = {
  RUNNING: { label: 'Đang chạy', color: '#38bdf8' },
  COMPLETED: { label: 'Hoàn tất', color: '#10b981' },
  SKIPPED: { label: 'Bỏ qua', color: '#94a3b8' },
  TIMEOUT: { label: 'Hết thời gian', color: '#f59e0b' },
  FAILED: { label: 'Thất bại', color: '#ef4444' },
  CANCELLED: { label: 'Đã hủy', color: '#94a3b8' },
  PENDING: { label: 'Chờ', color: '#64748b' },
  NEEDS_CLARIFICATION: { label: 'Cần làm rõ', color: '#d29922' },
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

const VERDICT_LABELS = {
  PASSED: 'Validator: ĐẠT',
  FAILED: 'Validator: KHÔNG ĐẠT',
  INCONCLUSIVE: 'Validator: CHƯA KẾT LUẬN (không phải đạt)',
  UNSUPPORTED_BY_ENGINE: 'Detection Engine không hỗ trợ',
};
const VERDICT_COLORS = { PASSED: '#10b981', FAILED: '#ef4444', INCONCLUSIVE: '#f59e0b', UNSUPPORTED_BY_ENGINE: '#ef4444' };

function CertaintyLine({ certainty, text, detail }) {
  return (
    <div style={{ display: 'flex', gap: '0.45rem', alignItems: 'flex-start', fontSize: '0.75rem' }}>
      <CertaintyBadge certainty={certainty} />
      <div style={{ color: 'var(--text-primary)' }}>
        {text}
        {detail && <div style={{ color: 'var(--text-tertiary)', fontSize: '0.7rem' }}>{detail}</div>}
      </div>
    </div>
  );
}

function KeyValues({ rows, notes }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '0.2rem 0.7rem', fontSize: '0.75rem' }}>
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <span style={{ color: 'var(--text-tertiary)' }}>{k}</span>
          <span style={{ color: 'var(--text-primary)', wordBreak: 'break-word' }}>{v}</span>
        </div>
      ))}
      {Array.isArray(notes) && notes.length > 0 && (
        <div style={{ gridColumn: '1 / -1', color: 'var(--text-secondary)' }}>
          {notes.map((n) => <div key={n}>• {n}</div>)}
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
      {stage === 'RISK_RULE_EXPLANATION' && sr?.reconciliation && (
        <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
          Đối chiếu: tổng đóng góp <strong>{sr.reconciliation.contributions_sum ?? '—'}</strong> · điểm Detection Engine{' '}
          <strong>{sr.reconciliation.final_score ?? '—'}</strong> ·{' '}
          <span style={{ color: (CERTAINTY_LABELS[sr.reconciliation.status] || CERTAINTY_LABELS.UNKNOWN).color }}>
            {(CERTAINTY_LABELS[sr.reconciliation.status] || CERTAINTY_LABELS.UNKNOWN).label}
          </span>
        </div>
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

      {['CLAIM_VERIFICATION', 'ANSWER_VERIFICATION', 'SCHEMA_RUNTIME_CHECK'].includes(stage) && Array.isArray(sr?.checks) && (
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
                  {chk.certainty && <span style={{ fontSize: '0.67rem', color: cert.color }}>{cert.label}</span>}
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

      {stage === 'REQUEST_UNDERSTANDING' && sr?.intent && (
        <KeyValues rows={[
          ['Nền tảng', sr.intent.platform || 'chưa rõ'],
          ['Tiến trình cha', (sr.intent.parent || []).join(', ') || sr.intent.parent_hint || '—'],
          ['Tiến trình con', (sr.intent.child || []).join(', ') || '—'],
          ['Từ khóa lệnh', (sr.intent.command || []).join(', ') || '—'],
          ['Gọi mô hình', sr.model_used ? 'Có' : 'Không'],
        ]} notes={sr.notices} />
      )}

      {stage === 'PLATFORM_LOGSOURCE' && sr && (
        <KeyValues rows={[
          ['Nền tảng', sr.platform || 'chưa rõ'],
          ['Logsource', sr.logsource ? `${sr.logsource.category} / ${sr.logsource.product}` : '—'],
          ...(sr.foreign_children?.length ? [['Không thuộc nền tảng', sr.foreign_children.join(', ')]] : []),
        ]} />
      )}

      {stage === 'TELEMETRY_FIELDS' && sr && (
        <KeyValues rows={[
          ['Trường Agent gửi', (sr.fields || []).join(', ')],
          ['Nền tảng thấy 24 giờ qua', (sr.observed_platforms || []).join(', ') || 'chưa có'],
          ['Tiến trình cha quan sát', (sr.observed_parents || []).join(', ') || '—'],
        ]} />
      )}

      {stage === 'CLARIFICATION' && Array.isArray(sr?.questions) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.76rem' }}>
          {sr.questions.map((q) => (
            <div key={q.slot} style={{ display: 'flex', gap: '0.4rem', color: 'var(--text-secondary)' }}>
              <FiHelpCircle size={12} color="#d29922" style={{ marginTop: '0.15rem', flexShrink: 0 }} />
              <span>{q.text}{q.options?.length ? ` (${q.options.slice(0, 5).join(' · ')})` : ''}</span>
            </div>
          ))}
        </div>
      )}

      {stage === 'HISTORICAL_VALIDATION' && sr?.validation && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
            <span data-testid="validation-verdict" style={{ fontWeight: 700, color: VERDICT_COLORS[sr.validation.verdict] || '#94a3b8' }}>
              {VERDICT_LABELS[sr.validation.verdict] || sr.validation.verdict}
            </span>
            {sr.validation.fpr != null && <span>· FPR {(sr.validation.fpr * 100).toFixed(2)}%</span>}
            {sr.validation.precision != null && <span>· Precision {(sr.validation.precision * 100).toFixed(2)}%</span>}
            {sr.validation.recall != null && <span>· Recall {(sr.validation.recall * 100).toFixed(2)}%</span>}
            {sr.validation.confusion && (
              <span>· TP {sr.validation.confusion.tp} / FP {sr.validation.confusion.fp} / FN {sr.validation.confusion.fn} / TN {sr.validation.confusion.tn}</span>
            )}
          </div>
          {sr.validation.dataset?.limitations && <div style={{ color: 'var(--text-tertiary)' }}>{sr.validation.dataset.limitations}</div>}
          {sr.recent_telemetry && (
            <div>
              Dry-run 24 giờ (không có nhãn): <strong>{sr.recent_telemetry.matches}</strong> lần khớp trên{' '}
              {sr.recent_telemetry.processes_scanned} tiến trình.
            </div>
          )}
        </div>
      )}

      {stage === 'ALTERNATIVE_EXPLANATIONS' && Array.isArray(sr?.alternatives) && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          {sr.alternatives.map((alt) => <CertaintyLine key={alt.alt_id} certainty={alt.certainty} text={alt.explanation} detail={alt.basis} />)}
        </div>
      )}

      {stage === 'ANSWER_GENERATION' && sr && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          <span>Mô hình: <code>{sr.model}</code> · Lần {sr.attempt}{sr.facts != null ? ` · ${sr.facts} dữ kiện đầu vào` : ''}</span>
          {Array.isArray(sr.feedback) && sr.feedback.length > 0 && (
            <div>Yêu cầu sửa từ bộ kiểm chứng: {sr.feedback.join(' · ')}</div>
          )}
          {Array.isArray(sr.cited_facts) && sr.cited_facts.length > 0 && <span>Dữ kiện được trích: {sr.cited_facts.join(', ')}</span>}
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

export default function ReasoningTracePanel({
  runs = [],
  activeRun = null,
  events = [],
  loading = false,
  streaming = false,
  expanded,
  onToggleExpand,
  onSelectRun,
  onSelectEvidenceRef,
  onRetry,
  title = 'Quá trình phân tích',
  emptyText,
}) {
  const [openStages, setOpenStages] = useState({});
  const [highlightRule, setHighlightRule] = useState(null);
  const [own, setOwn] = useState({ run: null, value: null, live: false });

  const { cards } = useMemo(() => buildStageCards(mergeEvents([], events)), [events]);
  const runStatus = traceRunStatus(activeRun, events) || (streaming ? 'RUNNING' : null);
  const running = runStatus === 'RUNNING' || runStatus === 'CREATED' || streaming;
  // Open while the backend works and after a run watched live, a failure or a question; otherwise the
  // analyst decides. Toggling is local state only: it never calls the API or the model.
  const runKey = activeRun?.analysis_run_id || null;
  if (own.run !== runKey) setOwn({ run: runKey, value: null, live: running });
  else if (running && !own.live) setOwn({ ...own, live: true });
  const attention = ['FAILED', 'TIMEOUT', 'NEEDS_CLARIFICATION', 'CANCELLED'].includes(runStatus);
  const isExpanded = expanded ?? own.value ?? (running || own.live || attention);
  const toggle = () => (onToggleExpand ? onToggleExpand() : setOwn({ ...own, value: !isExpanded }));
  const statusMeta = RUN_STATUS_META[runStatus] || { label: 'Chưa chạy', color: '#94a3b8', bg: 'rgba(148,163,184,0.12)' };
  const failure = [...events].reverse().find((ev) => ev.event_type === 'run_failed' || ev.event_type === 'analysis_failed');

  const hasTimeoutFallback = useMemo(
    () => runStatus === 'TIMEOUT' || cards.some((c) => ['MODEL_INFERENCE', 'ANSWER_GENERATION', 'REQUEST_UNDERSTANDING'].includes(c.stage)
      && ['TIMEOUT', 'FAILED'].includes(c.event.status)),
    [runStatus, cards],
  );

  const handleRuleClick = (ruleId) => {
    setHighlightRule((prev) => (prev === ruleId ? null : ruleId));
    setOpenStages((prev) => ({ ...prev, 'RISK_RULE_EXPLANATION-1': true }));
  };

  return (
    <div
      data-testid="decision-trace-panel"
      style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
        padding: '0.9rem 1.05rem', display: 'flex', flexDirection: 'column', gap: '0.7rem',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.6rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
          <FiDatabase size={15} color="#38bdf8" />
          <strong style={{ fontSize: '0.92rem', color: 'var(--text-primary)' }}>{title}</strong>
          {activeRun && (
            <span
              data-testid="trace-run-status"
              data-status={runStatus || ''}
              style={{
                padding: '0.16rem 0.55rem', borderRadius: '999px', fontSize: '0.72rem', fontWeight: 700,
                color: statusMeta.color, background: statusMeta.bg, border: `1px solid ${statusMeta.color}44`,
                display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
              }}
            >
              {running && <FiLoader size={11} className="animate-spin" />}
              {statusMeta.label}
            </span>
          )}
          {activeRun?.analysis_run_id && (
            <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
              {shortenId(activeRun.analysis_run_id)}
              {activeRun.model_name ? ` · ${activeRun.model_name}` : ''}
              {activeRun.task_type === 'incident_analysis' || !activeRun.task_type
                ? ` · ${activeRun.mode === 'fresh' ? 'Phân tích mới' : 'Tái sử dụng bộ nhớ'}` : ''}
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
                background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-secondary)',
                borderRadius: '6px', padding: '0.25rem 0.5rem', fontSize: '0.74rem',
              }}
            >
              {runs.map((r) => (
                <option key={r.analysis_run_id} value={r.analysis_run_id}>
                  {shortenId(r.analysis_run_id)} · {r.status} · {formatDateTimeVN(r.created_at)}
                </option>
              ))}
            </select>
          )}
          {onRetry && !running && ['FAILED', 'TIMEOUT', 'CANCELLED'].includes(runStatus) && (
            <button
              type="button"
              data-testid="trace-retry"
              onClick={onRetry}
              style={{
                background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.4)', color: '#fbbf24',
                borderRadius: '6px', padding: '0.3rem 0.65rem', fontSize: '0.76rem', fontWeight: 600, cursor: 'pointer',
                display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
              }}
            >
              <FiRefreshCw size={12} /> Thử lại
            </button>
          )}
          {activeRun && (
            <button
              type="button"
              data-testid="toggle-trace-details"
              onClick={toggle}
              style={{
                background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.35)', color: '#93c5fd',
                borderRadius: '6px', padding: '0.3rem 0.65rem', fontSize: '0.76rem', fontWeight: 600, cursor: 'pointer',
                display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
              }}
            >
              {isExpanded ? <FiChevronDown size={13} /> : <FiChevronRight size={13} />}
              {isExpanded ? 'Ẩn chi tiết' : 'Hiện chi tiết'}
            </button>
          )}
        </div>
      </div>

      {!activeRun && !loading && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', lineHeight: 1.5 }}>
          {emptyText || 'Chưa có phiên phân tích nào được ghi vết cho mục này.'}
        </div>
      )}

      {activeRun && !isExpanded && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Backend đã ghi {cards.length} bước
          {activeRun.started_at ? ` · bắt đầu ${formatDateTimeVN(activeRun.started_at)}` : ''}. Bấm{' '}
          <strong>Hiện chi tiết</strong> để xem bằng chứng, rule và kết quả kiểm chứng từng bước.
        </div>
      )}

      {isExpanded && activeRun && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
          {hasTimeoutFallback && (
            <div
              data-testid="trace-timeout-fallback-banner"
              style={{
                padding: '0.6rem 0.8rem', borderRadius: '6px', background: 'rgba(245, 158, 11, 0.12)',
                border: '1px solid rgba(245, 158, 11, 0.45)', color: '#fbbf24', fontSize: '0.78rem', fontWeight: 600,
              }}
            >
              Mô hình AI hết thời gian hoặc lỗi. Phần còn lại do hệ thống tổng hợp từ dữ liệu thật và được ghi rõ là
              không phải AI; không có kết luận AI nào được giả lập.
            </div>
          )}
          {failure && !hasTimeoutFallback && (
            <div data-testid="trace-failure-banner" style={{
              padding: '0.6rem 0.8rem', borderRadius: '6px', background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.4)', color: '#fca5a5', fontSize: '0.78rem',
            }}>
              {failure.summary} {failure.error_code ? <code>({failure.error_code})</code> : null}
            </div>
          )}

          {cards.length === 0 && (
            <div style={{ fontSize: '0.78rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <FiLoader size={13} className="animate-spin" /> Đang chờ sự kiện đầu tiên từ backend...
            </div>
          )}

          {cards.map((card, index) => {
            const item = card.event;
            const meta = STAGE_STATUS_META[item.status] || STAGE_STATUS_META.PENDING;
            const durText = formatDurationMs(item.duration_ms);
            const hasRich = Boolean(item.safe_result) || item.evidence_refs?.length > 0 || item.rule_refs?.length > 0
              || card.deltas.length > 0;
            const stageOpen = openStages[card.key] ?? (item.status === 'RUNNING' || ['FAILED', 'TIMEOUT', 'NEEDS_CLARIFICATION'].includes(item.status)
              || ['RISK_RULE_EXPLANATION', 'CLAIM_VERIFICATION', 'ANSWER_VERIFICATION', 'HISTORICAL_VALIDATION', 'CLARIFICATION'].includes(card.stage));
            return (
              <div
                key={card.key}
                data-testid={card.attempt > 1 ? `trace-stage-${card.stage}-${card.attempt}` : `trace-stage-${card.stage}`}
                data-status={item.status}
                style={{
                  border: '1px solid rgba(148,163,184,0.2)', borderLeft: `3px solid ${meta.color}`, borderRadius: '6px',
                  padding: '0.55rem 0.75rem', background: 'rgba(15, 23, 42, 0.35)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                    <StageIcon status={item.status} />
                    <strong style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                      {index + 1}. {item.status === 'RUNNING' ? `Đang ${(STAGE_LABELS[card.stage] || card.stage).toLowerCase()}…` : (STAGE_LABELS[card.stage] || card.stage)}
                      {card.attempt > 1 ? ` (lần ${card.attempt})` : ''}
                    </strong>
                    <span style={{ fontSize: '0.68rem', fontWeight: 700, color: meta.color, padding: '0.08rem 0.4rem', borderRadius: '4px', background: `${meta.color}18` }}>
                      {meta.label}
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)' }}>
                      · Nguồn: {SOURCE_LABELS[item.source_type] || item.source_type}
                      {item.phase && PHASE_LABELS[item.phase] ? ` · ${PHASE_LABELS[item.phase]}` : ''}
                    </span>
                    {item.error_code && <code style={{ fontSize: '0.66rem', color: '#fca5a5' }}>{item.error_code}</code>}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {durText && <span style={{ fontSize: '0.71rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>{durText}</span>}
                    {hasRich && (
                      <button
                        type="button"
                        onClick={() => setOpenStages((prev) => ({ ...prev, [card.key]: !stageOpen }))}
                        style={{ background: 'none', border: 'none', color: 'var(--text-tertiary)', fontSize: '0.72rem', cursor: 'pointer' }}
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
                    stage={card.stage}
                    item={item}
                    deltas={card.deltas}
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
