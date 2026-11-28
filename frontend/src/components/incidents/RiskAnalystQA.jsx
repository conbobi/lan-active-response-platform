import { useEffect, useState } from 'react';
import { FiCheckCircle, FiCpu, FiDatabase, FiMessageSquare, FiSend, FiXCircle } from 'react-icons/fi';
import { askRiskAnalyst, listQuestionRuns } from '../../api/threatMemory';
import useRunTrace from '../../hooks/useRunTrace';
import ReasoningTracePanel from '../ai/ReasoningTracePanel';
import CertaintyBadge from '../ai/CertaintyBadge';
import { shortenId } from '../../i18n/viVN';

// AI Risk Analyst: the analyst asks, the backend answers with a verified, structured explanation.
// The score shown is the Detection Engine's; the model can only explain it.

const card = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-md)',
  padding: '0.9rem 1.05rem', display: 'flex', flexDirection: 'column', gap: '0.6rem',
};
const heading = { fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' };

function Section({ title, children, testId }) {
  return (
    <div data-testid={testId} style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
      <div style={heading}>{title}</div>
      {children}
    </div>
  );
}

function EvidenceChips({ ids, onSelect }) {
  if (!ids?.length) return null;
  return (
    <span style={{ display: 'inline-flex', gap: '0.25rem', flexWrap: 'wrap', marginLeft: '0.35rem' }}>
      {ids.slice(0, 4).map((id) => (
        <button key={id} type="button" onClick={() => onSelect?.(id)} title={`Bằng chứng ${id}`}
                style={{ background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.28)', color: '#93c5fd',
                         borderRadius: '4px', padding: '0 0.3rem', fontSize: '0.66rem', fontFamily: 'monospace', cursor: 'pointer' }}>
          {shortenId(id)}
        </button>
      ))}
    </span>
  );
}

export function StructuredAnswer({ result, onSelectEvidenceRef }) {
  if (!result) return null;
  const ai = result.conclusion_source === 'AI_INFERENCE';
  const text = { fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5 };
  return (
    <div data-testid="structured-answer" style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <span data-testid="answer-source" style={{
          fontSize: '0.7rem', fontWeight: 700, padding: '0.1rem 0.5rem', borderRadius: '999px',
          color: ai ? '#a78bfa' : '#94a3b8', border: `1px solid ${ai ? '#a78bfa66' : '#94a3b866'}`,
        }}>
          {ai ? <><FiCpu size={11} /> Kết luận AI ({result.model_name}) đã qua kiểm chứng</>
            : <><FiDatabase size={11} /> Tổng hợp từ dữ liệu — không phải AI</>}
        </span>
        <span data-testid="answer-risk-score" style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
          Risk score (Detection Engine): <strong style={{ color: 'var(--text-primary)' }}>{result.risk_score?.value}/100</strong>
          {' '}· {result.risk_score?.severity}
        </span>
        {result.attempts > 1 && <span style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>· {result.attempts} lần sinh</span>}
      </div>

      <div data-testid="answer-conclusion" style={{ fontSize: '0.86rem', color: 'var(--text-primary)', lineHeight: 1.55 }}>
        {result.conclusion}
      </div>

      <Section title="Dữ kiện quan sát" testId="answer-facts">
        {result.observed_facts.map((f) => (
          <div key={f.fact_id} style={{ display: 'flex', gap: '0.45rem', alignItems: 'flex-start', ...text }}>
            <code style={{ fontSize: '0.68rem', color: 'var(--text-tertiary)' }}>{f.fact_id}</code>
            <CertaintyBadge certainty={f.certainty} />
            <span>{f.statement}<EvidenceChips ids={f.evidence_ids} onSelect={onSelectEvidenceRef} /></span>
          </div>
        ))}
      </Section>

      {result.matched_rules?.length > 0 && (
        <Section title="Rule đã khớp">
          {result.matched_rules.map((r) => (
            <div key={r.rule_id} style={text}>
              <code>{r.rule_id}</code>{r.label ? ` — ${r.label}` : ''}
              {r.contribution != null ? <strong style={{ color: '#60a5fa' }}> +{r.contribution}</strong> : ''}
              {r.reason ? ` · ${r.reason}` : ''}
            </div>
          ))}
        </Section>
      )}

      {result.alternative_explanations?.length > 0 && (
        <Section title="Giải thích khác cần cân nhắc">
          {result.alternative_explanations.map((a) => (
            <div key={a.alt_id} style={{ display: 'flex', gap: '0.45rem', alignItems: 'flex-start', ...text }}>
              <CertaintyBadge certainty={a.certainty} />
              <span>{a.explanation} <span style={{ color: 'var(--text-tertiary)' }}>({a.basis})</span></span>
            </div>
          ))}
        </Section>
      )}

      {result.missing_evidence?.length > 0 && (
        <Section title="Dữ liệu còn thiếu" testId="answer-missing">
          {result.missing_evidence.map((m) => <div key={m} style={text}>• {m}</div>)}
        </Section>
      )}

      {result.validation_results?.length > 0 && (
        <Section title="Kết quả kiểm chứng" testId="answer-validation">
          {result.validation_results.map((c) => (
            <div key={c.check_id} style={{ display: 'flex', gap: '0.4rem', alignItems: 'flex-start', ...text }}>
              {c.passed ? <FiCheckCircle size={13} color="#10b981" style={{ marginTop: '0.15rem' }} />
                : <FiXCircle size={13} color="#ef4444" style={{ marginTop: '0.15rem' }} />}
              <span><strong>{c.label}</strong> — {c.detail}</span>
            </div>
          ))}
        </Section>
      )}

      {result.recommendations?.length > 0 && (
        <Section title="Khuyến nghị (cần phân tích viên phê duyệt, hệ thống không tự thực thi)">
          {result.recommendations.map((r) => <div key={r.text} style={text}>• {r.text}</div>)}
        </Section>
      )}

      <Section title="Giới hạn">
        {result.limitations.map((l) => <div key={l} style={{ ...text, color: 'var(--text-tertiary)' }}>• {l}</div>)}
      </Section>
    </div>
  );
}

export default function RiskAnalystQA({ incident, onSelectEvidenceRef }) {
  const incidentId = incident?.id;
  const trace = useRunTrace(incidentId ? `risk-question-run:${incidentId}` : null);
  const [question, setQuestion] = useState('');
  const [runs, setRuns] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const suggestions = [
    `Vì sao incident này có risk score ${incident?.risk_score ?? ''}?`.replace(' ?', '?'),
    'Bằng chứng nào cho thấy đây là tấn công thật?',
    'Còn thiếu dữ liệu gì để kết luận?',
  ];

  const refreshRuns = () => incidentId && listQuestionRuns(incidentId)
    .then((res) => setRuns(Array.isArray(res?.runs) ? res.runs : []))
    .catch(() => {});

  useEffect(() => { refreshRuns(); }, [incidentId]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { if (trace.status && trace.status !== 'RUNNING') refreshRuns(); }, [trace.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const ask = async (text) => {
    const q = (text ?? question).trim();
    if (q.length < 3 || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await askRiskAnalyst(incidentId, q);
      trace.attach(res.run_id);
      setQuestion('');
    } catch (err) {
      setError(err?.message || 'Không gửi được câu hỏi');
    } finally {
      setBusy(false);
    }
  };

  const running = trace.status === 'RUNNING' || trace.status === 'CREATED';
  return (
    <div data-testid="risk-analyst-qa" style={card}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <FiMessageSquare size={15} color="#a78bfa" />
        <strong style={{ fontSize: '0.92rem', color: 'var(--text-primary)' }}>Hỏi AI Risk Analyst</strong>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
          Chỉ đọc: không đổi risk score, không thực thi ứng phó.
        </span>
      </div>
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
        {suggestions.map((s) => (
          <button key={s} type="button" disabled={busy || running} onClick={() => ask(s)}
                  style={{ fontSize: '0.74rem', padding: '0.2rem 0.6rem', borderRadius: '999px', cursor: 'pointer',
                           border: '1px solid rgba(167,139,250,0.4)', background: 'rgba(167,139,250,0.08)', color: '#c4b5fd' }}>
            {s}
          </button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: '0.4rem' }}>
        <input data-testid="risk-question-input" value={question} maxLength={500}
               onChange={(e) => setQuestion(e.target.value)}
               onKeyDown={(e) => e.key === 'Enter' && ask()}
               placeholder="Ví dụ: Vì sao incident này có risk score 55?"
               style={{ flex: 1, background: 'var(--bg-primary)', border: '1px solid var(--border-color)', color: 'var(--text-primary)',
                        borderRadius: '6px', padding: '0.45rem 0.6rem', fontSize: '0.82rem' }} />
        <button data-testid="risk-question-send" type="button" onClick={() => ask()} disabled={busy || running || question.trim().length < 3}
                style={{ background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.45)', color: '#c4b5fd',
                         borderRadius: '6px', padding: '0.4rem 0.75rem', cursor: 'pointer' }}>
          <FiSend size={13} />
        </button>
      </div>
      {error && <div style={{ fontSize: '0.78rem', color: '#fca5a5' }}>{error}</div>}
      {trace.error && <div style={{ fontSize: '0.78rem', color: '#fbbf24' }}>{trace.error}</div>}

      {trace.run && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Câu hỏi: <em>{trace.run.question}</em>
        </div>
      )}
      {(trace.runId || runs.length > 0) && (
        <ReasoningTracePanel
          runs={runs}
          activeRun={trace.run}
          events={trace.events}
          streaming={trace.streaming}
          onSelectRun={(id) => trace.attach(id)}
          onSelectEvidenceRef={onSelectEvidenceRef}
          onRetry={trace.run?.question ? () => ask(trace.run.question) : undefined}
          emptyText="Chọn một câu hỏi trước đó hoặc đặt câu hỏi mới."
        />
      )}
      {trace.run?.result && <StructuredAnswer result={trace.run.result} onSelectEvidenceRef={onSelectEvidenceRef} />}
    </div>
  );
}
