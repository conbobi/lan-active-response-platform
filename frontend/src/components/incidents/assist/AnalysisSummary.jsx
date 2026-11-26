// Six-part, evidence-referenced incident explanation for SOC analysts (API: analysis).
// Knowledge and similar cases are reference material and are shown apart from evidence.
const SEVERITY = {
  low: { label: 'Thấp', color: '#10b981' },
  medium: { label: 'Trung bình', color: '#f59e0b' },
  high: { label: 'Cao', color: '#f97316' },
  critical: { label: 'Nghiêm trọng', color: '#ef4444' },
};

const RESULT_LABELS = [
  ['applied', 'Đã áp dụng', '#10b981'],
  ['awaiting_approval', 'Chờ phê duyệt / thực thi', '#f59e0b'],
  ['blocked', 'Bị từ chối / hết hạn', '#9ca3af'],
  ['failed', 'Thất bại', '#ef4444'],
  ['rolled_back', 'Đã rollback', '#6b7280'],
  ['mock', 'MOCK (không có tác động thật)', '#a855f7'],
];

const box = {
  backgroundColor: 'var(--card-bg, rgba(255, 255, 255, 0.03))',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  padding: '0.9rem 1rem',
  display: 'flex',
  flexDirection: 'column',
  gap: '0.5rem',
};
const heading = { margin: 0, fontSize: '0.86rem', fontWeight: 700 };
const muted = { fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 };
const mono = { fontFamily: 'monospace', fontSize: '0.74rem' };

function Refs({ refs }) {
  if (!refs?.length) return null;
  return <span style={{ ...mono, color: 'var(--text-tertiary)' }}> [{refs.join(', ')}]</span>;
}

export default function AnalysisSummary({ analysis }) {
  if (!analysis) return null;
  const { level } = analysis.assessment;
  const severity = SEVERITY[analysis.danger?.severity] || SEVERITY.medium;
  return (
    <section aria-label="Phân tích sự cố" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {analysis.historical && (
        <div role="status" style={{ ...box, borderColor: 'rgba(107,114,128,0.5)' }}>
          <strong style={{ fontSize: '0.82rem' }}>Sự cố đã đóng — chế độ chỉ đọc.</strong>
          <span style={muted}>Vẫn xem được phân tích và thu thập chỉ đọc; không áp dụng chặn hay giám sát mới.</span>
        </div>
      )}

      <div style={box}>
        <h4 style={heading}>1. Chuyện gì xảy ra?</h4>
        <p style={{ ...muted, margin: 0 }}>{analysis.what_happened}</p>
      </div>

      <div style={box}>
        <h4 style={heading}>2. Bằng chứng ({analysis.evidence.length})</h4>
        {analysis.evidence.length === 0 && <span style={muted}>Chưa có bằng chứng tương quan.</span>}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-tertiary)' }}>
                <th scope="col">Nguồn</th><th scope="col">Mục tiêu</th><th scope="col">Thời điểm</th>
                <th scope="col">Hành vi</th><th scope="col">Evidence ID</th>
              </tr>
            </thead>
            <tbody>
              {analysis.evidence.map((row) => (
                <tr key={row.evidence_id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td style={mono}>{row.source || '—'}</td>
                  <td>{row.target}</td>
                  <td style={mono}>{row.time}</td>
                  <td>{row.behavior}</td>
                  <td style={{ ...mono, wordBreak: 'break-all' }}>{row.evidence_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={box}>
        <h4 style={heading}>
          3. Đánh giá{' '}
          <span style={{ ...mono, fontWeight: 600, padding: '0.1rem 0.4rem', borderRadius: 4, border: '1px solid var(--border)' }}>
            {level.pattern_id || 'n/a'} · mức {level.level} · {level.level_name}
          </span>
        </h4>
        {level.conclusion && <p style={{ ...muted, margin: 0 }}>{level.conclusion}</p>}
        <div style={{ fontSize: '0.8rem' }}>
          <strong>Đã xác nhận (có bằng chứng):</strong>
          {analysis.assessment.confirmed.length === 0 ? <span style={muted}> chưa có.</span> : (
            <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem' }}>
              {analysis.assessment.confirmed.map((fact) => (
                <li key={fact.text}>{fact.text}<Refs refs={fact.evidence_refs} /></li>
              ))}
            </ul>
          )}
        </div>
        {analysis.assessment.suspected.length > 0 && (
          <div style={{ fontSize: '0.8rem' }}>
            <strong>Nghi ngờ (chưa xác nhận):</strong>
            <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem' }}>
              {analysis.assessment.suspected.map((text) => <li key={text}>{text}</li>)}
            </ul>
          </div>
        )}
        {analysis.assessment.missing.length > 0 && (
          <div style={{ fontSize: '0.8rem' }}>
            <strong>Còn thiếu:</strong>
            <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem', color: 'var(--text-secondary)' }}>
              {analysis.assessment.missing.map((text) => <li key={text}>{text}</li>)}
            </ul>
          </div>
        )}
        {analysis.assessment.alternative_explanations.length > 0 && (
          <details style={{ fontSize: '0.78rem' }}>
            <summary style={{ cursor: 'pointer' }}>Giải thích khác cần loại trừ</summary>
            <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem' }}>
              {analysis.assessment.alternative_explanations.map((text) => <li key={text}>{text}</li>)}
            </ul>
          </details>
        )}
        <div style={{ fontSize: '0.8rem' }}>
          <strong>MITRE ATT&CK:</strong>{' '}
          {analysis.attack_mapping.length === 0 ? <span style={muted}>không ánh xạ (bằng chứng chưa đủ).</span> :
            analysis.attack_mapping.map((m) => (
              <span key={m.technique_id} style={{ marginRight: '0.75rem' }}>
                <strong>{m.technique_id}</strong> {m.name}<Refs refs={m.evidence_refs.slice(0, 4)} />
                {m.evidence_refs.length > 4 && <span style={mono}> +{m.evidence_refs.length - 4}</span>}
              </span>
            ))}
        </div>
        {analysis.post_exploitation.length > 0 && (
          <div style={{ fontSize: '0.8rem' }}>
            <strong>Hoạt động host liên quan:</strong>
            <ul style={{ margin: '0.2rem 0 0', paddingLeft: '1.2rem' }}>
              {analysis.post_exploitation.map((item, idx) => (
                <li key={`${item.source_incident_id}-${idx}`}>
                  {item.kind} — <strong>{item.status === 'correlated' ? 'đã tương quan' : 'liên quan, chưa tương quan'}</strong>
                  {item.reason ? ` (${item.reason})` : ''}<Refs refs={item.evidence_refs} />
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div style={{ ...box, borderColor: `${severity.color}66` }}>
        <h4 style={heading}>4. Mức nguy hiểm: <span style={{ color: severity.color }}>{severity.label}</span></h4>
        <p style={{ ...muted, margin: 0 }}>{analysis.danger.impact}</p>
      </div>

      <div style={box}>
        <h4 style={heading}>6. Kết quả sau phản ứng</h4>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', fontSize: '0.78rem' }}>
          {RESULT_LABELS.map(([key, label, color]) => (
            <span key={key} style={{ color }}>
              {label}: <strong>{analysis.response_results?.[key]?.length || 0}</strong>
            </span>
          ))}
        </div>
      </div>

      {analysis.knowledge.length > 0 && (
        <details style={{ ...box, gap: '0.35rem' }}>
          <summary style={{ cursor: 'pointer', fontSize: '0.82rem', fontWeight: 600 }}>
            Tài liệu tham khảo ({analysis.knowledge.length}) — kiến thức, không phải bằng chứng của sự cố
          </summary>
          {analysis.knowledge.map((k) => (
            <div key={k.chunk_id} style={{ fontSize: '0.76rem', borderTop: '1px solid var(--border)', paddingTop: '0.35rem' }}>
              <div>
                <strong>{k.title}</strong>{' '}
                <span style={{ color: 'var(--text-tertiary)' }}>· {k.source_id} · {k.version}</span>{' '}
                {k.url?.startsWith('https://') && <a href={k.url} target="_blank" rel="noreferrer noopener">nguồn</a>}
              </div>
              <div style={{ color: 'var(--text-secondary)' }}>{k.excerpt}</div>
            </div>
          ))}
        </details>
      )}

      {analysis.similar_cases.length > 0 && (
        <div style={{ ...box, gap: '0.3rem' }}>
          <strong style={{ fontSize: '0.82rem' }}>Ca tương tự — tham khảo, không phải bằng chứng của sự cố này</strong>
          {analysis.similar_cases.map((c) => (
            <div key={c.incident_id} style={{ fontSize: '0.76rem' }}>
              <a href={`/incidents/${encodeURIComponent(c.incident_id)}`}>{c.incident_id}</a>{' '}
              · {c.classification} · nhãn analyst: <strong>{c.analyst_label}</strong>
              {' '}· độ tương đồng {Math.round(c.similarity * 100)}%
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
