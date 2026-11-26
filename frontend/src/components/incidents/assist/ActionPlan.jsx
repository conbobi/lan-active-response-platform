// "5. Những việc nên làm": multi-action plan grouped by category (API: plan, batch routes).
// Every button maps to a backend route; unavailable items explain why.
import { useState } from 'react';
import Button from '../../ui/Button';

const CATEGORIES = [
  ['investigation', 'Điều tra'],
  ['containment', 'Ngăn chặn'],
  ['application_protection', 'Bảo vệ ứng dụng'],
  ['remediation', 'Khắc phục'],
  ['recovery', 'Phục hồi'],
];
const RISK = { low: 'thấp', medium: 'trung bình', high: 'cao', unknown: 'chưa rõ' };
const label = (kind) => kind.replaceAll('_', ' ');

function PlanCard({ item, selected, onToggle, selectable }) {
  const action = item.action;
  return (
    <div style={{
      border: `1px solid ${item.available ? 'var(--border)' : 'rgba(107,114,128,0.4)'}`, borderRadius: 8,
      padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.35rem',
      opacity: item.available || item.execution === 'advisory' ? 1 : 0.75,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        {selectable && (
          <input type="checkbox" checked={selected} onChange={onToggle} aria-label={`Chọn ${label(item.action_type)}`} />
        )}
        <strong style={{ fontSize: '0.84rem' }}>#{item.priority} {label(item.action_type)}</strong>
        <span style={{ fontSize: '0.7rem', padding: '0.05rem 0.35rem', borderRadius: 4, border: '1px solid var(--border)' }}>
          {item.execution === 'advisory' ? 'khuyến nghị' : item.policy_decision}
        </span>
        {action && (
          <span style={{ fontSize: '0.7rem', color: action.mock ? '#a855f7' : 'var(--accent)' }}>
            {action.mock ? 'MOCK · ' : ''}trạng thái: {action.status}
          </span>
        )}
      </div>
      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{item.why}</div>
      <div style={{ fontSize: '0.74rem', display: 'grid', gap: '0.15rem' }}>
        <span><strong>Tác dụng dự kiến:</strong> {item.expected_effect}</span>
        <span><strong>Rủi ro gián đoạn:</strong> {RISK[item.operational_risk] || item.operational_risk}</span>
        {item.verification_method && <span><strong>Xác minh:</strong> {item.verification_method}</span>}
        {item.rollback && <span><strong>Rollback:</strong> {item.rollback}</span>}
        {item.depends_on.length > 0 && <span><strong>Làm sau:</strong> {item.depends_on.map(label).join(', ')}</span>}
        {item.conflicts_with.length > 0 && <span><strong>Xung đột với:</strong> {item.conflicts_with.map(label).join(', ')}</span>}
        {item.evidence_ids.length > 0 && (
          <span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
            <strong style={{ fontFamily: 'inherit' }}>Bằng chứng:</strong> {item.evidence_ids.slice(0, 4).join(', ')}
            {item.evidence_ids.length > 4 ? ` +${item.evidence_ids.length - 4}` : ''}
          </span>
        )}
      </div>
      {!item.available && item.disabled_reason && (
        <div role="note" style={{ fontSize: '0.74rem', color: '#f59e0b' }}>
          {item.outcome_code ? `[${item.outcome_code}] ` : ''}{item.disabled_reason}
        </div>
      )}
      {item.related_incident_id && (
        <a href={`/incidents/${encodeURIComponent(item.related_incident_id)}`} style={{ fontSize: '0.76rem' }}>
          Thực hiện trên sự cố host liên quan {item.related_incident_id} (cần phê duyệt) →
        </a>
      )}
      {item.remediation && (
        <details style={{ fontSize: '0.76rem' }}>
          <summary style={{ cursor: 'pointer' }}>Hướng dẫn và bản vá đề xuất (cần phê duyệt, không tự áp dụng)</summary>
          <ul style={{ margin: '0.25rem 0', paddingLeft: '1.2rem' }}>
            {item.remediation.guidance.map((text) => <li key={text}>{text}</li>)}
          </ul>
          <div style={{ color: 'var(--text-tertiary)' }}>{item.remediation.applies_to}</div>
          <pre style={{ backgroundColor: 'rgba(0,0,0,0.4)', padding: '0.5rem', borderRadius: 4, overflowX: 'auto', fontSize: '0.72rem' }}>
            {item.remediation.secure_code_diff}
          </pre>
        </details>
      )}
    </div>
  );
}

export default function ActionPlan({ plan, canExecute, busy, onBatchPropose, onBatchDecision, pendingActions }) {
  const [selected, setSelected] = useState(() => new Set());
  const [pendingSelected, setPendingSelected] = useState(() => new Set());
  const proposable = (item) => item.available && item.execution === 'executable' && !item.related_incident_id && !item.action;

  const toggle = (set, setter, key) => {
    const next = new Set(set);
    if (next.has(key)) next.delete(key); else next.add(key);
    setter(next);
  };

  return (
    <section aria-label="Những việc nên làm" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <h4 style={{ margin: 0, fontSize: '0.86rem' }}>5. Những việc nên làm</h4>
      {CATEGORIES.map(([category, title]) => {
        const items = plan.filter((item) => item.category === category);
        if (!items.length) return null;
        return (
          <div key={category} style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
            <span style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>{title}</span>
            {items.map((item) => (
              <PlanCard key={item.plan_id} item={item} selectable={proposable(item)}
                        selected={selected.has(item.action_type)}
                        onToggle={() => toggle(selected, setSelected, item.action_type)} />
            ))}
          </div>
        );
      })}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <Button size="sm" variant="primary" disabled={busy || selected.size === 0}
                onClick={async () => { await onBatchPropose([...selected]); setSelected(new Set()); }}>
          Đề xuất các hành động đã chọn ({selected.size})
        </Button>
      </div>
      {canExecute && pendingActions.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.78rem' }}>
          <strong>Phê duyệt hàng loạt ({pendingActions.length} đang chờ)</strong>
          {pendingActions.map((action) => (
            <label key={action.action_id} style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
              <input type="checkbox" checked={pendingSelected.has(action.action_id)}
                     onChange={() => toggle(pendingSelected, setPendingSelected, action.action_id)} />
              {label(action.action_type)} <span style={{ fontFamily: 'monospace', color: 'var(--text-tertiary)' }}>{action.action_id.slice(0, 10)}…</span>
            </label>
          ))}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            {['approve', 'reject'].map((operation) => (
              <Button key={operation} size="sm" variant={operation === 'approve' ? 'primary' : 'danger'}
                      disabled={busy || pendingSelected.size === 0}
                      onClick={async () => { await onBatchDecision(operation, [...pendingSelected]); setPendingSelected(new Set()); }}>
                {operation === 'approve' ? 'Phê duyệt đã chọn' : 'Từ chối đã chọn'}
              </Button>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
