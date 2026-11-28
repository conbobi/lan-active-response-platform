import { CERTAINTY_LABELS } from './traceModel';

export default function CertaintyBadge({ certainty }) {
  const meta = CERTAINTY_LABELS[certainty] || CERTAINTY_LABELS.UNKNOWN;
  return (
    <span
      data-testid={`certainty-${certainty}`}
      style={{
        fontSize: '0.66rem', fontWeight: 700, color: meta.color, border: `1px solid ${meta.color}55`,
        borderRadius: '4px', padding: '0.02rem 0.35rem', whiteSpace: 'nowrap',
      }}
    >
      {certainty} · {meta.label}
    </span>
  );
}
