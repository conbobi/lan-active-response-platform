import React from 'react';

const HEADING_TITLES = {
  'observed facts': 'Bằng chứng quan sát',
  'behavioral interpretation': 'Diễn giải hành vi',
  'attack hypothesis': 'Giả thuyết tấn công',
  'confidence': 'Độ tin cậy đánh giá',
  'potential impact': 'Tác động tiềm ẩn',
  'missing evidence': 'Bằng chứng còn thiếu',
  'recommended investigation': 'Hướng điều tra tiếp theo',
};

/**
 * Render inline text safely without dangerouslySetInnerHTML.
 * Strips/converts **bold** and `code` Markdown syntax into React elements.
 */
export function SafeInlineText({ text }) {
  if (!text) return null;
  const tokens = String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <>
      {tokens.map((part, idx) => {
        if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
          return (
            <strong key={idx} style={{ color: 'var(--text-primary)' }}>
              {part.slice(2, -2)}
            </strong>
          );
        }
        if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
          return (
            <code
              key={idx}
              style={{
                padding: '1px 5px',
                borderRadius: '4px',
                background: 'rgba(59, 130, 246, 0.12)',
                color: '#93c5fd',
                fontSize: '0.82em',
                fontFamily: 'monospace',
              }}
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        return <React.Fragment key={idx}>{part}</React.Fragment>;
      })}
    </>
  );
}

/**
 * Parse backend triage summary (which may contain Markdown headings/bullets)
 * into clean structured sections without exposing raw ##, **, or - prefixes.
 */
export function parseAnalysisSections(rawText) {
  if (!rawText || typeof rawText !== 'string') return { lead: [], sections: [] };
  const lines = rawText.replace(/\r\n/g, '\n').split('\n');
  const lead = [];
  const sections = [];
  let current = null;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    const headingMatch = trimmed.match(/^#{1,4}\s+(.+)$/);
    if (headingMatch) {
      const rawTitle = headingMatch[1].replace(/\*\*/g, '').trim();
      const translatedTitle = HEADING_TITLES[rawTitle.toLowerCase()] || rawTitle;
      current = { title: translatedTitle, key: rawTitle.toLowerCase(), items: [] };
      sections.push(current);
      continue;
    }
    const cleanedLine = trimmed.replace(/^[-*•]\s+/, '').replace(/^\d+\.\s+/, '');
    if (current) {
      current.items.push(cleanedLine);
    } else {
      lead.push(cleanedLine);
    }
  }
  return { lead, sections };
}

export function SafeStructuredParagraphs({ text }) {
  const { lead, sections } = parseAnalysisSections(text);
  if (!lead.length && !sections.length) return null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {lead.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.88rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
          {lead.map((line, idx) => (
            <div key={idx}>
              <SafeInlineText text={line} />
            </div>
          ))}
        </div>
      )}
      {sections.map((sec, idx) => (
        <div
          key={idx}
          style={{
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '0.7rem 0.9rem',
          }}
        >
          <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--primary)', marginBottom: '0.35rem' }}>
            {sec.title}
          </div>
          <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            {sec.items.map((item, itemIdx) => (
              <li key={itemIdx}>
                <SafeInlineText text={item} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

