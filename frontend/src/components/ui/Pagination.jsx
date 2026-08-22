import React from 'react';
import { FiChevronLeft, FiChevronRight } from 'react-icons/fi';

export default function Pagination({ current, total, onChange }) {
  if (total <= 1) return null;
  const pages = Array.from({ length: total }, (_, i) => i + 1);
  const visible = pages.filter((p) => p === 1 || p === total || Math.abs(p - current) <= 1);

  const renderPages = () => {
    const result = [];
    let prev = 0;
    for (const p of visible) {
      if (p - prev > 1) result.push(<span key={`dots-${p}`} style={{ padding: '0 4px', color: 'var(--text-tertiary)', fontSize: '0.85rem' }}>…</span>);
      result.push(
        <button key={p} className={`page-btn ${p === current ? 'active' : ''}`} onClick={() => onChange(p)}>{p}</button>
      );
      prev = p;
    }
    return result;
  };

  return (
    <div className="pagination">
      <button className="page-btn" disabled={current === 1} onClick={() => onChange(current - 1)}><FiChevronLeft size={14} /></button>
      {renderPages()}
      <button className="page-btn" disabled={current === total} onClick={() => onChange(current + 1)}><FiChevronRight size={14} /></button>
    </div>
  );
}
