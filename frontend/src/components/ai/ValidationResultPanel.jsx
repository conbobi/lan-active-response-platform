import React from 'react';
import { FiCheckCircle, FiAlertTriangle, FiXCircle, FiSliders } from 'react-icons/fi';

export default function ValidationResultPanel({ result }) {
  if (!result) {
    return (
      <div style={{
        borderRadius: '0.75rem',
        border: '1px solid var(--border-primary, #334155)',
        background: 'var(--bg-secondary, #162032)',
        padding: '1.5rem',
        textAlign: 'center',
        color: 'var(--text-secondary, #cbd5e1)',
        fontSize: '0.8125rem'
      }}>
        No validation results available. Run validation using Agent B.
      </div>
    );
  }

  const {
    passed,
    verdict,
    reason,
    fpr = 0,
    precision = 0,
    recall = 0,
    f1 = 0,
    confusion = { tp: 0, fp: 0, fn: 0, tn: 0 },
    thresholds = { fpr: 0.05, precision: 0.95 },
    llm_explanation,
    fp_samples = [],
    fn_samples = []
  } = result;

  const isPassed = passed || verdict === 'PASSED';
  const dataset = result.dataset;

  // No statistics to show: never render missing metrics as 0%.
  if (!result.confusion || fpr == null || verdict === 'INCONCLUSIVE' || verdict === 'UNSUPPORTED_BY_ENGINE') {
    const title = verdict === 'UNSUPPORTED_BY_ENGINE' ? 'Detection Engine không hỗ trợ rule này'
      : verdict === 'INCONCLUSIVE' ? 'Chưa đủ dữ liệu kiểm định' : 'Kiểm định không thành công';
    return (
      <div role="status" style={{ padding: '1rem 1.25rem', borderRadius: '0.75rem', border: '1px solid rgba(245, 158, 11, 0.4)',
                                  background: 'rgba(245, 158, 11, 0.08)', color: '#fcd34d' }}>
        <strong>{title}</strong>
        {reason && <div style={{ marginTop: '0.35rem', color: '#e5e7eb' }}>{reason}</div>}
        {dataset?.total != null && (
          <div style={{ marginTop: '0.35rem', fontSize: '0.8rem', color: '#9ca3af' }}>
            Tập kiểm định: {dataset.attack} mẫu tấn công, {dataset.benign} mẫu benign
          </div>
        )}
      </div>
    );
  }

  // Helper colors
  const fprClass = fpr < 0.05 ? 'good' : fpr <= 0.10 ? 'warn' : 'bad';
  const fprColor = fpr < 0.05 ? '#34d399' : fpr <= 0.10 ? '#fbbf24' : '#f87171';

  const precisionClass = precision >= 0.95 ? 'good' : precision >= 0.85 ? 'warn' : 'bad';
  const precisionColor = precision >= 0.95 ? '#34d399' : precision >= 0.85 ? '#fbbf24' : '#f87171';

  return (
    <div className="val-panel-root" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', width: '100%' }}>
      {/* 1. Verdict Banner */}
      <div
        className={`val-verdict-banner ${isPassed ? 'passed' : 'failed'}`}
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.875rem',
          padding: '1rem 1.25rem',
          borderRadius: '0.75rem',
          border: '1px solid',
          borderColor: isPassed ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)',
          background: isPassed ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)',
          color: isPassed ? '#6ee7b7' : '#fda4af'
        }}
      >
        <div style={{ marginTop: '0.125rem' }}>
          {isPassed ? (
            <FiCheckCircle size={22} color="#34d399" />
          ) : (
            <FiXCircle size={22} color="#f87171" />
          )}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', flexWrap: 'wrap' }}>
            <span style={{ fontWeight: 800, fontSize: '0.875rem', letterSpacing: '0.025em' }}>
              AGENT B VERDICT: {verdict || (isPassed ? 'PASSED' : 'FAILED')}
            </span>
            <span
              style={{
                fontSize: '0.6875rem',
                fontFamily: 'ui-monospace, monospace',
                padding: '0.15rem 0.5rem',
                borderRadius: '9999px',
                fontWeight: 600,
                background: isPassed ? 'rgba(16, 185, 129, 0.2)' : 'rgba(244, 63, 94, 0.2)',
                color: isPassed ? '#a7f3d0' : '#fecdd3'
              }}
            >
              FPR Target &le; {(thresholds.fpr * 100).toFixed(1)}% | Precision &ge;{' '}
              {(thresholds.precision * 100).toFixed(1)}%
            </span>
          </div>
          <p style={{ margin: '0.375rem 0 0 0', fontSize: '0.75rem', color: '#e6edf3', lineHeight: 1.5 }}>
            {reason}
          </p>
        </div>
      </div>

      {/* 2. Key Metrics Grid */}
      <div
        className="val-kpi-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '0.75rem'
        }}
      >
        {/* FPR */}
        <div
          className={`val-kpi-card ${fprClass}`}
          style={{
            background: '#161b22',
            border: '1px solid',
            borderColor: fprColor,
            borderRadius: '0.625rem',
            padding: '0.875rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.25rem'
          }}
        >
          <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: '#8b949e' }}>
            FPR (False Positive)
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'monospace', color: fprColor }}>
            {(fpr * 100).toFixed(2)}%
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#8b949e' }}>
            Threshold: &le; {(thresholds.fpr * 100).toFixed(1)}%
          </div>
        </div>

        {/* Precision */}
        <div
          className={`val-kpi-card ${precisionClass}`}
          style={{
            background: '#161b22',
            border: '1px solid',
            borderColor: precisionColor,
            borderRadius: '0.625rem',
            padding: '0.875rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.25rem'
          }}
        >
          <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: '#8b949e' }}>
            Precision
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'monospace', color: precisionColor }}>
            {(precision * 100).toFixed(2)}%
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#8b949e' }}>
            Threshold: &ge; {(thresholds.precision * 100).toFixed(1)}%
          </div>
        </div>

        {/* Recall */}
        <div
          className="val-kpi-card"
          style={{
            background: '#161b22',
            border: '1px solid #2d3644',
            borderRadius: '0.625rem',
            padding: '0.875rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.25rem'
          }}
        >
          <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: '#8b949e' }}>
            Recall (Sensitivity)
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'monospace', color: '#60a5fa' }}>
            {(recall * 100).toFixed(2)}%
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#8b949e' }}>
            Malicious attack hit rate
          </div>
        </div>

        {/* F1 Score */}
        <div
          className="val-kpi-card"
          style={{
            background: '#161b22',
            border: '1px solid #2d3644',
            borderRadius: '0.625rem',
            padding: '0.875rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.25rem'
          }}
        >
          <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: '#8b949e' }}>
            F1 Score
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'monospace', color: '#c084fc' }}>
            {(f1 * 100).toFixed(2)}%
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#8b949e' }}>
            Harmonic balance
          </div>
        </div>
      </div>

      {/* 3. Confusion Matrix 2x2 */}
      <div
        className="val-table-container"
        style={{
          background: 'var(--bg-secondary, #162032)',
          border: '1px solid var(--border-primary, #334155)',
          borderRadius: '0.625rem',
          padding: '1rem',
          overflowX: 'auto'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-secondary, #cbd5e1)', marginBottom: '0.75rem' }}>
          <FiSliders size={14} color="#c084fc" />
          Statistical Confusion Matrix (Historical Benchmark Logs)
        </div>

        <table
          className="val-table"
          style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem', textAlign: 'center' }}
        >
          <thead>
            <tr style={{ background: '#161b22' }}>
              <th style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'left', color: '#8b949e' }}>
                Ground Truth \ Predicted
              </th>
              <th style={{ padding: '0.625rem', border: '1px solid #21262d', color: '#34d399' }}>
                Alerted (Positive)
              </th>
              <th style={{ padding: '0.625rem', border: '1px solid #21262d', color: '#8b949e' }}>
                Not Alerted (Negative)
              </th>
              <th style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'right', color: '#8b949e' }}>
                Total
              </th>
            </tr>
          </thead>
          <tbody style={{ fontFamily: 'ui-monospace, monospace' }}>
            <tr>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'left', color: '#fca5a5', fontFamily: 'inherit' }}>
                Malicious (Actual Attack)
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', fontWeight: 700 }}>
                TP: {confusion.tp || 0}
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', background: 'rgba(244, 63, 94, 0.15)', color: '#fb7185', fontWeight: 700 }}>
                FN: {confusion.fn || 0}
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'right', color: '#8b949e' }}>
                {(confusion.tp || 0) + (confusion.fn || 0)}
              </td>
            </tr>
            <tr>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'left', color: '#93c5fd', fontFamily: 'inherit' }}>
                Benign (Normal System)
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', background: 'rgba(244, 63, 94, 0.15)', color: '#fb7185', fontWeight: 700 }}>
                FP: {confusion.fp || 0}
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', fontWeight: 700 }}>
                TN: {confusion.tn || 0}
              </td>
              <td style={{ padding: '0.625rem', border: '1px solid #21262d', textAlign: 'right', color: '#8b949e' }}>
                {(confusion.fp || 0) + (confusion.tn || 0)}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* 4. FP Samples Preview if any */}
      {fp_samples && fp_samples.length > 0 && (
        <div style={{
          background: 'rgba(244, 63, 94, 0.05)',
          border: '1px solid rgba(244, 63, 94, 0.25)',
          borderRadius: '0.625rem',
          padding: '0.875rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', fontWeight: 700, color: '#f87171', marginBottom: '0.5rem' }}>
            <FiAlertTriangle size={14} />
            <span>Sample False Positives Triggered on Benign Logs ({fp_samples.length} items):</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', maxHeight: '160px', overflowY: 'auto' }}>
            {fp_samples.slice(0, 5).map((sample, idx) => (
              <div key={idx} style={{
                background: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '0.375rem',
                padding: '0.375rem 0.625rem',
                fontSize: '0.6875rem',
                fontFamily: 'monospace',
                color: '#f8fafc',
                wordBreak: 'break-all'
              }}>
                <span style={{ color: '#58a6ff', fontWeight: 600 }}>{sample.process}</span>: {sample.cmdline}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. LLM Analysis / Exclusions suggestion (if present) */}
      {llm_explanation && (
        <div style={{
          borderRadius: '0.625rem',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          background: 'rgba(245, 158, 11, 0.05)',
          padding: '1rem',
          fontSize: '0.75rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: '#fbbf24', marginBottom: '0.375rem' }}>
            <FiAlertTriangle size={14} />
            <span>Agent A Tuning Advice for High False Positive Rate:</span>
          </div>
          <div style={{ color: '#e6edf3', lineHeight: 1.6, whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>
            {llm_explanation}
          </div>
        </div>
      )}
    </div>
  );
}
