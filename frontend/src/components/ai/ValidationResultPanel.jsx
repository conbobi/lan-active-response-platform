import React from 'react';
import { FiCheckCircle, FiAlertTriangle, FiXCircle, FiSliders } from 'react-icons/fi';

export default function ValidationResultPanel({ result }) {
  if (!result) {
    return (
      <div className="rounded-xl border border-gray-800 bg-[#131722] p-6 text-center text-gray-500 text-sm">
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
    llm_explanation
  } = result;

  const isPassed = passed || verdict === 'PASSED';

  // FPR color helper
  const getFprColor = (val) => {
    if (val < 0.05) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (val <= 0.10) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
  };

  // Precision color helper
  const getPrecisionColor = (val) => {
    if (val >= 0.95) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    if (val >= 0.90) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
  };

  return (
    <div className="space-y-6">
      {/* 1. Verdict Banner */}
      <div
        className={`flex items-start gap-3 rounded-xl border p-4 ${
          isPassed
            ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
            : 'border-rose-500/30 bg-rose-500/10 text-rose-200'
        }`}
      >
        <div className="mt-0.5">
          {isPassed ? (
            <FiCheckCircle className="text-emerald-400 text-xl" />
          ) : (
            <FiXCircle className="text-rose-400 text-xl" />
          )}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-sm tracking-wide">
              AGENT B VERDICT: {verdict || (isPassed ? 'PASSED' : 'FAILED')}
            </span>
            <span
              className={`text-[11px] font-mono px-2 py-0.5 rounded-full font-semibold ${
                isPassed ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
              }`}
            >
              FPR Target &le; {(thresholds.fpr * 100).toFixed(1)}% | Precision &ge;{' '}
              {(thresholds.precision * 100).toFixed(1)}%
            </span>
          </div>
          <p className="mt-1 text-xs text-gray-300 leading-relaxed">{reason}</p>
        </div>
      </div>

      {/* 2. Key Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className={`rounded-xl border p-3.5 ${getFprColor(fpr)}`}>
          <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
            False Positive Rate (FPR)
          </div>
          <div className="mt-1.5 text-2xl font-black font-mono">
            {(fpr * 100).toFixed(2)}%
          </div>
          <div className="mt-1 text-[11px] text-gray-400">
            Threshold: &le; {(thresholds.fpr * 100).toFixed(1)}%
          </div>
        </div>

        <div className={`rounded-xl border p-3.5 ${getPrecisionColor(precision)}`}>
          <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
            Precision
          </div>
          <div className="mt-1.5 text-2xl font-black font-mono">
            {(precision * 100).toFixed(2)}%
          </div>
          <div className="mt-1 text-[11px] text-gray-400">
            Threshold: &ge; {(thresholds.precision * 100).toFixed(1)}%
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-[#131722] p-3.5 text-blue-400">
          <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
            Recall (Sensitivity)
          </div>
          <div className="mt-1.5 text-2xl font-black font-mono text-white">
            {(recall * 100).toFixed(2)}%
          </div>
          <div className="mt-1 text-[11px] text-gray-400">
            Coverage of known attacks
          </div>
        </div>

        <div className="rounded-xl border border-gray-800 bg-[#131722] p-3.5 text-purple-400">
          <div className="text-[11px] font-medium uppercase tracking-wider text-gray-400">
            F1 Score
          </div>
          <div className="mt-1.5 text-2xl font-black font-mono text-white">
            {(f1 * 100).toFixed(2)}%
          </div>
          <div className="mt-1 text-[11px] text-gray-400">
            Harmonic balance
          </div>
        </div>
      </div>

      {/* 3. Confusion Matrix 2x2 */}
      <div className="rounded-xl border border-gray-800 bg-[#131722] p-4">
        <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-3 flex items-center gap-2">
          <FiSliders size={14} className="text-purple-400" />
          Statistical Confusion Matrix (Historical Benchmark Logs)
        </h4>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-center border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="p-2 text-left">Ground Truth \ Predicted</th>
                <th className="p-2 text-emerald-400">Alerted (Positive)</th>
                <th className="p-2 text-gray-400">Not Alerted (Negative)</th>
                <th className="p-2 text-right">Total</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 font-mono">
              <tr>
                <td className="p-2.5 text-left font-sans font-medium text-rose-300">
                  Malicious (Actual Attack)
                </td>
                <td className="p-2.5 bg-emerald-500/10 text-emerald-400 font-bold">
                  TP: {confusion.tp || 0}
                </td>
                <td className="p-2.5 bg-rose-500/10 text-rose-400 font-bold">
                  FN: {confusion.fn || 0}
                </td>
                <td className="p-2.5 text-right text-gray-400">
                  {(confusion.tp || 0) + (confusion.fn || 0)}
                </td>
              </tr>
              <tr>
                <td className="p-2.5 text-left font-sans font-medium text-blue-300">
                  Benign (Normal System)
                </td>
                <td className="p-2.5 bg-rose-500/10 text-rose-400 font-bold">
                  FP: {confusion.fp || 0}
                </td>
                <td className="p-2.5 bg-emerald-500/10 text-emerald-400 font-bold">
                  TN: {confusion.tn || 0}
                </td>
                <td className="p-2.5 text-right text-gray-400">
                  {(confusion.fp || 0) + (confusion.tn || 0)}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. LLM Analysis / Exclusions suggestion (if present) */}
      {llm_explanation && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs">
          <div className="flex items-center gap-2 font-bold text-amber-400 mb-1.5">
            <FiAlertTriangle size={15} />
            <span>Agent A Detection Advice for High False Positive Rate:</span>
          </div>
          <div className="text-gray-300 leading-relaxed whitespace-pre-wrap font-sans">
            {llm_explanation}
          </div>
        </div>
      )}
    </div>
  );
}

