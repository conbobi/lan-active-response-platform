import React, { useCallback, useEffect, useState, useMemo } from 'react';
import api from '../../api/api';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import OperatorTokenPrompt from '../common/OperatorTokenPrompt';

// One message per backend outcome_code (app/core/response_outcome.py); never a generic "failed".
const OUTCOME_TEXT = {
  AUTHORIZATION_FAILED: 'Không có quyền: cần operator token hợp lệ cho Agent này (thao tác ghi cần vai trò admin).',
  INSUFFICIENT_EVIDENCE: 'Chưa đủ bằng chứng tương quan cho hành động này.',
  POLICY_DENIED: 'Chính sách phản ứng từ chối hành động này với bằng chứng hiện tại.',
  APPROVAL_REQUIRED: 'Hành động cần được phê duyệt trước khi thực thi.',
  AGENT_OFFLINE: 'Agent đã xác thực đang offline; không thể gửi lệnh thu thập.',
  EXECUTOR_UNAVAILABLE: 'Chưa có điểm thực thi (executor) được cấu hình cho hành động này.',
  VALIDATION_ERROR: 'Yêu cầu không hợp lệ.',
  CONFLICT: 'Trạng thái hành động đã thay đổi; tải lại để xem trạng thái mới.',
  NOT_FOUND: 'Không tìm thấy sự cố hoặc hành động trong phạm vi được cấp.',
  INTERNAL_ERROR: 'Lỗi nội bộ của Manager.',
  NETWORK_ERROR: 'Không kết nối được tới Manager.',
};

const describeError = (e) => ({
  outcome: e?.outcome || 'INTERNAL_ERROR',
  message: e?.message || '',
  requestId: e?.requestId,
});

export default function ResponseAssist({ incidentId }) {
  const [data, setData] = useState(null);
  const [auditActionId, setAuditActionId] = useState(null);
  const [auditLogs, setAuditLogs] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [nowStamp, setNowStamp] = useState(Date.now());

  const path = `/incidents/${encodeURIComponent(incidentId)}/response-proposals`;

  const load = useCallback(async (signal) => {
    try {
      const result = await api.get(path, { signal });
      if (!signal?.aborted) {
        setData(result);
        setError('');
      }
    } catch (e) {
      if (!signal?.aborted) setError(describeError(e));
    }
  }, [path]);

  const hasActiveActions = useMemo(() => {
    return data?.actions?.some(a =>
      ['dispatched', 'executing', 'verifying', 'monitoring'].includes(a.status) || a.rollback_available
    );
  }, [data]);

  // Periodic refresh & live clock for TTL
  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);

    const clock = setInterval(() => setNowStamp(Date.now()), 1000);
    const poller = hasActiveActions && setInterval(() => load(controller.signal), 3000);

    return () => {
      clearInterval(clock);
      if (poller) clearInterval(poller);
      controller.abort();
    };
  }, [load, hasActiveActions]);

  async function handleOperation(operation, action = null) {
    if (operation === 'propose') {
      setBusy(true);
      setError('');
      try {
        await api.post(path, action ? { action_type: action.action_type } : {});
        await load();
      } catch (e) {
        setError(describeError(e));
      } finally {
        setBusy(false);
      }
      return;
    }

    if (!action) return;

    if (operation === 'audit') {
      setBusy(true);
      try {
        const endpoint = `/response-actions/${encodeURIComponent(action.action_id)}`;
        const res = await api.get(endpoint);
        setAuditActionId(action.action_id);
        setAuditLogs(res.audit || []);
      } catch (e) {
        setError(describeError(e));
      } finally {
        setBusy(false);
      }
      return;
    }

    // Require confirmation for mutating operations
    const impactMsg = action.potential_impact || action.expected_effect || '';
    const confirmPrompt = `Confirm ${operation.toUpperCase()} for ${action.action_type.replaceAll('_', ' ')}?\n\nImpact: ${impactMsg}`;
    if (!window.confirm(confirmPrompt)) {
      return;
    }

    setBusy(true);
    setError('');
    try {
      const endpoint = `/response-actions/${encodeURIComponent(action.action_id)}/${operation}`;
      await api.post(endpoint, {});
      await load();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const investigation = data?.investigation;
  const policyDecision = data?.policy_decision;

  const getStatusColor = (status) => {
    switch (status) {
      case 'succeeded': return '#10b981';
      case 'failed':
      case 'rollback_failed': return '#ef4444';
      case 'verifying':
      case 'executing':
      case 'dispatched': return '#3b82f6';
      case 'approved': return '#06b6d4';
      case 'pending_approval': return '#f59e0b';
      case 'rolled_back':
      case 'expired': return '#6b7280';
      default: return '#9ca3af';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', color: 'var(--text-primary)' }}>
      {/* 1. Core Principle Banner */}
      <div style={{
        padding: '0.75rem 1rem',
        borderRadius: '8px',
        backgroundColor: 'rgba(59, 130, 246, 0.08)',
        border: '1px solid rgba(59, 130, 246, 0.25)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.5rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <span style={{ fontSize: '1.1rem' }}>🛡️</span>
          <div>
            <span style={{ fontWeight: 700, fontSize: '0.85rem', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Execution Boundary
            </span>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
              AI Proposed ≠ Approved ≠ Executed ≠ Verified
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => handleOperation('propose')}
            title="Refresh evidence investigation"
          >
            {busy ? 'Investigating...' : '🔄 Investigate'}
          </Button>
        </div>
      </div>

      {error?.outcome === 'AUTHORIZATION_FAILED' && (
        <OperatorTokenPrompt reason={error.message} onSaved={() => { setError(''); load(); }} />
      )}

      {error && (
        <div style={{
          padding: '0.65rem 0.9rem',
          borderRadius: '6px',
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          color: '#ef4444',
          fontSize: '0.82rem'
        }}>
          <strong>[{error.outcome}]</strong> {OUTCOME_TEXT[error.outcome] || ''}
          {error.message && <div style={{ marginTop: '0.25rem', opacity: 0.85 }}>Manager: {error.message}</div>}
          {error.requestId && <div style={{ marginTop: '0.15rem', fontSize: '0.72rem', opacity: 0.7 }}>request_id: {error.requestId}</div>}
        </div>
      )}

      {/* 2. Investigation & Evidence Header */}
      {data && !investigation && (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          No correlated HTTP observations found for this incident.
        </div>
      )}

      {investigation && (
        <div style={{
          backgroundColor: 'var(--card-bg, rgba(255, 255, 255, 0.03))',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '1rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.75rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>{investigation.classification}</span>
              <Badge variant={investigation.confidence >= 0.8 ? 'danger' : 'warning'}>
                Rule Confidence: {Math.round(investigation.confidence * 100)}%
              </Badge>
              <Badge variant={investigation.evidence_completeness === 'complete_for_session_grant' ? 'success' : 'default'}>
                Completeness: {investigation.evidence_completeness}
              </Badge>
            </div>
            {policyDecision && (
              <Badge variant={policyDecision === 'REQUIRE_APPROVAL' ? 'warning' : policyDecision === 'ALLOW_AUTOMATIC' ? 'success' : 'danger'}>
                Policy: {policyDecision}
              </Badge>
            )}
          </div>

          <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {investigation.behavioral_interpretation}
          </p>

          {/* Evidence Details Collapsible */}
          <details style={{ marginTop: '0.25rem', fontSize: '0.8rem' }}>
            <summary style={{ cursor: 'pointer', color: 'var(--accent)', fontWeight: 600 }}>
              View Correlated Evidence Facts ({investigation.observed_facts?.length || 0})
            </summary>
            <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {investigation.observed_facts?.map((f, idx) => (
                <div key={idx} style={{
                  padding: '0.5rem 0.75rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.2)',
                  borderRadius: '4px',
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '0.6rem'
                }}>
                  <span style={{ color: '#38bdf8' }}>[{f.provenance}]</span>
                  <span>ID: {f.evidence_ids?.join(', ')}</span>
                  <span>At: {f.observed_at}</span>
                  {f.method && <span>{f.method} {f.http_status ? `(HTTP ${f.http_status})` : ''}</span>}
                  {f.source_ip && <span>Peer: {f.source_ip}</span>}
                  {f.automation_hint && <span style={{ color: '#f59e0b' }}>Tool: {f.automation_hint}</span>}
                  {f.payload_indicators?.length > 0 && <span style={{ color: '#ef4444' }}>Indicators: {f.payload_indicators.join(', ')}</span>}
                  {f.outcome && <span style={{ color: '#10b981' }}>Outcome: {f.outcome}</span>}
                </div>
              ))}
              {investigation.missing_evidence?.length > 0 && (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', fontStyle: 'italic', padding: '0.25rem 0' }}>
                  Missing evidence requirements: {investigation.missing_evidence.join(', ')}
                </div>
              )}
            </div>
          </details>

          {/* Candidate response proposal triggers */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', fontWeight: 600 }}>
              Recommended Candidate Actions:
            </span>
            {investigation.recommended_responses?.map((candidate) => (
              <Button
                key={candidate.action_id}
                size="sm"
                variant="outline"
                disabled={busy}
                onClick={() => handleOperation('propose', candidate)}
              >
                + Propose {candidate.action_type.replaceAll('_', ' ')}
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* 3. Action Lifecycle Cards */}
      {data?.actions?.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <h4 style={{ margin: '0.5rem 0 0 0', fontSize: '0.88rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.05em' }}>
            Active & Historical Response Actions ({data.actions.length})
          </h4>

          {data.actions.map((action) => {
            const snap = action.result || {};
            const verification = snap.verification;
            const target = action.target_resource || {};

            // Calculate remaining TTL
            let remainingSec = null;
            if (snap.deadline && snap.deadline > nowStamp / 1000) {
              remainingSec = Math.max(0, Math.round(snap.deadline - nowStamp / 1000));
            }

            return (
              <div
                key={action.action_id}
                style={{
                  backgroundColor: 'var(--card-bg, rgba(255, 255, 255, 0.02))',
                  border: `1px solid ${action.status === 'succeeded' ? 'rgba(16, 185, 129, 0.3)' : 'var(--border)'}`,
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem'
                }}
              >
                {/* Header row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.92rem' }}>
                        {action.action_type.replaceAll('_', ' ').toUpperCase()}
                      </span>
                      <span style={{
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        backgroundColor: `${getStatusColor(action.status)}20`,
                        color: getStatusColor(action.status),
                        border: `1px solid ${getStatusColor(action.status)}50`
                      }}>
                        {action.status.toUpperCase()}
                      </span>
                      {action.recommendation_source && (
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                          via {action.recommendation_source}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                      {action.expected_effect}
                    </div>
                  </div>

                  {/* TTL countdown badge */}
                  {remainingSec !== null && (
                    <div style={{
                      padding: '0.2rem 0.6rem',
                      borderRadius: '4px',
                      backgroundColor: 'rgba(245, 158, 11, 0.15)',
                      border: '1px solid rgba(245, 158, 11, 0.35)',
                      color: '#f59e0b',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace',
                      fontWeight: 700
                    }}>
                      ⏱️ TTL: {Math.floor(remainingSec / 60)}m {remainingSec % 60}s remaining
                    </div>
                  )}
                </div>

                {/* Target & Provenance Row */}
                <div style={{
                  fontSize: '0.78rem',
                  backgroundColor: 'rgba(0, 0, 0, 0.25)',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '1rem',
                  fontFamily: 'monospace'
                }}>
                  {target.source_ip && <span>Direct Peer: <strong>{target.source_ip}</strong></span>}
                  {target.endpoint && <span>Route: {target.method || 'POST'} {target.endpoint}</span>}
                  {target.session_ref && <span>Session Ref: {target.session_ref.slice(0, 16)}...</span>}
                  {action.rollback_strategy && <span>Rollback: {action.rollback_strategy}</span>}
                </div>

                {/* Verification Result Box */}
                {verification && (
                  <div style={{
                    padding: '0.6rem 0.8rem',
                    borderRadius: '6px',
                    backgroundColor: verification.verification_status === 'succeeded' ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    border: `1px solid ${verification.verification_status === 'succeeded' ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
                    fontSize: '0.78rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.3rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, color: verification.verification_status === 'succeeded' ? '#10b981' : '#ef4444' }}>
                        Verification Outcome: {verification.verification_status}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                        Method: {verification.verification_method || verification.method}
                      </span>
                    </div>
                    {verification.expected_result && (
                      <div style={{ color: 'var(--text-secondary)' }}>
                        Expected: {verification.expected_result}
                      </div>
                    )}
                    {verification.actual_result && (
                      <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                        Observed: {verification.actual_result}
                      </div>
                    )}
                    {verification.evidence_refs?.length > 0 && (
                      <div style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: 'var(--text-tertiary)' }}>
                        Evidence Receipts: {verification.evidence_refs.join(', ')}
                      </div>
                    )}
                    {verification.failure_reason && (
                      <div style={{ color: '#ef4444', fontSize: '0.75rem' }}>
                        Failure Cause: {verification.failure_reason}
                      </div>
                    )}
                  </div>
                )}

                {/* Related telemetry records (for collect_additional_evidence) */}
                {snap.related_records && (
                  <details style={{ fontSize: '0.78rem' }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--accent)' }}>
                      Collected Network & Telemetry Records
                    </summary>
                    <pre style={{
                      backgroundColor: 'rgba(0,0,0,0.4)',
                      padding: '0.5rem',
                      borderRadius: '4px',
                      overflowX: 'auto',
                      maxHeight: '180px',
                      fontSize: '0.72rem'
                    }}>
                      {JSON.stringify(snap.related_records, null, 2)}
                    </pre>
                  </details>
                )}

                {/* Operations Action Bar */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                  {action.status === 'pending_approval' && (
                    <>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={busy}
                        onClick={() => handleOperation('approve', action)}
                      >
                        ✓ Approve
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={busy}
                        onClick={() => handleOperation('reject', action)}
                      >
                        ✕ Reject
                      </Button>
                    </>
                  )}

                  {action.status === 'approved' && (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={busy}
                      onClick={() => handleOperation('execute', action)}
                    >
                      ⚡ Execute Action
                    </Button>
                  )}

                  {action.rollback_available && (
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={busy}
                      onClick={() => handleOperation('rollback', action)}
                    >
                      ↺ Rollback / Undo
                    </Button>
                  )}

                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => handleOperation('audit', action)}
                  >
                    📜 View Audit Trail
                  </Button>
                </div>

                {/* Audit trail modal/section for this specific action */}
                {auditActionId === action.action_id && auditLogs && (
                  <div style={{
                    marginTop: '0.5rem',
                    padding: '0.75rem',
                    backgroundColor: 'rgba(0, 0, 0, 0.35)',
                    borderRadius: '6px',
                    border: '1px solid var(--border)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.78rem' }}>Audit Trail History</span>
                      <Button size="xs" variant="outline" onClick={() => { setAuditActionId(null); setAuditLogs(null); }}>
                        Close
                      </Button>
                    </div>
                    <ol style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                      {auditLogs.map((log, idx) => (
                        <li key={idx} style={{ marginBottom: '0.25rem' }}>
                          <span style={{ color: 'var(--text-tertiary)' }}>{log.at}</span> ·{' '}
                          <strong style={{ color: '#38bdf8' }}>{log.actor}</strong> →{' '}
                          <span style={{ color: getStatusColor(log.event) }}>{log.event}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
