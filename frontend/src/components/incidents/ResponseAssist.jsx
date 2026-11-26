import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import toast from 'react-hot-toast';
import { FiCopy, FiInfo, FiShield } from 'react-icons/fi';
import api from '../../api/api';
import { readSession, requestSignIn, subscribeSession } from '../../api/operatorSession';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import EvidenceExplorer from './EvidenceExplorer';
import {
  ACTION_CATEGORY_COLORS,
  ACTION_STATUS_META,
  AUDIT_EVENT_LABELS,
  COMPLETENESS_LABELS,
  POLICY_DECISION_LABELS,
  PROPOSAL_ORIGIN_LABELS,
  VERIFICATION_METHOD_LABELS,
  formatDateTimeUTC,
  formatDateTimeVN,
  formatDurationVN,
  getActionMeta,
  shortenId,
  translateActor,
  translateClassification,
  translateMissingEvidence,
} from '../../i18n/viVN';

const OUTCOME_TEXT = {
  SIGN_IN_REQUIRED: 'Cần đăng nhập tài khoản SOC để tiếp tục.',
  SESSION_EXPIRED: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.',
  INSUFFICIENT_PRIVILEGES: 'Tài khoản hiện tại không đủ quyền thực hiện thao tác trên Agent này.',
  AUTHORIZATION_FAILED: 'Không có quyền: cần tài khoản operator/admin hợp lệ cho Agent này.',
  INSUFFICIENT_EVIDENCE: 'Chưa đủ bằng chứng tương quan cho hành động này.',
  POLICY_DENIED: 'Chính sách phản ứng từ chối hành động này với bằng chứng hiện tại.',
  APPROVAL_REQUIRED: 'Hành động cần được phê duyệt trước khi thực thi.',
  AGENT_OFFLINE: 'Agent đã xác thực đang offline; không thể gửi lệnh thu thập.',
  EXECUTOR_UNAVAILABLE: 'Chưa có điểm thực thi (executor) được cấu hình cho hành động này.',
  VALIDATION_ERROR: 'Yêu cầu không hợp lệ.',
  CONFLICT: 'Trạng thái hành động đã thay đổi; đang tải lại trạng thái mới.',
  NOT_FOUND: 'Không tìm thấy sự cố hoặc hành động trong phạm vi được cấp.',
  INTERNAL_ERROR: 'Lỗi nội bộ của Manager.',
  NETWORK_ERROR: 'Không kết nối được tới Manager.',
};

const describeError = (e) => ({
  outcome:
    e?.status === 403
      ? 'INSUFFICIENT_PRIVILEGES'
      : e?.status === 401 && e?.outcome !== 'SESSION_EXPIRED'
      ? 'SIGN_IN_REQUIRED'
      : e?.outcome || 'INTERNAL_ERROR',
  message: e?.message || '',
  requestId: e?.requestId,
});

export default function ResponseAssist({ incidentId, incident = null }) {
  const session = useSyncExternalStore(subscribeSession, readSession);
  return <ProposalList key={`${incidentId}/${Boolean(session)}`} incidentId={incidentId} incident={incident} />;
}

function CopyChip({ value, label }) {
  if (!value) return null;
  const copy = () => {
    navigator.clipboard?.writeText(String(value)).then(() => toast.success(`Đã sao chép ${label}`));
  };
  return (
    <span
      title={String(value)}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.3rem',
        padding: '0.15rem 0.45rem',
        borderRadius: '4px',
        background: 'rgba(255,255,255,0.05)',
        border: '1px solid var(--border)',
        fontFamily: 'monospace',
        fontSize: '0.73rem',
      }}
    >
      <span>{shortenId(value)}</span>
      <button
        type="button"
        onClick={copy}
        aria-label={`Sao chép ${label}`}
        style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', padding: 0, display: 'inline-flex' }}
      >
        <FiCopy size={11} />
      </button>
    </span>
  );
}

function ProposalList({ incidentId, incident }) {
  const [data, setData] = useState(null);
  const [auditByAction, setAuditByAction] = useState({});
  const [openAuditId, setOpenAuditId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [nowStamp, setNowStamp] = useState(Date.now);

  const sequence = useRef(0);
  const path = `/incidents/${encodeURIComponent(incidentId)}/response-proposals`;

  const load = useCallback(
    (signal) => {
      const version = ++sequence.current;
      return api
        .get(path, { signal })
        .then((result) => {
          if (signal?.aborted || version !== sequence.current) return;
          setData(result);
          setError('');
        })
        .catch((err) => {
          if (signal?.aborted || version !== sequence.current) return;
          setData(null);
          setError(describeError(err));
        });
    },
    [path]
  );

  const hasActiveActions = useMemo(
    () =>
      data?.actions?.some(
        (a) => ['dispatched', 'executing', 'verifying', 'monitoring'].includes(a.status) || a.rollback_available
      ),
    [data]
  );

  const hasData = Boolean(data);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    if (!hasData) return undefined;
    const controller = new AbortController();
    const clock = setInterval(() => setNowStamp(Date.now()), 1000);
    const poller = setInterval(() => load(controller.signal), hasActiveActions ? 3000 : 10000);
    return () => {
      clearInterval(clock);
      clearInterval(poller);
      controller.abort();
    };
  }, [load, hasData, hasActiveActions]);

  // Preload audit metadata for visible actions so Who/When explanation fields are complete.
  useEffect(() => {
    const actions = data?.actions || [];
    if (!actions.length) return;
    let cancelled = false;
    const targets = actions.slice(0, 5).filter((a) => !auditByAction[a.action_id]);
    if (!targets.length) return;
    Promise.allSettled(
      targets.map((a) => api.get(`/response-actions/${encodeURIComponent(a.action_id)}`))
    ).then((results) => {
      if (cancelled) return;
      const next = {};
      results.forEach((res, idx) => {
        if (res.status === 'fulfilled' && Array.isArray(res.value?.audit)) {
          next[targets[idx].action_id] = res.value.audit;
        }
      });
      if (Object.keys(next).length) {
        setAuditByAction((prev) => ({ ...prev, ...next }));
      }
    });
    return () => {
      cancelled = true;
    };
  }, [data?.actions]);

  function showSaved(saved) {
    sequence.current++;
    setData(
      (previous) =>
        previous && {
          ...previous,
          actions: [saved, ...previous.actions.filter((item) => item.action_id !== saved.action_id)],
        }
    );
  }

  async function handleOperation(operation, action = null) {
    if (operation === 'propose') {
      setBusy(true);
      setError('');
      try {
        showSaved(await api.post(path, action ? { action_type: action.action_type } : {}));
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
      if (openAuditId === action.action_id) {
        setOpenAuditId(null);
        return;
      }
      setBusy(true);
      try {
        const res = await api.get(`/response-actions/${encodeURIComponent(action.action_id)}`);
        setAuditByAction((prev) => ({ ...prev, [action.action_id]: res.audit || [] }));
        setOpenAuditId(action.action_id);
      } catch (e) {
        setError(describeError(e));
      } finally {
        setBusy(false);
      }
      return;
    }

    const meta = getActionMeta(action.action_type);
    const impactMsg = action.potential_impact || action.expected_effect || '';
    const opLabels = { approve: 'PHÊ DUYỆT', reject: 'TỪ CHỐI', execute: 'THỰC THI', rollback: 'HOÀN TÁC' };
    const confirmPrompt = `Xác nhận ${opLabels[operation] || operation.toUpperCase()} hành động "${meta.title}"?\n\nTác động dự kiến: ${impactMsg}`;
    if (!window.confirm(confirmPrompt)) return;

    setBusy(true);
    setError('');
    try {
      const endpoint = `/response-actions/${encodeURIComponent(action.action_id)}/${operation}`;
      showSaved(await api.post(endpoint, {}));
      const refreshedDetail = await api.get(`/response-actions/${encodeURIComponent(action.action_id)}`).catch(() => null);
      if (refreshedDetail?.audit) {
        setAuditByAction((prev) => ({ ...prev, [action.action_id]: refreshedDetail.audit }));
      }
      await load();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }

  const investigation = data?.investigation;
  const policyDecision = data?.policy_decision;

  // Phase 6: Derived Summary separating investigation from active prevention/containment.
  const derivedSummary = useMemo(() => {
    const actions = data?.actions || [];
    const summary = {
      investigationCompleted: 0,
      preventionActive: 0,
      containmentActive: 0,
      awaitingApproval: 0,
      failedCount: 0,
      rolledBackCount: 0,
    };
    for (const a of actions) {
      const meta = getActionMeta(a.action_type);
      if (a.status === 'pending_approval') summary.awaitingApproval++;
      if (['failed', 'partial', 'rollback_failed'].includes(a.status)) summary.failedCount++;
      if (['rolled_back', 'expired'].includes(a.status)) summary.rolledBackCount++;
      if (!meta.isMitigation && ['succeeded', 'monitoring'].includes(a.status) && a.action_type !== 'unisolate') {
        summary.investigationCompleted++;
      }
      if (meta.category === 'prevention' && ['verifying', 'succeeded'].includes(a.status)) {
        summary.preventionActive++;
      }
      if (meta.category === 'containment' && ['verifying', 'succeeded', 'applied'].includes(a.status)) {
        summary.containmentActive++;
      }
    }
    return summary;
  }, [data?.actions]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', color: 'var(--text-primary)' }}>
      {/* Header Banner */}
      <div
        style={{
          padding: '0.85rem 1rem',
          borderRadius: '8px',
          backgroundColor: 'rgba(59, 130, 246, 0.08)',
          border: '1px solid rgba(59, 130, 246, 0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.6rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <FiShield size={20} color="#38bdf8" />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>
              Trợ lý ứng phó AI · Ranh giới kiểm soát thực thi
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Đề xuất ≠ Phê duyệt ≠ Đã thực thi ≠ Đã xác minh hiệu lực
            </div>
          </div>
        </div>
        <Button
          size="sm"
          variant="outline"
          disabled={busy}
          onClick={() => handleOperation('propose')}
          title="Đánh giá lại bằng chứng và tạo đề xuất phù hợp"
        >
          {busy ? 'Đang xử lý…' : 'Tạo đề xuất từ bằng chứng'}
        </Button>
      </div>

      {/* Sign-in / Structured Error Banner */}
      {['SIGN_IN_REQUIRED', 'SESSION_EXPIRED'].includes(error?.outcome) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 1rem', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.35)' }}>
          <span style={{ fontSize: '0.84rem', color: '#fbbf24' }}>{OUTCOME_TEXT[error.outcome]}</span>
          <Button size="sm" variant="primary" onClick={() => requestSignIn(OUTCOME_TEXT[error.outcome])}>
            Đăng nhập
          </Button>
        </div>
      )}

      {error && (
        <div
          style={{
            padding: '0.65rem 0.9rem',
            borderRadius: '6px',
            backgroundColor: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#ef4444',
            fontSize: '0.82rem',
          }}
        >
          <strong>[{error.outcome}]</strong> {OUTCOME_TEXT[error.outcome] || ''}
          {error.message && <div style={{ marginTop: '0.2rem', opacity: 0.9 }}>Chi tiết từ Manager: {error.message}</div>}
          {error.requestId && <div style={{ marginTop: '0.15rem', fontSize: '0.72rem', opacity: 0.7 }}>Mã yêu cầu: {error.requestId}</div>}
        </div>
      )}

      {/* Phase 6: Derived Summary Bar */}
      {data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))', gap: '0.55rem' }}>
          <SummaryPill label="Điều tra hoàn tất" value={derivedSummary.investigationCompleted} color="#38bdf8" />
          <SummaryPill label="Ngăn chặn hiệu lực" value={derivedSummary.preventionActive} color="#f59e0b" />
          <SummaryPill label="Cô lập / Kiểm soát" value={derivedSummary.containmentActive} color="#ef4444" />
          <SummaryPill label="Chờ phê duyệt" value={derivedSummary.awaitingApproval} color="#eab308" />
          <SummaryPill label="Thất bại / Một phần" value={derivedSummary.failedCount} color="#ef4444" />
          <SummaryPill label="Hoàn tác / Hết TTL" value={derivedSummary.rolledBackCount} color="#9ca3af" />
        </div>
      )}

      {/* Phase 6: Mandatory distinction banner when only investigation succeeded */}
      {derivedSummary.investigationCompleted > 0 &&
        derivedSummary.preventionActive === 0 &&
        derivedSummary.containmentActive === 0 && (
          <div
            style={{
              padding: '0.7rem 0.95rem',
              borderRadius: '8px',
              background: 'rgba(56, 189, 248, 0.1)',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              fontSize: '0.83rem',
              color: 'var(--text-primary)',
            }}
          >
            <FiInfo size={16} color="#38bdf8" style={{ flexShrink: 0 }} />
            <span>
              <strong>Đã thu thập bằng chứng thành công</strong> — Hành động này chỉ thu thập và xác minh telemetry phục vụ điều tra,{' '}
              <strong>chưa thực hiện hoặc chứng minh đã chặn cuộc tấn công</strong>.
            </span>
          </div>
        )}

      {/* Investigation Context Card */}
      {data && !investigation && (
        <div style={{ padding: '1.25rem', textAlign: 'center', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', borderRadius: '8px', border: '1px solid var(--border)' }}>
          Chưa có quan sát HTTP/xác thực tương quan cho sự cố này.
        </div>
      )}

      {investigation && (
        <div
          style={{
            backgroundColor: 'var(--card-bg, rgba(255, 255, 255, 0.03))',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '1rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>
                {translateClassification(investigation.classification)}
              </span>
              <Badge variant={investigation.confidence >= 0.8 ? 'danger' : 'warning'}>
                Độ tin cậy luật: {Math.round(investigation.confidence * 100)}%
              </Badge>
              <Badge variant={investigation.evidence_completeness === 'complete_for_session_grant' ? 'success' : 'default'}>
                {COMPLETENESS_LABELS[investigation.evidence_completeness] || investigation.evidence_completeness}
              </Badge>
            </div>
            {policyDecision && (
              <Badge variant={policyDecision === 'REQUIRE_APPROVAL' ? 'warning' : policyDecision === 'ALLOW_AUTOMATIC' ? 'success' : 'danger'}>
                Chính sách: {POLICY_DECISION_LABELS[policyDecision] || policyDecision}
              </Badge>
            )}
          </div>

          <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            {investigation.behavioral_interpretation}
          </p>

          {investigation.missing_evidence?.length > 0 && (
            <div style={{ fontSize: '0.78rem', color: '#fbbf24', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: '6px', padding: '0.5rem 0.75rem' }}>
              <strong>Bằng chứng còn thiếu:</strong>{' '}
              {investigation.missing_evidence.map((item) => translateMissingEvidence(item)).join(' · ')}
            </div>
          )}

          {/* Candidate response triggers */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', fontWeight: 600 }}>
              Hành động có thể đề xuất từ bằng chứng hiện tại:
            </span>
            {investigation.recommended_responses?.map((candidate) => {
              const meta = getActionMeta(candidate.action_type);
              return (
                <Button
                  key={candidate.action_id}
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => handleOperation('propose', candidate)}
                >
                  + Đề xuất: {meta.title} ({meta.categoryLabel})
                </Button>
              );
            })}
          </div>
        </div>
      )}

      {/* Phase 5: Action Explanation Cards */}
      {data?.actions?.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <h4 style={{ margin: '0.25rem 0 0 0', fontSize: '0.86rem', textTransform: 'uppercase', color: 'var(--text-tertiary)', letterSpacing: '0.04em' }}>
            Các hành động ứng phó & xác minh ({data.actions.length})
          </h4>

          {data.actions.map((action) => {
            const snap = action.result || {};
            const verification = snap.verification;
            const meta = getActionMeta(action.action_type);
            const catColors = ACTION_CATEGORY_COLORS[meta.category] || ACTION_CATEGORY_COLORS.investigation;
            const statusMeta = ACTION_STATUS_META[action.status] || {
              label: action.status,
              code: action.status.toUpperCase(),
              color: '#9ca3af',
            };
            const audit = auditByAction[action.action_id] || [];

            const executeReason = !data.can_execute
              ? 'Thiếu quyền thực thi.'
              : action.status !== 'approved'
              ? 'Đang chờ phê duyệt.'
              : !investigation?.recommended_responses?.some((item) => item.action_id === action.action_id)
              ? 'Bằng chứng hiện tại chưa đủ.'
              : action.action_type === 'collect_additional_evidence' && !data.agent_online
              ? 'Agent đang offline.'
              : '';
            const target = action.target_resource || {};

            let remainingSec = null;
            if (snap.deadline && snap.deadline > nowStamp / 1000) {
              remainingSec = Math.max(0, Math.round(snap.deadline - nowStamp / 1000));
            }

            const proposedAudit = audit.find((e) => e.event === 'proposed');
            const approvedAudit = audit.find((e) => e.event === 'approved');
            const dispatchedAudit = audit.find((e) => e.event === 'dispatched');
            const executedAudit = audit.find((e) => e.event === 'executed');
            const verifiedAudit = audit.find((e) => ['succeeded', 'partial', 'failed'].includes(e.event));

            const isExecuted = ['dispatched', 'executing', 'verifying', 'monitoring', 'succeeded', 'partial', 'failed', 'rolled_back', 'rollback_failed', 'expired'].includes(action.status);
            const isVerifiedSuccess = action.status === 'succeeded' && verification?.verification_status === 'succeeded';

            const resultTitle = isVerifiedSuccess
              ? meta.successHeadline
              : action.status === 'monitoring'
              ? meta.successHeadline
              : action.status === 'failed'
              ? 'Thực thi hoặc xác minh thất bại'
              : action.status === 'rolled_back'
              ? 'Đã hoàn tác tác động'
              : action.status === 'expired'
              ? 'Hành động đã hết thời hạn hiệu lực (TTL)'
              : 'Chưa xác minh hiệu lực cuối cùng';

            const resultDescription = isVerifiedSuccess
              ? meta.successExplanation
              : verification?.actual_result ||
                (action.status === 'pending_approval'
                  ? 'Đề xuất đang chờ quản trị viên hoặc operator có quyền Agent phê duyệt.'
                  : action.status === 'approved'
                  ? 'Đã được phê duyệt nhưng chưa gửi lệnh thực thi.'
                  : 'Đang theo dõi trạng thái xử lý từ điểm thực thi.');

            return (
              <div
                key={action.action_id}
                style={{
                  backgroundColor: 'var(--card-bg, rgba(255, 255, 255, 0.02))',
                  border: `1px solid ${isVerifiedSuccess ? 'rgba(16, 185, 129, 0.35)' : 'var(--border)'}`,
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
              >
                {/* Top Header: What + Category + Status + TTL */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>{meta.title}</strong>
                      <span
                        style={{
                          padding: '0.15rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          color: catColors.color,
                          backgroundColor: catColors.bg,
                          border: `1px solid ${catColors.border}`,
                        }}
                      >
                        {meta.categoryLabel}
                      </span>
                      <span
                        style={{
                          padding: '0.15rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          color: statusMeta.color,
                          backgroundColor: `${statusMeta.color}20`,
                          border: `1px solid ${statusMeta.color}50`,
                        }}
                      >
                        {statusMeta.label} ({statusMeta.code})
                      </span>
                    </div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                      action_type: {action.action_type} · id: {shortenId(action.action_id)}
                    </div>
                  </div>

                  {remainingSec !== null && (
                    <div
                      style={{
                        padding: '0.25rem 0.6rem',
                        borderRadius: '4px',
                        backgroundColor: 'rgba(245, 158, 11, 0.15)',
                        border: '1px solid rgba(245, 158, 11, 0.35)',
                        color: '#f59e0b',
                        fontSize: '0.75rem',
                        fontWeight: 700,
                      }}
                    >
                      ⏱️ Còn hiệu lực: {formatDurationVN(remainingSec)}
                    </div>
                  )}
                </div>

                {/* Lifecycle Stepper: PROPOSED -> APPROVED -> EXECUTED -> VERIFIED */}
                <LifecycleStepper
                  proposed={true}
                  approved={['approved', 'dispatched', 'executing', 'verifying', 'monitoring', 'succeeded', 'partial', 'rolled_back', 'expired'].includes(action.status)}
                  executed={isExecuted}
                  verified={isVerifiedSuccess}
                  failed={['failed', 'rollback_failed', 'rejected', 'not_recommended'].includes(action.status)}
                />

                {/* Why / Who / Target Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '0.65rem' }}>
                  {/* Why */}
                  <ExplainBlock title="Vì sao hệ thống đề xuất?">
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', lineHeight: 1.5 }}>
                      {action.rationale} {action.expected_effect}
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)', marginTop: '0.3rem' }}>
                      Nguồn đề xuất: {PROPOSAL_ORIGIN_LABELS[action.recommendation_source] || action.recommendation_source || 'Chính sách bằng chứng'}
                    </div>
                  </ExplainBlock>

                  {/* Who */}
                  <ExplainBlock title="Ai chịu trách nhiệm?">
                    <ul style={{ margin: 0, paddingLeft: '1rem', fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <li>
                        <strong>Đề xuất:</strong>{' '}
                        {action.recommendation_source === 'evidence_policy'
                          ? 'Response Policy Engine'
                          : action.recommendation_source === 'ollama'
                          ? 'AI (kiểm định bởi Policy)'
                          : translateActor(proposedAudit?.actor || 'policy')}
                      </li>
                      <li>
                        <strong>Phê duyệt:</strong>{' '}
                        {approvedAudit ? approvedAudit.actor : action.requires_approval ? 'Đang chờ phê duyệt' : 'Tự động theo chính sách'}
                      </li>
                      <li>
                        <strong>Thực thi:</strong> {meta.executorLabel}
                      </li>
                      <li>
                        <strong>Xác minh:</strong> LARP Manager
                      </li>
                    </ul>
                  </ExplainBlock>

                  {/* Target */}
                  <ExplainBlock title="Mục tiêu & Lớp thực thi">
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                      <div><strong>Agent:</strong> <code>{action.target_agent_id}</code></div>
                      <div><strong>Lớp thực thi:</strong> {meta.enforcementLayer}</div>
                      {target.source_ip && <div><strong>IP nguồn trực tiếp:</strong> <code>{target.source_ip}</code></div>}
                      {target.endpoint && <div><strong>Route HTTP:</strong> <code>{target.method || 'POST'} {target.endpoint}</code></div>}
                      {target.session_ref && <div><strong>Phiên cookie:</strong> <code>{shortenId(target.session_ref)}</code></div>}
                      <div><strong>Có thể hoàn tác:</strong> {action.rollback_available ? 'Có' : 'Không'}</div>
                    </div>
                  </ExplainBlock>
                </div>

                {/* When: Real timestamps in Asia/Ho_Chi_Minh */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem', fontSize: '0.74rem', color: 'var(--text-tertiary)', background: 'rgba(0,0,0,0.2)', padding: '0.45rem 0.7rem', borderRadius: '6px' }}>
                  {proposedAudit && <span title={formatDateTimeUTC(proposedAudit.at)}><strong>Đề xuất:</strong> {formatDateTimeVN(proposedAudit.at)}</span>}
                  {approvedAudit && <span title={formatDateTimeUTC(approvedAudit.at)}><strong>Phê duyệt:</strong> {formatDateTimeVN(approvedAudit.at)}</span>}
                  {dispatchedAudit && <span title={formatDateTimeUTC(dispatchedAudit.at)}><strong>Phát lệnh:</strong> {formatDateTimeVN(dispatchedAudit.at)}</span>}
                  {executedAudit && <span title={formatDateTimeUTC(executedAudit.at)}><strong>Thực thi:</strong> {formatDateTimeVN(executedAudit.at)}</span>}
                  {(verifiedAudit || verification?.observed_at) && (
                    <span title={formatDateTimeUTC(verifiedAudit?.at || verification?.observed_at)}>
                      <strong>Xác minh:</strong> {formatDateTimeVN(verifiedAudit?.at || verification?.observed_at)}
                    </span>
                  )}
                  {!proposedAudit && action.proposal_created_at && (
                    <span title={formatDateTimeUTC(action.proposal_created_at)}>
                      <strong>Tạo đề xuất:</strong> {formatDateTimeVN(action.proposal_created_at)}
                    </span>
                  )}
                </div>

                {/* Result & Verification Evidence */}
                <div
                  style={{
                    padding: '0.75rem 0.9rem',
                    borderRadius: '6px',
                    backgroundColor: isVerifiedSuccess
                      ? 'rgba(16, 185, 129, 0.08)'
                      : action.status === 'failed'
                      ? 'rgba(239, 68, 68, 0.08)'
                      : 'rgba(59, 130, 246, 0.06)',
                    border: `1px solid ${
                      isVerifiedSuccess
                        ? 'rgba(16, 185, 129, 0.3)'
                        : action.status === 'failed'
                        ? 'rgba(239, 68, 68, 0.3)'
                        : 'rgba(59, 130, 246, 0.25)'
                    }`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.4rem',
                    fontSize: '0.8rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                    <strong style={{ color: isVerifiedSuccess ? '#10b981' : action.status === 'failed' ? '#ef4444' : 'var(--text-primary)' }}>
                      {resultTitle}
                    </strong>
                    {verification?.verification_method && (
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                        Phương pháp: {VERIFICATION_METHOD_LABELS[verification.verification_method] || verification.verification_method}
                      </span>
                    )}
                  </div>
                  <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5 }}>{resultDescription}</div>

                  {/* IDs with Copy chips */}
                  {(snap.command_id || verification?.evidence_refs?.length > 0) && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem', alignItems: 'center', marginTop: '0.2rem' }}>
                      {snap.command_id && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                          <span>Mã lệnh:</span>
                          <CopyChip value={snap.command_id} label="Command ID" />
                        </span>
                      )}
                      {verification?.evidence_refs?.length > 0 && (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                          <span>Phiếu xác nhận bằng chứng:</span>
                          {verification.evidence_refs.map((ref) => (
                            <CopyChip key={ref} value={ref} label="Phiếu bằng chứng" />
                          ))}
                        </span>
                      )}
                    </div>
                  )}

                  {verification?.failure_reason && (
                    <div style={{ color: '#ef4444', fontSize: '0.76rem' }}>
                      <strong>Lý do thất bại:</strong> {verification.failure_reason}
                    </div>
                  )}
                </div>

                {/* Phase 7: Structured Evidence Explorer instead of raw JSON */}
                {snap.related_records && (
                  <EvidenceExplorer
                    relatedRecords={snap.related_records}
                    observedFacts={investigation?.observed_facts || []}
                    behavior={incident?.detection_evidence?.behavior || null}
                    snapshotTimestamp={verification?.observed_at}
                    agentId={action.target_agent_id}
                  />
                )}

                {/* Operations Action Bar */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {action.status === 'pending_approval' && (
                    <>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={busy || !data.can_execute}
                        onClick={() => handleOperation('approve', action)}
                      >
                        ✓ Phê duyệt
                      </Button>
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={busy || !data.can_execute}
                        onClick={() => handleOperation('reject', action)}
                      >
                        ✕ Từ chối
                      </Button>
                    </>
                  )}

                  {['approved', 'pending_approval'].includes(action.status) && (
                    <Button
                      size="sm"
                      variant="primary"
                      disabled={busy || !!executeReason}
                      onClick={() => handleOperation('execute', action)}
                    >
                      ⚡ Thực thi hành động{executeReason ? ` · ${executeReason}` : ''}
                    </Button>
                  )}

                  {action.rollback_available && (
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={busy || !data.can_execute}
                      onClick={() => handleOperation('rollback', action)}
                    >
                      ↺ Hoàn tác
                    </Button>
                  )}

                  <Button size="sm" variant="outline" disabled={busy} onClick={() => handleOperation('audit', action)}>
                    📜 {openAuditId === action.action_id ? 'Ẩn nhật ký kiểm toán' : 'Xem nhật ký kiểm toán'}
                  </Button>
                </div>

                {/* Audit Trail */}
                {openAuditId === action.action_id && (
                  <div
                    style={{
                      padding: '0.75rem',
                      backgroundColor: 'rgba(0, 0, 0, 0.35)',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem' }}>
                      <strong style={{ fontSize: '0.78rem' }}>Nhật ký kiểm toán (Audit Trail)</strong>
                    </div>
                    <ol style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.76rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                      {audit.map((log, idx) => (
                        <li key={idx}>
                          <span style={{ color: 'var(--text-tertiary)' }} title={formatDateTimeUTC(log.at)}>
                            {formatDateTimeVN(log.at)}
                          </span>{' '}
                          · <strong style={{ color: '#38bdf8' }}>{translateActor(log.actor)}</strong> →{' '}
                          <span style={{ color: 'var(--text-primary)' }}>
                            {AUDIT_EVENT_LABELS[log.event] || log.event}
                          </span>
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

function SummaryPill({ label, value, color }) {
  return (
    <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.5rem 0.7rem' }}>
      <div style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>{label}</div>
      <div style={{ fontSize: '1.05rem', fontWeight: 800, color: color || 'var(--text-primary)', marginTop: '0.1rem' }}>{value}</div>
    </div>
  );
}

function ExplainBlock({ title, children }) {
  return (
    <div style={{ background: 'rgba(0, 0, 0, 0.22)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.65rem 0.75rem' }}>
      <div style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-tertiary)', marginBottom: '0.35rem', textTransform: 'uppercase' }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function LifecycleStepper({ proposed, approved, executed, verified, failed }) {
  const steps = [
    { label: 'Đề xuất', done: proposed },
    { label: 'Phê duyệt', done: approved },
    { label: 'Thực thi', done: executed },
    { label: failed ? 'Thất bại' : 'Xác minh', done: verified, isFailed: failed },
  ];
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
      {steps.map((s, idx) => (
        <div key={s.label} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
          <span
            style={{
              padding: '0.18rem 0.55rem',
              borderRadius: '999px',
              fontSize: '0.72rem',
              fontWeight: 700,
              background: s.isFailed
                ? 'rgba(239, 68, 68, 0.16)'
                : s.done
                ? 'rgba(16, 185, 129, 0.16)'
                : 'rgba(255, 255, 255, 0.04)',
              color: s.isFailed ? '#ef4444' : s.done ? '#10b981' : 'var(--text-tertiary)',
              border: `1px solid ${s.isFailed ? 'rgba(239, 68, 68, 0.4)' : s.done ? 'rgba(16, 185, 129, 0.4)' : 'var(--border)'}`,
            }}
          >
            {s.done ? '✓ ' : ''}{s.label}
          </span>
          {idx < steps.length - 1 && <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem' }}>→</span>}
        </div>
      ))}
    </div>
  );
}
