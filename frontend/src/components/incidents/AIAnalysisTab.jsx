import { useState, useEffect, useRef, useMemo } from 'react';
import toast from 'react-hot-toast';
import {
  FiCheckCircle,
  FiClock,
  FiCopy,
  FiEye,
  FiHelpCircle,
  FiRefreshCw,
  FiShield,
} from 'react-icons/fi';
import api from '../../api/api';
import { getAIAnalysis, getIncidentTimeline, rateAIAnalysis } from '../../api/incidents';
import Button from '../ui/Button';
import AISuggestionPanel from './AISuggestionPanel';
import AnalysisSourcePanel from './AnalysisSourcePanel';
import DecisionTracePanel from './DecisionTracePanel';
import { getRunTrace, listAnalysisRuns, runAnalysis, streamRunTrace } from '../../api/threatMemory';
import { SafeStructuredParagraphs, parseAnalysisSections } from './SafeAnalysisContent';
import {
  COMPLETENESS_LABELS,
  formatDateTimeUTC,
  formatDateTimeVN,
  getActionMeta,
  shortenId,
  translateActivity,
  translateClassification,
  translateIncidentStatus,
  translateMissingEvidence,
  translateSeverity,
  translateTimelineEventType,
} from '../../i18n/viVN';

const MITRE_EXPLANATIONS = {
  T1110: 'Kẻ tấn công thử nhiều mật khẩu liên tiếp vào dịch vụ xác thực để chiếm quyền truy cập.',
  'T1110.001': 'Dò mật khẩu trực tiếp theo từ điển hoặc danh sách mật khẩu.',
  T1190: 'Kẻ tấn công khai thác hoặc thăm dò lỗ hổng trong ứng dụng web công khai (ví dụ SQL Injection).',
  T1046: 'Quét cổng dịch vụ nhằm phát hiện các cổng/dịch vụ đang mở trên máy mục tiêu.',
  T1059: 'Thực thi lệnh qua trình thông dịch hệ thống như bash, sh hoặc PowerShell.',
  'T1059.004': 'Thực thi lệnh qua Unix/Linux Shell.',
  'T1059.006': 'Thực thi mã hoặc backdoor bằng trình thông dịch Python.',
};

const FALLBACK_STATUS_WARNINGS = {
  timeout: 'Mô hình AI quá thời gian chờ (timeout) — nội dung bên dưới là báo cáo tổng hợp xác định từ bằng chứng thực tế và đề xuất theo policy, KHÔNG phải phân tích AI thành công.',
  model_error: 'Không gọi được mô hình AI cục bộ — hệ thống hiển thị báo cáo tổng hợp xác định từ bằng chứng thực tế.',
  schema_invalid: 'Mô hình AI trả cấu trúc không hợp lệ — hệ thống đã loại bỏ kết quả thiếu căn cứ và hiển thị báo cáo xác định từ bằng chứng.',
  queue_saturated: 'Hàng đợi phân tích AI đang quá tải — hệ thống hiển thị tóm tắt xác định từ bằng chứng.',
  evidence_changed: 'Bằng chứng sự cố vừa cập nhật trong lúc phân tích — hệ thống đang xếp hàng đánh giá lại theo bằng chứng mới nhất.',
};

export default function AIAnalysisTab({ incidentId, incident = null, httpIncident = false, onOpenAssist }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [error, setError] = useState(null);
  const [ratingLoading, setRatingLoading] = useState(false);
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [assistState, setAssistState] = useState(null);
  const [selectedFactIdx, setSelectedFactIdx] = useState(null);
  const [traceRuns, setTraceRuns] = useState([]);
  const [activeRun, setActiveRun] = useState(null);
  const [traceEvents, setTraceEvents] = useState([]);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceStreaming, setTraceStreaming] = useState(false);
  const [traceExpanded, setTraceExpanded] = useState(false);
  const pollTimerRef = useRef(null);
  const streamAbortRef = useRef(null);
  const factCardRefs = useRef({});

  const stopTraceStream = () => {
    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
      streamAbortRef.current = null;
    }
    setTraceStreaming(false);
  };

  const appendTraceEvent = (ev) => {
    if (!ev || typeof ev !== 'object') return;
    setTraceEvents((prev) => {
      if (prev.some((item) => item.sequence === ev.sequence)) return prev;
      return [...prev, ev].sort((a, b) => (a.sequence || 0) - (b.sequence || 0));
    });
    if (ev.event_type === 'analysis_started') {
      setActiveRun((prev) => (prev ? { ...prev, status: 'RUNNING', started_at: ev.started_at || prev.started_at } : prev));
    } else if (ev.event_type === 'analysis_completed' || ev.event_type === 'analysis_failed') {
      const terminalStatus = ev.status === 'TIMEOUT' ? 'TIMEOUT' : ev.event_type === 'analysis_completed' ? 'COMPLETED' : (ev.status || 'FAILED');
      setActiveRun((prev) =>
        prev
          ? {
              ...prev,
              status: terminalStatus,
              completed_at: ev.completed_at || prev.completed_at,
              analysis_id: ev.safe_result?.analysis_id || prev.analysis_id,
            }
          : prev,
      );
    }
  };

  const connectRunStream = (runId, afterSequence = 0, { refreshOnDone = true } = {}) => {
    stopTraceStream();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setTraceStreaming(true);

    streamRunTrace(runId, {
      afterSequence,
      signal: controller.signal,
      onEvent: (ev) => {
        appendTraceEvent(ev);
        if (ev.event_type === 'analysis_completed' || ev.event_type === 'analysis_failed') {
          if (pollTimerRef.current) {
            clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
          }
          setTraceStreaming(false);
          setRegenerating(false);
          if (refreshOnDone) {
            fetchAnalysis(true);
            getRunTrace(runId)
              .then((res) => {
                if (res?.run) setActiveRun(res.run);
                if (Array.isArray(res?.events)) setTraceEvents(res.events);
              })
              .catch(() => {});
            listAnalysisRuns(incidentId)
              .then((res) => setTraceRuns(Array.isArray(res?.runs) ? res.runs : []))
              .catch(() => {});
          }
          if (ev.status === 'TIMEOUT') {
            toast('AI hết thời gian chờ — đã tạo báo cáo dự phòng xác định.', { icon: '⚠' });
          } else if (ev.event_type === 'analysis_completed') {
            toast.success('Đã hoàn tất phân tích AI!');
          } else {
            toast.error('Phiên phân tích AI không thành công');
          }
        }
      },
      onError: () => {
        setTraceStreaming(false);
      },
      onClose: () => {
        setTraceStreaming(false);
      },
    });
  };

  const loadRunTrace = async (runId, { autoStream = true } = {}) => {
    if (!runId) return;
    setTraceLoading(true);
    try {
      const res = await getRunTrace(runId);
      if (res?.run) {
        setActiveRun(res.run);
        const evs = Array.isArray(res.events) ? res.events : [];
        setTraceEvents(evs);
        const isLive = res.run.status === 'CREATED' || res.run.status === 'RUNNING';
        if (autoStream && isLive) {
          setTraceExpanded(true);
          setRegenerating(true);
          const maxSeq = evs.reduce((acc, item) => Math.max(acc, item.sequence || 0), 0);
          connectRunStream(runId, maxSeq);
        }
      }
    } catch {
      // Ignore trace load errors so analysis panel remains usable
    } finally {
      setTraceLoading(false);
    }
  };

  const fetchAnalysis = async (isRetry = false) => {
    try {
      if (!isRetry) setLoading(true);
      setError(null);
      const data = await getAIAnalysis(incidentId);
      setAnalysis(data);
    } catch (err) {
      if (err.status === 404 || err.response?.status === 404 || err.message?.includes('404')) {
        setAnalysis(null);
        setError('pending');
      } else {
        setError(err.message || 'Lỗi khi tải kết quả phân tích AI');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!incidentId) return undefined;
    stopTraceStream();
    setTraceRuns([]);
    setActiveRun(null);
    setTraceEvents([]);
    setTraceExpanded(false);
    fetchAnalysis();
    getIncidentTimeline(incidentId).then((items) => setTimelineEvents(Array.isArray(items) ? items : []));
    api
      .get(`/incidents/${encodeURIComponent(incidentId)}/response-proposals`)
      .then((res) => setAssistState(res))
      .catch(() => setAssistState(null));
    listAnalysisRuns(incidentId)
      .then((res) => {
        const runs = Array.isArray(res?.runs) ? res.runs : [];
        setTraceRuns(runs);
        const active = runs.find((r) => r.status === 'RUNNING' || r.status === 'CREATED') || runs[0];
        if (active?.analysis_run_id) {
          loadRunTrace(active.analysis_run_id, { autoStream: true });
        }
      })
      .catch(() => {});

    return () => {
      stopTraceStream();
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [incidentId]);

  const handleRegenerate = async (mode = 'fresh') => {
    try {
      setRegenerating(true);
      setError(null);
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      stopTraceStream();

      const oldAnalysisId = analysis?.id || null;
      const startTime = Date.now();

      const runRes = await runAnalysis(incidentId, mode);
      const runId = runRes?.analysis_run_id || null;
      toast(mode === 'fresh' ? 'Đang làm mới bằng AI (~2-4 phút trên CPU).' : 'Đang phân tích lại (có thể dùng mẫu đã kiểm chứng).', { icon: '⏳', duration: 5000 });

      if (runId) {
        setTraceExpanded(true);
        setActiveRun({
          analysis_run_id: runId,
          incident_id: incidentId,
          mode,
          status: 'RUNNING',
          started_at: new Date().toISOString(),
        });
        setTraceEvents([]);
        listAnalysisRuns(incidentId)
          .then((res) => {
            if (Array.isArray(res?.runs)) setTraceRuns(res.runs);
          })
          .catch(() => {});
        const traceSnapshot = await getRunTrace(runId).catch(() => null);
        const existingEvs = Array.isArray(traceSnapshot?.events) ? traceSnapshot.events : [];
        if (traceSnapshot?.run) setActiveRun(traceSnapshot.run);
        if (existingEvs.length > 0) setTraceEvents(existingEvs);
        const maxSeq = existingEvs.reduce((acc, item) => Math.max(acc, item.sequence || 0), 0);
        const terminalNow = ['COMPLETED', 'FAILED', 'TIMEOUT', 'CANCELLED'].includes(traceSnapshot?.run?.status);
        if (terminalNow) {
          setRegenerating(false);
          fetchAnalysis(true);
          return;
        }
        connectRunStream(runId, maxSeq);
      }

      let attempts = 0;
      pollTimerRef.current = setInterval(async () => {
        attempts++;
        if (attempts > 60) {
          clearInterval(pollTimerRef.current);
          setRegenerating(false);
          pollTimerRef.current = null;
          setError('AI quá thời gian chờ sau 5 phút. Vui lòng thử lại.');
          toast.error('Quá thời gian phân tích AI');
          return;
        }
        try {
          const data = await getAIAnalysis(incidentId);
          const isNew = data && data.id && data.id !== oldAnalysisId;
          const isFresh = data?.created_at && new Date(data.created_at).getTime() > startTime;
          if (isNew && isFresh) {
            clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
            setAnalysis(data);
            setRegenerating(false);
            if (runId) loadRunTrace(runId, { autoStream: false });
          }
        } catch {
          // 404 while running
        }
      }, 5000);
    } catch (err) {
      setRegenerating(false);
      stopTraceStream();
      const msg = err.response?.data?.detail || err.message || 'Lỗi khi kích hoạt phân tích AI';
      setError(msg);
      toast.error(msg);
    }
  };

  const handleRate = async (rating) => {
    if (ratingLoading || !analysis) return;
    try {
      setRatingLoading(true);
      await rateAIAnalysis(incidentId, rating);
      setAnalysis((prev) => ({ ...prev, analyst_rating: rating }));
      toast.success(rating === 'helpful' ? 'Đã lưu đánh giá: Hữu ích' : 'Đã lưu đánh giá: Chưa chính xác');
    } catch (err) {
      toast.error(`Không thể lưu đánh giá: ${err.message}`);
    } finally {
      setRatingLoading(false);
    }
  };

  const behavior = incident?.detection_evidence?.behavior || {};
  const chain = incident?.detection_evidence?.chain || null;
  const isChain = Boolean(chain) || incident?.detection_evidence?.rule_id === 'web_compromise_chain';
  const investigation = assistState?.investigation || null;
  const severityMeta = translateSeverity(incident?.severity);
  const rawMeta = useMemo(() => {
    if (!analysis?.raw_response) return {};
    try {
      const parsed = JSON.parse(analysis.raw_response);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }, [analysis?.raw_response]);
  const rawClassification = investigation?.classification || behavior.classification || rawMeta.classification || '';
  const classificationText = isChain && !rawClassification
    ? (chain?.execution_observed ? 'Chuỗi xâm nhập ứng dụng web (RCE / Reverse Shell)' : 'Chuỗi tấn công ứng dụng web')
    : translateClassification(rawClassification);
  const sourceIp =
    behavior.source_ip ||
    chain?.source_ips?.[0] ||
    chain?.network?.[0]?.dst?.split(':')[0] ||
    investigation?.observed_facts?.find((f) => f.source_ip)?.source_ip ||
    null;
  const anchorCmd = `${chain?.anchor?.name || ''} ${chain?.anchor?.exe || ''} ${chain?.anchor?.cmdline || ''}`.toLowerCase();
  const serviceName =
    behavior.service ||
    (isChain ? (anchorCmd.includes('vulnerable_web') || anchorCmd.includes('flask') ? 'flask_web' : (chain?.anchor?.name || 'web_service')) : null) ||
    (httpIncident ? 'flask_web' : null);
  const failedAttempts = Number.isInteger(behavior.failed_attempts) ? behavior.failed_attempts : null;
  const successAttempts = Number.isInteger(behavior.successful_attempts) ? behavior.successful_attempts : null;

  const executiveNarrative = useMemo(() => {
    if (isChain && chain) {
      return chain.severity_reason || incident?.description || 'Hệ thống đã tương quan chuỗi xâm nhập ứng dụng web từ nhiều nguồn bằng chứng.';
    }
    if (failedAttempts !== null && sourceIp) {
      const successNote =
        successAttempts === 0
          ? 'Chưa ghi nhận lần đăng nhập thành công nào từ nguồn này.'
          : successAttempts > 0
          ? `Ghi nhận ${successAttempts} lần đăng nhập thành công trong chuỗi sự kiện — cần kiểm tra ngay.`
          : 'Chưa xác minh được kết quả đăng nhập thành công hay thất bại toàn phần.';
      return `Phát hiện ${failedAttempts} lần đăng nhập thất bại liên tiếp từ IP ${sourceIp} vào ứng dụng ${serviceName || 'hệ thống'}. ${successNote}`;
    }
    if (investigation?.behavioral_interpretation) {
      return investigation.behavioral_interpretation;
    }
    return incident?.story || incident?.description || 'Hệ thống đã ghi nhận sự cố từ dữ liệu telemetry trên máy trạm.';
  }, [isChain, chain, failedAttempts, successAttempts, sourceIp, serviceName, investigation, incident]);

  const parsedSections = useMemo(() => parseAnalysisSections(analysis?.summary || ''), [analysis?.summary]);

  // Build real-timestamp-only timeline combining backend timeline, chain stages, incident, AI analysis, and response actions.
  const mergedTimeline = useMemo(() => {
    const entries = [];
    if (chain) {
      for (const cond of chain.conditions || []) {
        if (['OBSERVED', 'CORRELATED'].includes(cond.status) && cond.observed_at) {
          entries.push({
            time: cond.observed_at,
            label: cond.label || cond.id,
            title: cond.detail || cond.id,
            severity: ['outbound_connection', 'privileged_execution', 'web_spawned_shell'].includes(cond.id) ? 'critical' : 'warning',
          });
        }
      }
      for (const net of chain.network || []) {
        if (net.first_seen) {
          entries.push({
            time: net.first_seen,
            label: 'Kết nối ra ngoài',
            title: `PID ${net.pid} → ${net.dst}${net.socket_stdio ? ' (stdin/stdout gắn vào socket)' : ''}`,
            severity: 'critical',
          });
        }
      }
    }
    for (const item of timelineEvents) {
      if (!item?.time) continue;
      entries.push({
        time: item.time,
        label: translateTimelineEventType(item.type),
        title: item.title,
        detail: item.details,
        severity: item.severity || 'info',
      });
    }
    if (behavior.first_attempt_at) {
      const scan = behavior.activity_summary;
      const firstLabel =
        behavior.evidence_type === 'authentication'
          ? 'Xác thực thất bại đầu tiên'
          : behavior.evidence_type === 'network'
            ? 'Kết nối đầu tiên từ nguồn'
            : 'Request đầu tiên từ nguồn';
      entries.push({
        time: behavior.first_attempt_at,
        label: firstLabel,
        title: scan?.is_service_scan
          ? `Bắt đầu quét dịch vụ web bằng ${(scan.tools || []).join(', ') || 'công cụ tự động'} từ ${sourceIp || 'nguồn chưa rõ'}`
          : `Bắt đầu chuỗi truy cập bất thường từ ${sourceIp || 'nguồn chưa rõ'}`,
        detail: { source_ip: sourceIp, service: serviceName },
        severity: 'warning',
      });
    }
    if (behavior.activity_summary?.last_request_at && behavior.activity_summary.last_request_at !== behavior.first_attempt_at) {
      const scan = behavior.activity_summary;
      entries.push({
        time: scan.last_request_at,
        label: 'Request cuối cùng từ nguồn',
        title: `Tổng cộng ${scan.request_count} request tới ${scan.distinct_path_count} đường dẫn trong ${scan.duration_seconds} giây`,
        severity: 'warning',
      });
    }
    if (incident?.createdAt || incident?.created_at) {
      entries.push({
        time: incident.createdAt || incident.created_at,
        label: 'Tạo hồ sơ sự cố',
        title: `Hệ thống mở sự cố ${incident.id} (Risk ${incident.riskScore ?? incident.risk_score ?? 0}/100)`,
        severity: 'warning',
      });
    }
    if (analysis?.created_at) {
      entries.push({
        time: analysis.created_at,
        label: 'Phân tích AI hoàn tất',
        title: analysis.model_name === 'threat-memory' ? 'Tạo báo cáo từ mẫu đã kiểm chứng (không gọi mô hình)' : `Tạo báo cáo phân tích bởi ${analysis.model_name || 'mô hình AI cục bộ'}`,
        severity: 'info',
      });
    }
    for (const act of assistState?.actions || []) {
      const meta = getActionMeta(act.action_type);
      const created = act.proposal_created_at || act.result?.start;
      if (created) {
        entries.push({
          time: typeof created === 'number' ? new Date(created * 1000).toISOString() : created,
          label: 'Đề xuất hành động',
          title: `${meta.title} (${act.action_type})`,
          severity: 'info',
        });
      }
      const vTime = act.result?.verification?.observed_at || act.result?.verification?.timestamp;
      if (vTime) {
        entries.push({
          time: vTime,
          label: 'Xác minh hành động',
          title: act.status === 'succeeded' ? meta.successHeadline : `${meta.title} — ${act.status}`,
          severity: act.status === 'succeeded' ? 'success' : 'warning',
        });
      }
    }
    const deduped = [];
    const seen = new Set();
    for (const entry of entries) {
      const key = `${entry.time}|${entry.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(entry);
    }
    deduped.sort((a, b) => new Date(a.time) - new Date(b.time));
    return deduped;
  }, [chain, timelineEvents, behavior.first_attempt_at, behavior.evidence_type, behavior.activity_summary, sourceIp, serviceName, incident, analysis, assistState]);

  // Observed evidence cards (distinguishing confirmed facts vs inferences vs missing evidence).
  const observedFacts = useMemo(() => {
    const facts = [];
    if (chain) {
      for (const cond of chain.conditions || []) {
        if (!['OBSERVED', 'CORRELATED'].includes(cond.status)) continue;
        facts.push({
          kind: 'confirmed',
          title: `${cond.label || cond.id} (${cond.status === 'OBSERVED' ? 'Quan sát trực tiếp' : 'Liên kết bằng chứng'})`,
          summary: cond.detail || '',
          observedAt: cond.observed_at,
          evidenceIds: cond.evidence_ids || [],
          raw: cond,
        });
      }
      const anchorId = chain.anchor?.id;
      for (const proc of chain.process_tree || []) {
        if (proc.id === anchorId) continue;
        facts.push({
          kind: 'confirmed',
          title: `Tiến trình liên quan: ${proc.name || 'process'} (PID ${proc.pid})`,
          summary: `PPID ${proc.parent_pid} · ${proc.euid === 0 ? 'root (euid 0)' : `euid ${proc.euid ?? 'chưa rõ'}`} · ${proc.cmdline || proc.exe}`,
          observedAt: proc.started_at,
          evidenceIds: proc.id ? [proc.id] : [],
          raw: proc,
        });
      }
      for (const net of chain.network || []) {
        facts.push({
          kind: 'confirmed',
          title: `Kết nối mạng xác minh qua inode: ${net.dst}`,
          summary: `${net.src} → ${net.dst} (${net.direction || 'outbound'}) · PID ${net.pid}${net.socket_stdio ? ' · stdin/stdout gắn socket' : ''}`,
          observedAt: net.first_seen,
          evidenceIds: net.flow_id ? [net.flow_id] : [],
          raw: net,
        });
      }
      return facts;
    }
    const scan = behavior.activity_summary;
    if (scan) {
      const answered = (scan.answered || []).map((a) => `${a.method} ${a.path} → ${a.http_status}`).join(', ');
      facts.push({
        kind: 'confirmed',
        title: scan.is_service_scan ? 'Quét dịch vụ web (tổng hợp từ nhật ký truy cập)' : 'Hoạt động HTTP tự động (tổng hợp)',
        summary: [
          `${scan.request_count} request · ${scan.distinct_path_count} đường dẫn · ${scan.duration_seconds} giây`,
          sourceIp ? `Nguồn: ${sourceIp}` : null,
          scan.tools?.length ? `Công cụ: ${scan.tools.join(', ')}` : null,
          scan.target_ports?.length ? `Cổng: ${scan.target_ports.join(', ')}` : null,
          `${scan.not_found_path_count} đường dẫn 404 bị dò`,
          answered ? `Dịch vụ đã trả lời: ${answered}` : null,
          ...(scan.successful_logins_from_source || []).map(
            (l) => `Cùng nguồn đã đăng nhập thành công: ${l.username && l.username !== 'unknown' ? l.username : 'tài khoản không xác định'} (${l.service})`,
          ),
        ]
          .filter(Boolean)
          .join(' · '),
        observedAt: scan.last_request_at,
        evidenceIds: behavior.source_event_ids || [],
        raw: scan,
      });
    }
    if (!scan && Array.isArray(investigation?.observed_facts)) {
      for (const f of investigation.observed_facts) {
        facts.push({
          kind: 'confirmed',
          title: f.provenance === 'web_access_logs' ? 'Quan sát HTTP từ nhật ký truy cập' : 'Bằng chứng tương quan',
          summary: [
            f.method ? `${f.method} (HTTP ${f.http_status ?? '—'})` : null,
            f.source_ip ? `Nguồn: ${f.source_ip}` : null,
            f.automation_hint ? `Công cụ: ${f.automation_hint}` : null,
            f.outcome ? `Kết quả: ${f.outcome}` : null,
          ]
            .filter(Boolean)
            .join(' · '),
          observedAt: f.observed_at,
          evidenceIds: f.evidence_ids || [],
          raw: f,
        });
      }
    }
    if (failedAttempts !== null) {
      facts.push({
        kind: 'confirmed',
        title: 'Bản ghi xác thực ứng dụng',
        summary: `${failedAttempts} lần thất bại · ${successAttempts ?? 0} lần thành công · Dịch vụ: ${serviceName || 'N/A'}`,
        observedAt: behavior.last_attempt_at || behavior.first_attempt_at,
        evidenceIds: behavior.source_event_ids || [],
        raw: behavior,
      });
    }
    return facts;
  }, [chain, investigation, failedAttempts, successAttempts, serviceName, behavior]);

  const missingEvidenceList = useMemo(() => {
    if (chain) {
      const items = (chain.conditions || [])
        .filter((c) => c.status === 'NOT_OBSERVED')
        .map((c) => `${c.label || c.id}: ${c.detail || 'Chưa có bằng chứng'}`);
      return items.length > 0 ? items : ['Không có khoảng trống lớn trong chuỗi bằng chứng đã quan sát.'];
    }
    const items = [];
    if (Array.isArray(investigation?.missing_evidence)) {
      for (const m of investigation.missing_evidence) items.push(translateMissingEvidence(m));
    }
    if (successAttempts === 0) {
      items.push('Chưa ghi nhận phiên đăng nhập thành công; cần đối chiếu thêm nếu nghi ngờ mật khẩu bị lộ.');
    }
    if (!incident?.culpritProcess && !incident?.culprit_process) {
      items.push('Chưa có tiến trình hoặc PID trên host gắn trực tiếp vào lưu lượng này.');
    }
    return Array.from(new Set(items));
  }, [chain, investigation, successAttempts, incident]);

  const confidencePct = Math.round(((analysis?.confidence ?? investigation?.confidence ?? 0) * 100));
  const completenessCode = investigation?.evidence_completeness || (analysis ? 'partial' : 'partial');
  const completenessText = COMPLETENESS_LABELS[completenessCode] || completenessCode;

  if (loading || regenerating) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1rem 0' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            background: 'var(--bg-secondary)',
            padding: '1rem',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border)',
          }}
        >
          <FiRefreshCw className="spin" size={20} color="var(--primary)" />
          <div>
            <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {regenerating ? 'Đang chạy phân tích AI mới...' : 'Đang tải hồ sơ phân tích AI...'}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              {regenerating
                ? 'Quá trình suy luận chạy nền trên máy chủ. Bạn có thể chuyển sang tab khác mà không mất tiến trình.'
                : 'Đang tổng hợp dữ kiện sự cố, bằng chứng và dòng thời gian.'}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.15rem', padding: '0.25rem 0' }}>
      {/* A. TÓM TẮT SỰ CỐ (10-20s Executive View) */}
      <div
        style={{
          background: 'var(--bg-secondary)',
          border: `1px solid ${severityMeta.border}`,
          borderRadius: 'var(--radius-md)',
          padding: '1rem 1.15rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.85rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            <span
              style={{
                fontSize: '0.74rem',
                fontWeight: 700,
                padding: '0.2rem 0.55rem',
                borderRadius: '4px',
                background: severityMeta.bg,
                color: severityMeta.color,
                border: `1px solid ${severityMeta.border}`,
              }}
            >
              Mức độ: {severityMeta.label}
            </span>
            <strong style={{ fontSize: '1rem', color: 'var(--text-primary)' }}>
              Phân tích sự cố bằng AI · {classificationText}
            </strong>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <Button variant="outline" size="sm" onClick={() => handleRegenerate('fresh')} disabled={regenerating}>
              <FiRefreshCw size={13} style={{ marginRight: '0.35rem' }} /> Phân tích lại bằng AI
            </Button>
          </div>
        </div>

        {/* Concise grounded verdict */}
        <div
          style={{
            padding: '0.75rem 0.95rem',
            borderRadius: '6px',
            background: 'rgba(59, 130, 246, 0.08)',
            borderLeft: `4px solid ${severityMeta.color}`,
            fontSize: '0.88rem',
            lineHeight: 1.55,
            color: 'var(--text-primary)',
          }}
        >
          {executiveNarrative}
        </div>

        {/* 8-card KPI grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.55rem' }}>
          <SummaryCell label="Điểm rủi ro" value={`${incident?.riskScore ?? incident?.risk_score ?? 0}/100`} accent={severityMeta.color} />
          <SummaryCell label="Nguồn tấn công" value={sourceIp || 'Chưa xác định'} mono />
          <SummaryCell label="Máy bị ảnh hưởng" value={incident?.agentId || incident?.agent_id || 'Không rõ'} mono />
          <SummaryCell label="Dịch vụ mục tiêu" value={serviceName || 'Hệ thống'} mono />
          <SummaryCell
            label="Thời gian phát hiện (VN)"
            value={formatDateTimeVN(incident?.createdAt || incident?.created_at)}
            title={formatDateTimeUTC(incident?.createdAt || incident?.created_at)}
          />
          <SummaryCell
            label="Trạng thái & Hoạt động"
            value={`${translateIncidentStatus(incident?.status)} · ${translateActivity(incident?.detection_activity)}`}
          />
          <SummaryCell label="Độ tin cậy AI" value={`${confidencePct}%`} />
          <SummaryCell label="Mức độ đầy đủ bằng chứng" value={completenessText} />
        </div>
      </div>

      <AnalysisSourcePanel incidentId={incidentId} analysisId={analysis?.id} busy={regenerating} onRun={handleRegenerate} />

      <DecisionTracePanel
        runs={traceRuns}
        activeRun={activeRun}
        events={traceEvents}
        loading={traceLoading}
        streaming={traceStreaming}
        expanded={traceExpanded}
        onToggleExpand={() => setTraceExpanded((prev) => !prev)}
        onSelectRun={(selectedRunId) => loadRunTrace(selectedRunId, { autoStream: true })}
        onSelectEvidenceRef={(eid) => {
          const idx = observedFacts.findIndex((f) => Array.isArray(f.evidenceIds) && f.evidenceIds.includes(eid));
          if (idx >= 0) {
            setSelectedFactIdx(idx);
            factCardRefs.current[idx]?.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
          } else {
            navigator.clipboard?.writeText?.(eid).catch(() => {});
            toast(`Mã bằng chứng: ${eid}`, { icon: '🔍' });
          }
        }}
      />

      {FALLBACK_STATUS_WARNINGS[rawMeta.status] && (
        <div
          style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(245, 158, 11, 0.12)',
            border: '1px solid rgba(245, 158, 11, 0.45)',
            color: '#fbbf24',
            fontSize: '0.84rem',
            fontWeight: 600,
          }}
        >
          ⚠ {FALLBACK_STATUS_WARNINGS[rawMeta.status]}
        </div>
      )}

      {/* B. CHUYỆN GÌ ĐÃ XẢY RA? (Safe Structured Interpretation, NO raw Markdown) */}
      <SectionCard title="Chuyện gì đã xảy ra?" subtitle={analysis ? (analysis.model_name === 'threat-memory' ? 'Từ mẫu đã kiểm chứng (không gọi mô hình)' : `Mô hình: ${analysis.model_name || 'AI cục bộ'}`) : 'Chưa có bản phân tích AI'}>
        {error && error !== 'pending' && !analysis ? (
          <div style={{ color: 'var(--error)', fontSize: '0.84rem' }}>
            Không thể tải kết quả phân tích AI: {error}
          </div>
        ) : !analysis ? (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Sự cố chưa có bản tóm tắt AI. Hệ thống vẫn hiển thị đầy đủ bằng chứng xác định và các hành động ứng phó ở dưới.
            </span>
            <Button variant="primary" size="sm" onClick={() => handleRegenerate('fresh')}>
              Chạy phân tích AI ngay
            </Button>
          </div>
        ) : analysis.error_message || analysis.summary === '[AI analysis failed]' ? (
          <div style={{ color: 'var(--error)', fontSize: '0.84rem' }}>
            Phân tích AI gặp sự cố: {analysis.error_message || 'Mô hình không trả về cấu trúc hợp lệ.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
            <SafeStructuredParagraphs text={analysis.summary} />
            {analysis.root_cause && (
              <div
                style={{
                  padding: '0.75rem 0.9rem',
                  borderRadius: '6px',
                  background: 'rgba(16, 185, 129, 0.06)',
                  border: '1px solid rgba(16, 185, 129, 0.25)',
                }}
              >
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#10b981', marginBottom: '0.25rem' }}>
                  Nguyên nhân gốc
                </div>
                <SafeStructuredParagraphs text={analysis.root_cause} />
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* C. BẰNG CHỨNG QUAN SÁT (Confirmed Fact vs Inference vs Missing Evidence) */}
      <SectionCard title="Bằng chứng quan sát" subtitle="Phân tách rõ dữ kiện đã xác thực, suy luận hành vi và phần còn thiếu">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem' }}>
          {/* Confirmed Facts */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <FiCheckCircle size={13} /> Sự kiện đã xác nhận (Confirmed Fact)
            </div>
            {observedFacts.length === 0 ? (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
                Chưa có bản ghi tương quan chi tiết gắn với sự cố này.
              </div>
            ) : (
              observedFacts.map((f, idx) => {
                const open = selectedFactIdx === idx;
                return (
                  <div
                    key={idx}
                    ref={(el) => {
                      if (el) factCardRefs.current[idx] = el;
                    }}
                    style={{
                      padding: '0.65rem 0.8rem',
                      borderRadius: '6px',
                      background: 'rgba(16, 185, 129, 0.06)',
                      border: '1px solid rgba(16, 185, 129, 0.25)',
                      fontSize: '0.8rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                      <strong style={{ color: 'var(--text-primary)' }}>{f.title}</strong>
                      <button
                        type="button"
                        onClick={() => setSelectedFactIdx(open ? null : idx)}
                        style={{ background: 'none', border: 'none', color: 'var(--primary)', fontSize: '0.74rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
                      >
                        <FiEye size={12} /> {open ? 'Thu gọn' : 'Xem bản ghi gốc'}
                      </button>
                    </div>
                    <div style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>{f.summary}</div>
                    {f.observedAt && (
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)', marginTop: '0.2rem' }} title={formatDateTimeUTC(f.observedAt)}>
                        Thời điểm: {formatDateTimeVN(f.observedAt)}
                      </div>
                    )}
                    {open && (
                      <div style={{ marginTop: '0.5rem', padding: '0.5rem', borderRadius: '4px', background: 'rgba(0,0,0,0.35)', fontSize: '0.74rem', fontFamily: 'monospace', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                        {f.evidenceIds.length > 0 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                            <span>Mã bằng chứng: {f.evidenceIds.slice(0, 5).map((id) => shortenId(id)).join(', ')}{f.evidenceIds.length > 5 ? ` (+${f.evidenceIds.length - 5})` : ''}</span>
                            <button
                              type="button"
                              onClick={() => navigator.clipboard.writeText(f.evidenceIds.join(', ')).then(() => toast.success('Đã sao chép mã bằng chứng'))}
                              style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', padding: 0 }}
                              title="Sao chép toàn bộ mã bằng chứng"
                            >
                              <FiCopy size={11} />
                            </button>
                          </div>
                        )}
                        {f.raw?.user_agent && <div>User-Agent: {f.raw.user_agent}</div>}
                        {f.raw?.request_id && <div>Request ID: {f.raw.request_id}</div>}
                        {f.raw?.request_method && <div>Endpoint: {f.raw.request_method} {f.raw.request_path}</div>}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Inference & Missing Evidence */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            <div
              style={{
                padding: '0.65rem 0.8rem',
                borderRadius: '6px',
                background: 'rgba(59, 130, 246, 0.06)',
                border: '1px solid rgba(59, 130, 246, 0.25)',
                fontSize: '0.8rem',
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#60a5fa', marginBottom: '0.25rem' }}>
                Suy luận hành vi (Inference)
              </div>
              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {parsedSections.sections.find((s) => s.key.includes('interpretation'))?.items?.[0] ||
                  investigation?.behavioral_interpretation ||
                  'Chuỗi sự kiện phù hợp với hành vi tự động dò tìm hoặc thử thông tin đăng nhập.'}
              </div>
            </div>

            <div
              style={{
                padding: '0.65rem 0.8rem',
                borderRadius: '6px',
                background: 'rgba(245, 158, 11, 0.06)',
                border: '1px solid rgba(245, 158, 11, 0.25)',
                fontSize: '0.8rem',
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f59e0b', display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.3rem' }}>
                <FiHelpCircle size={13} /> Bằng chứng còn thiếu (Missing Evidence)
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.1rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                {missingEvidenceList.map((m, idx) => (
                  <li key={idx}>{m}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </SectionCard>

      {/* D. TIMELINE SỰ CỐ THỰC TẾ */}
      <SectionCard title="Dòng thời gian sự cố thực tế" subtitle="Chỉ hiển thị các mốc có timestamp thực tế từ hệ thống (Asia/Ho_Chi_Minh)">
        {mergedTimeline.length === 0 ? (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
            Chưa có sự kiện nào có mốc thời gian được ghi nhận.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {mergedTimeline.map((ev, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  gap: '0.75rem',
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  background: 'rgba(255,255,255,0.02)',
                  borderLeft: `3px solid ${
                    ev.severity === 'success' ? '#10b981' : ev.severity === 'critical' ? '#ef4444' : ev.severity === 'warning' ? '#f59e0b' : '#3b82f6'
                  }`,
                  fontSize: '0.8rem',
                }}
              >
                <div>
                  <span style={{ fontWeight: 700, color: 'var(--text-primary)', marginRight: '0.5rem' }}>{ev.label}:</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{ev.title}</span>
                </div>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)', whiteSpace: 'nowrap' }} title={formatDateTimeUTC(ev.time)}>
                  <FiClock size={11} style={{ marginRight: '0.25rem', verticalAlign: 'middle' }} />
                  {formatDateTimeVN(ev.time)}
                </span>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      {/* E. MITRE ATT&CK */}
      <SectionCard title="Ánh xạ MITRE ATT&CK" subtitle="Chỉ hiển thị kỹ thuật khi có bằng chứng xác thực tương ứng">
        {analysis?.mitre_techniques?.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            {analysis.mitre_techniques.map((t, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: '6px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.8rem', color: 'var(--primary)', background: 'rgba(59, 130, 246, 0.12)', padding: '2px 6px', borderRadius: '4px' }}>
                    {t.id}
                  </span>
                  <strong style={{ fontSize: '0.86rem', color: 'var(--text-primary)' }}>{t.name}</strong>
                  {t.tactic && <span style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)' }}>({t.tactic})</span>}
                </div>
                {MITRE_EXPLANATIONS[t.id] && (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    <strong>Giải thích:</strong> {MITRE_EXPLANATIONS[t.id]}
                  </div>
                )}
                {t.evidence && (
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', borderLeft: '2px solid var(--border)', paddingLeft: '0.5rem' }}>
                    <strong>Bằng chứng hỗ trợ:</strong> {t.evidence}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
            Chưa đủ bằng chứng xác thực để gán kỹ thuật MITRE ATT&CK (không suy đoán khi thiếu dữ kiện).
          </div>
        )}
      </SectionCard>

      {/* F. ĐIỀU CẦN ĐIỀU TRA THÊM */}
      <SectionCard title="Điều cần điều tra thêm" subtitle="Các bước kiểm chứng khuyến nghị trước khi kết luận hoặc đóng sự cố">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <ul style={{ margin: 0, paddingLeft: '1.15rem', fontSize: '0.83rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            {missingEvidenceList.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
          {(httpIncident || isChain) && onOpenAssist && (
            <Button variant="primary" size="sm" onClick={onOpenAssist}>
              <FiShield size={13} style={{ marginRight: '0.35rem' }} /> Mở Trợ lý ứng phó & Cách ly
            </Button>
          )}
        </div>
      </SectionCard>

      {!httpIncident && !isChain && <AISuggestionPanel incidentId={incidentId} onRefresh={() => fetchAnalysis(true)} />}

      {/* Analyst Feedback */}
      {analysis && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
            padding: '0.8rem 1rem',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
          }}
        >
          <div>
            <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Đánh giá chất lượng phân tích AI
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)' }}>
              Phản hồi của chuyên viên SOC giúp hiệu chỉnh độ chính xác cho các sự cố tiếp theo.
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <Button
              variant={analysis.analyst_rating === 'helpful' ? 'primary' : 'outline'}
              size="sm"
              disabled={ratingLoading}
              onClick={() => handleRate('helpful')}
            >
              👍 Hữu ích
            </Button>
            <Button
              variant={analysis.analyst_rating === 'wrong' ? 'danger' : 'outline'}
              size="sm"
              disabled={ratingLoading}
              onClick={() => handleRate('wrong')}
            >
              👎 Chưa chính xác
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function SectionCard({ title, subtitle, children }) {
  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        padding: '1rem 1.15rem',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.7rem',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: '0.4rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.45rem' }}>
        <strong style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>{title}</strong>
        {subtitle && <span style={{ fontSize: '0.74rem', color: 'var(--text-tertiary)' }}>{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function SummaryCell({ label, value, mono = false, accent, title }) {
  return (
    <div
      title={title}
      style={{
        background: 'rgba(15, 23, 42, 0.45)',
        border: '1px solid var(--border)',
        borderRadius: '6px',
        padding: '0.5rem 0.7rem',
      }}
    >
      <div style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>{label}</div>
      <div
        style={{
          fontSize: '0.84rem',
          fontWeight: 700,
          color: accent || 'var(--text-primary)',
          fontFamily: mono ? 'monospace' : 'inherit',
          marginTop: '0.15rem',
        }}
      >
        {value}
      </div>
    </div>
  );
}
