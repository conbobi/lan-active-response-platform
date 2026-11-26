/**
 * Centralized Vietnamese (vi-VN) presentation mapping and Asia/Ho_Chi_Minh formatters.
 * Technical identifiers (action_type, rule_id, status enum, evidence_id, command_id) remain untouched.
 */

const VN_FORMATTER = new Intl.DateTimeFormat('vi-VN', {
  timeZone: 'Asia/Ho_Chi_Minh',
  day: '2-digit',
  month: '2-digit',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

const UTC_FORMATTER = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  day: '2-digit',
  month: '2-digit',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

function toDate(value) {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const raw = String(value).trim();
  if (!raw) return null;
  // Normalize naive ISO strings from SQLite as UTC.
  const normalized = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(raw)
    ? `${raw.replace(' ', 'T')}Z`
    : raw;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function formatDateTimeVN(value) {
  const date = toDate(value);
  if (!date) return 'Không rõ';
  const parts = Object.fromEntries(VN_FORMATTER.formatToParts(date).map((p) => [p.type, p.value]));
  return `${parts.day}/${parts.month}/${parts.year} ${parts.hour}:${parts.minute}:${parts.second}`;
}

export function formatDateTimeUTC(value) {
  const date = toDate(value);
  if (!date) return 'Không rõ';
  const parts = Object.fromEntries(UTC_FORMATTER.formatToParts(date).map((p) => [p.type, p.value]));
  return `${parts.day}/${parts.month}/${parts.year} ${parts.hour}:${parts.minute}:${parts.second} UTC`;
}

export function formatDurationVN(seconds) {
  if (seconds == null || Number.isNaN(Number(seconds))) return 'Không rõ';
  const total = Math.max(0, Math.round(Number(seconds)));
  const m = Math.floor(total / 60);
  const s = total % 60;
  if (m === 0) return `${s} giây`;
  if (s === 0) return `${m} phút`;
  return `${m} phút ${s} giây`;
}

export function shortenId(value, head = 8, tail = 6) {
  if (!value) return '—';
  const str = String(value);
  if (str.length <= head + tail + 3) return str;
  return `${str.slice(0, head)}…${str.slice(-tail)}`;
}

export const SEVERITY_META = {
  critical: { label: 'Nghiêm trọng', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.14)', border: 'rgba(239, 68, 68, 0.4)' },
  high: { label: 'Cao', color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.14)', border: 'rgba(245, 158, 11, 0.4)' },
  medium: { label: 'Trung bình', color: '#3b82f6', bg: 'rgba(59, 130, 246, 0.14)', border: 'rgba(59, 130, 246, 0.4)' },
  low: { label: 'Thấp', color: '#10b981', bg: 'rgba(16, 185, 129, 0.14)', border: 'rgba(16, 185, 129, 0.4)' },
};

export const INCIDENT_STATUS_LABELS = {
  open: 'Chưa đóng sự cố',
  investigating: 'Đang điều tra',
  contained: 'Đã cô lập',
  resolved: 'Đã khắc phục',
  false_positive: 'Báo động giả',
  closed: 'Đã đóng hồ sơ',
};

export const ACTIVITY_LABELS = {
  historical: 'Hoạt động đã kết thúc',
  active: 'Đang hoạt động',
  running: 'Đang chạy',
};

export const CLASSIFICATION_LABELS = {
  authentication_brute_force: 'Dò mật khẩu tự động (Brute Force)',
  observed_login_failures: 'Ghi nhận nhiều lần đăng nhập thất bại',
  repeated_auth_failures: 'Đăng nhập thất bại lặp lại',
  sqli_exploitation_confirmed: 'Xác nhận khai thác SQL Injection',
  sqli_exploitation_suspected: 'Nghi vấn khai thác SQL Injection',
  sqli_probe_observed: 'Phát hiện thăm dò SQL Injection',
  sqli_probing: 'Thăm dò lỗ hổng SQL Injection',
  sqli_tool_indicator: 'Phát hiện dấu hiệu công cụ rà quét SQLi',
  automated_http_activity: 'Hoạt động HTTP tự động hóa',
  network_service_scanning: 'Quét cổng dịch vụ mạng',
  likely_malicious: 'Nghi vấn cao hành vi độc hại (Reverse Shell)',
  confirmed_malicious: 'Đã xác nhận hành vi độc hại',
  suspicious_unconfirmed: 'Quan sát dấu hiệu đáng ngờ (chưa xác nhận)',
  benign_expected: 'Hành vi hợp lệ dự kiến',
  insufficient_telemetry: 'Chưa đủ dữ liệu telemetry để kết luận',
};

export const COMPLETENESS_LABELS = {
  complete_for_session_grant: 'Đủ bằng chứng cấp phiên bất thường',
  complete: 'Đầy đủ bằng chứng',
  partial: 'Bằng chứng một phần',
  insufficient: 'Chưa đủ bằng chứng',
};

export const ACTION_META = {
  collect_additional_evidence: {
    title: 'Thu thập thêm bằng chứng mạng',
    category: 'investigation',
    categoryLabel: 'Điều tra',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Agent Endpoint (Telemetry)',
    isMitigation: false,
    successHeadline: 'Đã thu thập bằng chứng thành công',
    successExplanation:
      'Agent đã gửi network snapshot về Manager. Manager đã đối chiếu khớp command_id và xác minh việc thu thập dữ liệu. Lưu ý: hành động này không chặn cuộc tấn công.',
  },
  increase_monitoring: {
    title: 'Tăng cường giám sát HTTP',
    category: 'investigation',
    categoryLabel: 'Điều tra',
    executorLabel: 'Hệ thống Manager',
    enforcementLayer: 'Manager (Truy vấn nhật ký có giới hạn thời gian)',
    isMitigation: false,
    successHeadline: 'Đang tăng cường giám sát lưu lượng',
    successExplanation:
      'Manager rà soát định kỳ bản ghi HTTP cho IP nguồn trong cửa sổ thời gian quy định. Hành động này không chặn truy cập.',
  },
  generate_remediation_guidance: {
    title: 'Tạo hướng dẫn khắc phục',
    category: 'remediation',
    categoryLabel: 'Khắc phục',
    executorLabel: 'Hệ thống Manager',
    enforcementLayer: 'Manager (Ghi chú hồ sơ sự cố)',
    isMitigation: false,
    successHeadline: 'Đã lưu hướng dẫn khắc phục',
    successExplanation:
      'Manager đã gắn ghi chú hướng dẫn khắc phục liên kết tới mã bằng chứng trong hồ sơ sự cố.',
  },
  temporary_ip_block: {
    title: 'Chặn IP tạm thời tại ứng dụng (HTTP 403)',
    category: 'prevention',
    categoryLabel: 'Ngăn chặn',
    executorLabel: 'Ứng dụng Flask (HTTP/WAF)',
    enforcementLayer: 'Ứng dụng Flask HTTP/WAF',
    isMitigation: true,
    successHeadline: 'Đã xác minh chặn HTTP tại ứng dụng',
    successExplanation:
      'Ứng dụng đã áp dụng chính sách chặn cho IP mục tiêu. Request kiểm thử POST /login từ peer trực tiếp đã nhận HTTP 403.',
  },
  apply_rate_limit: {
    title: 'Giới hạn tần suất đăng nhập (HTTP 429)',
    category: 'prevention',
    categoryLabel: 'Ngăn chặn',
    executorLabel: 'Ứng dụng Flask (HTTP/WAF)',
    enforcementLayer: 'Ứng dụng Flask HTTP/WAF',
    isMitigation: true,
    successHeadline: 'Đã xác minh giới hạn tần suất HTTP tại ứng dụng',
    successExplanation:
      'Ứng dụng đã kích hoạt rate limit (tối đa 3 POST /login mỗi 10 giây). Request vượt ngưỡng từ IP mục tiêu đã nhận HTTP 429.',
  },
  revoke_session: {
    title: 'Thu hồi phiên đăng nhập Flask',
    category: 'remediation',
    categoryLabel: 'Khắc phục',
    executorLabel: 'Ứng dụng Flask (HTTP/WAF)',
    enforcementLayer: 'Ứng dụng Flask Session Guard',
    isMitigation: true,
    successHeadline: 'Đã xác minh thu hồi phiên đăng nhập',
    successExplanation:
      'Phiên cookie mục tiêu đã bị đưa vào danh sách từ chối và xác nhận trả về HTTP 401 khi truy cập lại.',
  },
  isolate: {
    title: 'Cô lập mạng máy trạm',
    category: 'containment',
    categoryLabel: 'Kiểm soát endpoint',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Tường lửa Endpoint (UFW / Agent)',
    isMitigation: true,
    successHeadline: 'Đã cô lập máy được quản lý',
    successExplanation:
      'Máy trạm được quản lý đã áp dụng luật cô lập mạng, chỉ giữ kết nối điều khiển với LARP Manager.',
  },
  unisolate: {
    title: 'Gỡ cô lập mạng máy trạm',
    category: 'recovery',
    categoryLabel: 'Khôi phục',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Tường lửa Endpoint (UFW / Agent)',
    isMitigation: false,
    successHeadline: 'Đã khôi phục kết nối mạng cho máy trạm',
    successExplanation: 'Luật cô lập đã được gỡ bỏ khỏi máy trạm được quản lý.',
  },
  kill_process: {
    title: 'Kết thúc tiến trình đơn lẻ',
    category: 'containment',
    categoryLabel: 'Kiểm soát endpoint',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Hệ điều hành Endpoint (Process Control)',
    isMitigation: true,
    successHeadline: 'Đã kết thúc tiến trình mục tiêu',
    successExplanation: 'Agent đã gửi tín hiệu kết thúc đúng PID và thời điểm khởi chạy đã xác minh.',
  },
  kill_process_tree: {
    title: 'Tiêu diệt toàn bộ cây tiến trình',
    category: 'containment',
    categoryLabel: 'Kiểm soát endpoint',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Hệ điều hành Endpoint (Process Tree)',
    isMitigation: true,
    successHeadline: 'Đã tiêu diệt cây tiến trình độc hại',
    successExplanation: 'Agent đã kết thúc tiến trình gốc cùng toàn bộ tiến trình con liên quan.',
  },
  block_ip: {
    title: 'Chặn IP trên tường lửa máy trạm',
    category: 'prevention',
    categoryLabel: 'Ngăn chặn',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Tường lửa Endpoint',
    isMitigation: true,
    successHeadline: 'Đã áp dụng quy tắc chặn IP trên tường lửa',
    successExplanation: 'Agent đã cài đặt quy tắc tường lửa chặn kết nối đối với IP mục tiêu.',
  },
  quarantine: {
    title: 'Cách ly hạn chế kết nối',
    category: 'containment',
    categoryLabel: 'Kiểm soát endpoint',
    executorLabel: 'LARP Agent',
    enforcementLayer: 'Tường lửa Endpoint',
    isMitigation: true,
    successHeadline: 'Đã chuyển máy trạm sang chế độ cách ly',
    successExplanation: 'Máy trạm chỉ được phép duy trì kênh quản trị SSH/DNS/Manager.',
  },
};

export const ACTION_CATEGORY_COLORS = {
  investigation: { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.14)', border: 'rgba(56, 189, 248, 0.35)' },
  prevention: { color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.14)', border: 'rgba(245, 158, 11, 0.35)' },
  containment: { color: '#ef4444', bg: 'rgba(239, 68, 68, 0.14)', border: 'rgba(239, 68, 68, 0.35)' },
  remediation: { color: '#a855f7', bg: 'rgba(168, 85, 247, 0.14)', border: 'rgba(168, 85, 247, 0.35)' },
  recovery: { color: '#10b981', bg: 'rgba(16, 185, 129, 0.14)', border: 'rgba(16, 185, 129, 0.35)' },
};

export const ACTION_STATUS_META = {
  pending_approval: { label: 'Chờ phê duyệt', code: 'PENDING_APPROVAL', color: '#f59e0b' },
  approved: { label: 'Đã phê duyệt (chưa thực thi)', code: 'APPROVED', color: '#06b6d4' },
  dispatched: { label: 'Đã xếp hàng thực thi', code: 'EXECUTED', color: '#3b82f6' },
  executing: { label: 'Đang thực thi', code: 'EXECUTING', color: '#3b82f6' },
  verifying: { label: 'Đang xác minh hiệu lực', code: 'VERIFYING', color: '#3b82f6' },
  monitoring: { label: 'Đang giám sát', code: 'MONITORING', color: '#38bdf8' },
  succeeded: { label: 'Đã xác minh hiệu lực', code: 'VERIFIED', color: '#10b981' },
  applied: { label: 'Đã áp dụng', code: 'EXECUTED', color: '#10b981' },
  partial: { label: 'Hoàn thành một phần', code: 'PARTIAL', color: '#f59e0b' },
  failed: { label: 'Thất bại', code: 'FAILED', color: '#ef4444' },
  rejected: { label: 'Đã từ chối', code: 'REJECTED', color: '#9ca3af' },
  not_recommended: { label: 'Không khuyến nghị', code: 'POLICY_DENIED', color: '#9ca3af' },
  policy_denied: { label: 'Chính sách từ chối', code: 'POLICY_DENIED', color: '#ef4444' },
  require_more_evidence: { label: 'Cần thêm bằng chứng', code: 'REQUIRE_MORE_EVIDENCE', color: '#f59e0b' },
  expired: { label: 'Hết thời hạn (TTL)', code: 'EXPIRED', color: '#6b7280' },
  rolled_back: { label: 'Đã hoàn tác', code: 'ROLLED_BACK', color: '#6b7280' },
  reverted: { label: 'Đã hoàn tác', code: 'ROLLED_BACK', color: '#6b7280' },
  rollback_failed: { label: 'Hoàn tác thất bại', code: 'ROLLBACK_FAILED', color: '#ef4444' },
};

export const PROPOSAL_ORIGIN_LABELS = {
  evidence_policy: 'Bộ quy tắc dựa trên bằng chứng (tất định — không qua LLM)',
  policy_fallback: 'Chính sách dự phòng (tất định)',
  ollama: 'Mô hình AI (đã kiểm tra schema & bằng chứng)',
  exact_cache: 'Bộ nhớ đệm phân tích (đã xác thực trước đó)',
  policy_engine: 'Policy Engine (tự động theo ngưỡng)',
};

export const POLICY_DECISION_LABELS = {
  ALLOW_AUTOMATIC: 'Cho phép tự động',
  REQUIRE_APPROVAL: 'Yêu cầu phê duyệt của quản trị/operator',
  REQUIRE_MORE_EVIDENCE: 'Cần thu thập thêm bằng chứng',
  DENY: 'Chính sách từ chối',
};

export const AUDIT_EVENT_LABELS = {
  proposed: 'Đã tạo đề xuất',
  pending_approval: 'Chờ phê duyệt',
  approved: 'Đã phê duyệt',
  rejected: 'Đã từ chối',
  dispatched: 'Đã phát lệnh',
  executing: 'Đang thực thi',
  verifying: 'Đang xác minh',
  executed: 'Đã thực thi tại điểm cuối',
  succeeded: 'Xác minh thành công',
  partial: 'Hoàn thành một phần',
  failed: 'Thất bại',
  expired: 'Hết hiệu lực TTL',
  rolled_back: 'Đã hoàn tác',
  rollback_failed: 'Hoàn tác thất bại',
  created: 'Đã tạo lệnh',
  applied: 'Đã áp dụng',
  undo_requested: 'Yêu cầu hoàn tác',
  undone: 'Đã hoàn tác',
  auto_undone: 'Tự động hoàn tác (hết TTL)',
};

export const VERIFICATION_METHOD_LABELS = {
  authenticated_network_snapshot: 'Đối chiếu snapshot mạng từ Agent đã xác thực',
  application_lease_and_http_receipt: 'Đối chiếu lease ứng dụng và phiếu phản hồi HTTP',
  targeted_session_rejection: 'Xác nhận từ chối cookie phiên mục tiêu (HTTP 401)',
  persisted_incident_note: 'Xác nhận đã lưu ghi chú khắc phục trong cơ sở dữ liệu',
  time_bounded_http_query: 'Truy vấn nhật ký HTTP trong cửa sổ thời gian giới hạn',
};

export const ACTOR_LABELS = {
  policy: 'Response Policy Engine',
  manager: 'LARP Manager',
  lab_waf: 'Bộ điều phối Flask HTTP/WAF',
  policy_engine: 'Policy Engine',
};

export function translateActor(actor) {
  if (!actor) return 'Hệ thống';
  return ACTOR_LABELS[actor] || actor;
}

export function translateMissingEvidence(item) {
  const map = {
    'Verified application-side credential mismatch':
      'Chưa xác minh được liệu có lần đăng nhập thành công bất thường nào hay không.',
    'Verified enforcement point':
      'Chưa có điểm thực thi ứng dụng (HTTP/WAF) hoặc phiếu peer trực tiếp để chặn tại lớp ứng dụng.',
  };
  return map[item] || item;
}

export function getActionMeta(actionType) {
  return (
    ACTION_META[actionType] || {
      title: actionType ? actionType.replaceAll('_', ' ') : 'Hành động ứng phó',
      category: 'investigation',
      categoryLabel: 'Ứng phó',
      executorLabel: 'Hệ thống LARP',
      enforcementLayer: 'Manager / Endpoint',
      isMitigation: false,
      successHeadline: 'Đã hoàn tất hành động',
      successExplanation: 'Hành động đã được hệ thống ghi nhận hoàn tất.',
    }
  );
}

export function translateClassification(cls) {
  if (!cls) return 'Chưa phân loại';
  return CLASSIFICATION_LABELS[cls] || cls.replaceAll('_', ' ');
}

export function translateSeverity(severity) {
  const key = String(severity || 'medium').toLowerCase();
  return SEVERITY_META[key] || SEVERITY_META.medium;
}

export function translateIncidentStatus(status) {
  const key = String(status || 'open').toLowerCase();
  return INCIDENT_STATUS_LABELS[key] || status;
}

export function translateActivity(activity) {
  const key = String(activity || 'historical').toLowerCase();
  return ACTIVITY_LABELS[key] || activity;
}

export function translateTimelineEventType(type) {
  const map = {
    process_spawn: 'Khởi chạy tiến trình',
    process_observed: 'Quan sát tiến trình',
    network: 'Kết nối mạng',
    network_connection: 'Kết nối mạng',
    rule_trigger: 'Kích hoạt luật phát hiện',
    action: 'Hành động ứng phó',
    ai_analysis: 'Phân tích AI',
    incident_created: 'Tạo sự cố',
    http_observed: 'Quan sát HTTP',
    auth_failure: 'Đăng nhập thất bại',
  };
  return map[type] || (type ? type.replaceAll('_', ' ') : 'Sự kiện');
}

