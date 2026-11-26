import React, { useMemo, useState } from 'react';
import { FiGlobe, FiLock, FiActivity, FiCpu, FiChevronDown, FiChevronUp, FiCopy } from 'react-icons/fi';
import toast from 'react-hot-toast';
import { formatDateTimeVN, formatDateTimeUTC, shortenId } from '../../i18n/viVN';

const TAB_ITEMS = [
  { id: 'http', label: 'HTTP', icon: FiGlobe },
  { id: 'auth', label: 'Xác thực', icon: FiLock },
  { id: 'network', label: 'Mạng (Flows)', icon: FiActivity },
  { id: 'processes', label: 'Tiến trình', icon: FiCpu },
];

function formatRange(timestamps) {
  const valid = timestamps.filter(Boolean).map((t) => new Date(t)).filter((d) => !Number.isNaN(d.getTime()));
  if (!valid.length) return 'Chưa có mốc thời gian';
  valid.sort((a, b) => a - b);
  const first = formatDateTimeVN(valid[0]);
  const last = formatDateTimeVN(valid[valid.length - 1]);
  return first === last ? first : `${first} → ${last}`;
}

export default function EvidenceExplorer({
  relatedRecords = null,
  observedFacts = [],
  behavior = null,
  snapshotTimestamp = null,
  agentId = '',
}) {
  const [activeTab, setActiveTab] = useState('http');
  const [showRawJson, setShowRawJson] = useState(false);

  const summary = useMemo(() => {
    const httpRows = Array.isArray(relatedRecords?.http) ? relatedRecords.http : [];
    const authRows = Array.isArray(relatedRecords?.authentication) ? relatedRecords.authentication : [];
    const flowRows = Array.isArray(relatedRecords?.flows) ? relatedRecords.flows : [];
    const procRows = Array.isArray(relatedRecords?.process_metadata_in_window)
      ? relatedRecords.process_metadata_in_window
      : [];

    // HTTP metrics
    let getCount = 0;
    let postCount = 0;
    const statusCounts = {};
    const httpTimes = [];
    for (const r of httpRows) {
      const m = String(r.method || '').toUpperCase();
      if (m === 'GET') getCount++;
      if (m === 'POST') postCount++;
      const code = r.status_code ?? r.http_status;
      if (code != null) statusCounts[code] = (statusCounts[code] || 0) + 1;
      if (r.timestamp) httpTimes.push(r.timestamp);
    }
    if (!httpRows.length && observedFacts.length) {
      for (const f of observedFacts) {
        const m = String(f.method || '').toUpperCase();
        if (m === 'GET') getCount++;
        if (m === 'POST') postCount++;
        if (f.http_status != null) statusCounts[f.http_status] = (statusCounts[f.http_status] || 0) + 1;
        if (f.observed_at) httpTimes.push(f.observed_at);
      }
    }

    // Auth metrics
    const authFailed = authRows.length
      ? authRows.filter((a) => String(a.status).toLowerCase() === 'failed').length
      : (behavior?.failed_attempts ?? 0);
    const authSuccess = authRows.length
      ? authRows.filter((a) => String(a.status).toLowerCase() === 'success').length
      : (behavior?.successful_attempts ?? 0);
    const authTimes = authRows.map((a) => a.timestamp).filter(Boolean);
    if (!authTimes.length) {
      if (behavior?.first_attempt_at) authTimes.push(behavior.first_attempt_at);
      if (behavior?.last_attempt_at) authTimes.push(behavior.last_attempt_at);
    }

    // Network metrics
    const protocolCounts = {};
    let pidLinkedCount = 0;
    const flowTimes = [];
    for (const f of flowRows) {
      const proto = String(f.protocol || 'TCP').toUpperCase();
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
      if (f.pid != null) pidLinkedCount++;
      if (f.start_time || f.timestamp) flowTimes.push(f.start_time || f.timestamp);
    }

    const sourceIp =
      behavior?.source_ip ||
      observedFacts.find((f) => f.source_ip)?.source_ip ||
      'Không rõ';

    return {
      httpRows,
      httpTotal: httpRows.length || observedFacts.length,
      getCount,
      postCount,
      statusCounts,
      httpRange: formatRange(httpTimes),
      sourceIp,
      service: behavior?.service || 'flask_web',
      authRows,
      authFailed,
      authSuccess,
      username: behavior?.username || null,
      authRange: formatRange(authTimes),
      flowRows,
      protocolCounts,
      pidLinkedCount,
      flowRange: formatRange(flowTimes),
      procRows,
    };
  }, [relatedRecords, observedFacts, behavior]);

  const copyText = async (val, label) => {
    try {
      await navigator.clipboard.writeText(String(val));
      toast.success(`Đã sao chép ${label}`);
    } catch {
      toast.error('Không thể sao chép vào clipboard');
    }
  };

  return (
    <div
      style={{
        background: 'rgba(15, 23, 42, 0.45)',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        padding: '0.85rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.75rem',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Trình khám phá bằng chứng thu thập (Evidence Explorer)
        </div>
        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
          {TAB_ITEMS.map(({ id, label, icon: Icon }) => {
            const active = activeTab === id;
            const count =
              id === 'http'
                ? summary.httpTotal
                : id === 'auth'
                ? summary.authRows.length || (summary.authFailed + summary.authSuccess)
                : id === 'network'
                ? summary.flowRows.length
                : summary.procRows.length;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                  padding: '0.3rem 0.65rem',
                  borderRadius: '6px',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: active ? '1px solid var(--primary)' : '1px solid var(--border)',
                  background: active ? 'rgba(59, 130, 246, 0.16)' : 'var(--bg-secondary)',
                  color: active ? 'var(--primary)' : 'var(--text-secondary)',
                }}
              >
                <Icon size={12} />
                {label}
                <span style={{ opacity: 0.8 }}>({count})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* HTTP Tab */}
      {activeTab === 'http' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))', gap: '0.5rem' }}>
            <MetricBox label="Tổng request" value={summary.httpTotal} />
            <MetricBox label="GET / POST" value={`${summary.getCount} / ${summary.postCount}`} />
            <MetricBox label="IP nguồn" value={summary.sourceIp} mono />
            <MetricBox label="Dịch vụ đích" value={summary.service} mono />
            <MetricBox
              label="Phân bố mã HTTP"
              value={
                Object.keys(summary.statusCounts).length
                  ? Object.entries(summary.statusCounts).map(([code, cnt]) => `${code}: ${cnt}`).join(' · ')
                  : 'Chưa có'
              }
            />
            <MetricBox label="Khoảng thời gian (VN)" value={summary.httpRange} />
          </div>
          {summary.httpRows.length > 0 ? (
            <RecordTable
              headers={['Mã bản ghi', 'Phương thức', 'Mã HTTP', 'Thời điểm (Asia/Ho_Chi_Minh)']}
              rows={summary.httpRows.slice(0, 12).map((r) => [
                <CopyableId key={r.id} value={r.id} onCopy={() => copyText(r.id, 'HTTP Event ID')} />,
                r.method || '—',
                r.status_code ?? '—',
                <span title={formatDateTimeUTC(r.timestamp)}>{formatDateTimeVN(r.timestamp)}</span>,
              ])}
            />
          ) : (
            <EmptyNote text="Không có bản ghi HTTP bổ sung ngoài bằng chứng ban đầu trong cửa sổ thu thập." />
          )}
        </div>
      )}

      {/* Auth Tab */}
      {activeTab === 'auth' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: '0.5rem' }}>
            <MetricBox label="Đăng nhập thất bại" value={summary.authFailed} color="#ef4444" />
            <MetricBox label="Đăng nhập thành công" value={summary.authSuccess} color={summary.authSuccess > 0 ? '#f59e0b' : '#10b981'} />
            <MetricBox label="Tài khoản mục tiêu" value={summary.username || 'Không xác định / Nhiều tài khoản'} />
            <MetricBox label="IP nguồn" value={summary.sourceIp} mono />
            <MetricBox label="Khoảng thời gian (VN)" value={summary.authRange} />
          </div>
          {summary.authRows.length > 0 ? (
            <RecordTable
              headers={['Mã sự kiện', 'Kết quả', 'Thời điểm (Asia/Ho_Chi_Minh)']}
              rows={summary.authRows.slice(0, 12).map((r) => [
                <CopyableId key={r.id} value={r.id} onCopy={() => copyText(r.id, 'Auth Event ID')} />,
                r.status === 'failed' ? 'Thất bại' : r.status === 'success' ? 'Thành công' : r.status,
                <span title={formatDateTimeUTC(r.timestamp)}>{formatDateTimeVN(r.timestamp)}</span>,
              ])}
            />
          ) : (
            <EmptyNote text="Không có bản ghi xác thực mới phát sinh trong cửa sổ thu thập." />
          )}
        </div>
      )}

      {/* Network Tab */}
      {activeTab === 'network' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: '0.5rem' }}>
            <MetricBox label="Số luồng mạng (Flows)" value={summary.flowRows.length} />
            <MetricBox
              label="Giao thức"
              value={
                Object.keys(summary.protocolCounts).length
                  ? Object.entries(summary.protocolCounts).map(([p, c]) => `${p}: ${c}`).join(' · ')
                  : 'Chưa có'
              }
            />
            <MetricBox
              label="Tương quan PID"
              value={
                summary.flowRows.length === 0
                  ? 'Không có flow'
                  : summary.pidLinkedCount > 0
                  ? `${summary.pidLinkedCount}/${summary.flowRows.length} flow có PID`
                  : 'Chưa xác định PID trên flow'
              }
              color={summary.pidLinkedCount === 0 && summary.flowRows.length > 0 ? '#f59e0b' : undefined}
            />
            <MetricBox label="Thời điểm snapshot" value={snapshotTimestamp ? formatDateTimeVN(snapshotTimestamp) : summary.flowRange} />
          </div>
          {summary.flowRows.length > 0 ? (
            <RecordTable
              headers={['Mã Flow', 'Giao thức', 'Nguồn / Đích', 'PID', 'Thời điểm (VN)']}
              rows={summary.flowRows.slice(0, 12).map((f) => [
                <CopyableId key={f.id} value={f.id} onCopy={() => copyText(f.id, 'Flow ID')} />,
                f.protocol || 'TCP',
                f.src_ip || f.dst_ip
                  ? `${f.src_ip || '?'}:${f.src_port || '*'} → ${f.dst_ip || '?'}:${f.dst_port || '*'}`
                  : `Agent ${agentId || 'endpoint'}`,
                f.pid != null ? String(f.pid) : 'Chưa xác định',
                <span title={formatDateTimeUTC(f.start_time || f.timestamp)}>
                  {formatDateTimeVN(f.start_time || f.timestamp)}
                </span>,
              ])}
            />
          ) : (
            <EmptyNote text="Không ghi nhận network flow nào liên kết tới IP nguồn trong cửa sổ ±2 phút." />
          )}
        </div>
      )}

      {/* Processes Tab */}
      {activeTab === 'processes' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.5rem' }}>
            <MetricBox label="Tiến trình liên quan" value={summary.procRows.length} />
            <MetricBox
              label="Trạng thái"
              value={summary.procRows.length ? 'Có metadata tiến trình' : 'Không có tiến trình trong cửa sổ thu thập'}
            />
          </div>
          {summary.procRows.length > 0 ? (
            <RecordTable
              headers={['PID', 'Parent PID', 'Tên tiến trình', 'Đường dẫn / Lệnh', 'Thời điểm (VN)']}
              rows={summary.procRows.slice(0, 12).map((p) => [
                p.pid ?? '—',
                p.parent_pid ?? p.ppid ?? '—',
                p.name || 'Không rõ',
                p.cmdline || p.exe_path || p.exe || 'Không có thông tin',
                formatDateTimeVN(p.created_at),
              ])}
            />
          ) : (
            <EmptyNote text="Không có dữ liệu tiến trình (process metadata) trong cửa sổ thu thập này." />
          )}
        </div>
      )}

      {/* Collapsed Raw Technical JSON */}
      {relatedRecords && (
        <div>
          <button
            type="button"
            onClick={() => setShowRawJson((v) => !v)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-tertiary)',
              fontSize: '0.75rem',
              cursor: 'pointer',
              padding: 0,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.3rem',
            }}
          >
            {showRawJson ? <FiChevronUp size={13} /> : <FiChevronDown size={13} />}
            {showRawJson ? 'Ẩn dữ liệu JSON kỹ thuật' : 'Xem dữ liệu JSON kỹ thuật (nâng cao)'}
          </button>
          {showRawJson && (
            <pre
              style={{
                marginTop: '0.45rem',
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                padding: '0.6rem',
                borderRadius: '6px',
                overflowX: 'auto',
                maxHeight: '200px',
                fontSize: '0.72rem',
                color: 'var(--text-secondary)',
              }}
            >
              {JSON.stringify(relatedRecords, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function MetricBox({ label, value, mono = false, color }) {
  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: '6px',
        padding: '0.45rem 0.65rem',
      }}
    >
      <div style={{ fontSize: '0.7rem', color: 'var(--text-tertiary)' }}>{label}</div>
      <div
        style={{
          fontSize: '0.82rem',
          fontWeight: 700,
          color: color || 'var(--text-primary)',
          fontFamily: mono ? 'monospace' : 'inherit',
          marginTop: '0.15rem',
          wordBreak: 'break-word',
        }}
      >
        {value}
      </div>
    </div>
  );
}

function RecordTable({ headers, rows }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: '6px' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem' }}>
        <thead>
          <tr style={{ background: 'rgba(255, 255, 255, 0.03)', textAlign: 'left' }}>
            {headers.map((h) => (
              <th key={h} style={{ padding: '0.4rem 0.6rem', color: 'var(--text-tertiary)', borderBottom: '1px solid var(--border)' }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cells, idx) => (
            <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              {cells.map((cell, cIdx) => (
                <td key={cIdx} style={{ padding: '0.4rem 0.6rem', color: 'var(--text-secondary)', fontFamily: cIdx === 0 ? 'monospace' : 'inherit' }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CopyableId({ value, onCopy }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }} title={value}>
      <span>{shortenId(value)}</span>
      <button
        type="button"
        onClick={onCopy}
        title={`Sao chép ${value}`}
        style={{ background: 'none', border: 'none', color: 'var(--text-tertiary)', cursor: 'pointer', padding: 0, display: 'inline-flex' }}
      >
        <FiCopy size={11} />
      </button>
    </span>
  );
}

function EmptyNote({ text }) {
  return (
    <div style={{ padding: '0.65rem 0.85rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', color: 'var(--text-tertiary)', fontSize: '0.78rem', fontStyle: 'italic' }}>
      {text}
    </div>
  );
}

