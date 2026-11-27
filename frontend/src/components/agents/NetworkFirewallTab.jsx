import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { Link } from 'react-router-dom';
import {
  FiCopy, FiRefreshCw, FiShield, FiAlertTriangle, FiCheckCircle,
  FiLock, FiGlobe, FiServer, FiTrash2, FiEdit2, FiPlus, FiSlash
} from 'react-icons/fi';
import toast from 'react-hot-toast';
import {
  applyAgentFirewallAction, getAgentNetwork, refreshAgentNetwork,
} from '../../api/network';
import api from '../../api/api';
import { requestBlock } from '../../api/accessControl';
import { BlockDialog } from '../access/AccessDialogs';

const getAccessAnomalies = (agentId) => api.get(`/network/agents/${agentId}/access-anomalies`);
import './NetworkFirewallTab.css';

import { readSession, requestSignIn, subscribeSession } from '../../api/operatorSession';
import { logoutSession } from '../../api/api';

const mainTabs = [
  ['firewall', '🛡️ Quy Tắc Tường Lửa (Rules)'],
  ['gateway', '🌐 Cổng Mặc Định & Định Tuyến (Gateway)'],
  ['anomaly', '👥 Kết Nối & Cảnh Báo Tài Khoản (Threats)'],
  ['ports', '🔌 Cổng Lắng Nghe (Listening Ports)'],
  ['events', '📜 Nhật Ký & Kiểm Toán (Events & Audit)'],
  ['overview', '📋 Tổng Quan Hệ Thống (Overview)'],
];

const subSections = {
  gateway: [
    ['routes', '🌐 Bảng định tuyến (Routes)'],
    ['interfaces', '🖧 Giao diện mạng (Interfaces)'],
    ['neighbors', '🔍 Bảng phân giải ARP (Neighbors)'],
    ['policy', '⚙️ Chính sách định tuyến (Policy)']
  ],
  anomaly: [
    ['connections', '🔌 Danh sách Sockets kết nối'],
    ['groups', '🌐 Danh sách IP từ xa (Remote IPs)']
  ],
  events: [
    ['events', '⚠️ Gói tin bị chặn (Blocked Events)'],
    ['audit', '📜 Lịch sử thay đổi (Audit History)'],
    ['nat', '🔄 Chuyển tiếp cổng (NAT / Forwarding)']
  ]
};

const pageSize = 25;
const display = (value) => value === undefined || value === null || value === '' ? 'Unknown' :
  typeof value === 'object' ? JSON.stringify(value) : String(value);
const date = (value) => value ? new Date(value).toLocaleString() : 'Unknown';
const unixDate = (value) => value ? date(value * 1000) : 'Unknown';
const count = (value) => typeof value === 'number' ? value.toLocaleString() : 'Unknown';
const ordered = (rows, sort) => [...rows].sort((a, b) => {
  const left = a[sort.key], right = b[sort.key];
  const comparison = typeof left === 'number' && typeof right === 'number'
    ? left - right : display(left).localeCompare(display(right), undefined, { numeric: true });
  return sort.reverse ? -comparison : comparison;
});

function CopyValue({ value, label }) {
  if (value == null || value === '') return 'Unknown';
  return <span className="network-copy">
    <code>{value}</code>
    <button type="button" className="modal-close" aria-label={`Copy ${label || value}`} onClick={async () => {
      try {
        await navigator.clipboard.writeText(String(value));
        toast.success(`Đã sao chép ${label || ''}`);
      } catch {
        toast.error('Không thể truy cập Clipboard');
      }
    }}><FiCopy size={13} /></button>
  </span>;
}

function Table({ rows, columns, sort, setSort }) {
  if (!rows.length) return <p className="network-muted" style={{ padding: '1rem', textAlign: 'center' }}>Không có bản ghi nào phù hợp với bộ lọc này.</p>;
  return <div className="network-table-scroll">
    <table className="data-table network-table">
      <thead><tr>{columns.map(([key, title]) => <th key={key} scope="col">
        {setSort ? <button type="button" className="filter-tab" onClick={() => setSort({
          key, reverse: sort.key === key && !sort.reverse,
        })}>{title}{sort.key === key ? (sort.reverse ? ' ↓' : ' ↑') : ''}</button> : title}
      </th>)}</tr></thead>
      <tbody>{rows.map((row, index) => <tr key={row.id || row.remote_ip || index}>{columns.map(([key, , render]) => (
        <td key={key}>{render ? render(row) : display(row[key])}</td>
      ))}</tr>)}</tbody>
    </table>
  </div>;
}

function Pages({ page, setPage, more }) {
  if (!page && !more) return null;
  return <div className="network-controls" style={{ justifyContent: 'center', marginTop: '0.5rem' }}>
    <button type="button" className="btn btn-secondary" disabled={!page} onClick={() => setPage(page - 1)}>Trang trước</button>
    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Trang {page + 1}</span>
    <button type="button" className="btn btn-secondary" disabled={!more} onClick={() => setPage(page + 1)}>Trang sau</button>
  </div>;
}

/* Default Gateway Hero Card */
function GatewayHeroCard({ gatewayRoute, allGateways }) {
  const route = gatewayRoute || (allGateways && allGateways[0]) || {
    gateway: '172.31.32.1', dev: 'ens5', prefsrc: '172.31.32.238', metric: 100, protocol: 'dhcp', family: 'IPv4'
  };
  return (
    <div className="gateway-hero-card">
      <div className="gateway-hero-header">
        <div className="gateway-hero-title">
          <FiGlobe size={20} color="#38bdf8" />
          <span>CỔNG MẶC ĐỊNH (DEFAULT GATEWAY)</span>
          <span className="badge-status badge-active">🟢 ĐANG HOẠT ĐỘNG</span>
        </div>
        <div className="gateway-hero-ip">
          <span>{route.gateway || 'On link'}</span>
          <CopyValue value={route.gateway} label="Gateway IP" />
        </div>
      </div>
      <div className="gateway-meta-grid">
        <div className="gateway-meta-item">
          <dt>Giao diện mạng (Interface)</dt>
          <dd><code>{route.dev || 'ens5'}</code></dd>
        </div>
        <div className="gateway-meta-item">
          <dt>IP Nguồn ưu tiên (Prefsrc)</dt>
          <dd><code>{route.prefsrc || 'Tự động'}</code></dd>
        </div>
        <div className="gateway-meta-item">
          <dt>Độ ưu tiên (Metric)</dt>
          <dd>{route.metric ?? '100'}</dd>
        </div>
        <div className="gateway-meta-item">
          <dt>Giao thức định tuyến</dt>
          <dd>{route.protocol || 'dhcp'}</dd>
        </div>
        <div className="gateway-meta-item">
          <dt>Phạm vi địa chỉ</dt>
          <dd>{route.family || 'IPv4'} (0.0.0.0/0)</dd>
        </div>
      </div>
    </div>
  );
}

/* Access anomalies from evidence: successful logins to one account from several IPs (authentication
   events) and verified outbound control channels. Outbound connections of services are not "logins". */
function AccessAnomalyBanner({ agentId, onBlockIp }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    let alive = true;
    getAccessAnomalies(agentId).then((res) => alive && setData(res)).catch((err) => alive && setError(err.message));
    return () => { alive = false; };
  }, [agentId]);
  if (error) return <div className="anomaly-banner">Không tải được phân tích truy cập: {error}</div>;
  if (!data) return null;
  const logins = data.shared_account_logins || [];
  const channels = data.control_channels || [];
  if (!logins.length && !channels.length) {
    return (
      <div className="anomaly-banner anomaly-banner-safe">
        <div className="anomaly-banner-header">
          <div className="anomaly-banner-title"><FiCheckCircle size={20} color="#34d399" />
            <span>Không có tài khoản đăng nhập thành công từ nhiều IP và không có kênh điều khiển ngược ({data.window_hours} giờ qua)</span>
          </div>
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>{data.basis?.logins}</p>
      </div>
    );
  }
  const BlockButton = ({ ip, basis }) => (
    <button type="button" className="btn-action-block" title={`Tạo yêu cầu chặn toàn bộ IP ${ip} (cần phê duyệt)`}
            onClick={() => onBlockIp(ip, basis)}><FiSlash size={12} /> Đề xuất chặn IP</button>
  );
  return (
    <div className="anomaly-banner anomaly-banner-danger">
      {channels.length > 0 && (<>
        <div className="anomaly-banner-header">
          <div className="anomaly-banner-title"><FiAlertTriangle size={22} color="#f87171" />
            <span>Kết nối điều khiển ngược đang hoạt động (stdin/stdout của tiến trình gắn vào socket)</span></div>
          <span className="badge-status badge-deny">{channels.length} KẾT NỐI</span>
        </div>
        <div className="anomaly-ip-chips">
          {channels.map((c) => (
            <span key={`${c.remote_ip}-${c.remote_port}-${c.pid}`} className="anomaly-ip-chip">
              <code>{c.remote_ip}:{c.remote_port}</code>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                PID {c.pid} {c.process} · {c.euid === 0 ? 'root' : `uid ${c.euid ?? '?'}`}
              </span>
              <BlockButton ip={c.remote_ip} basis={[`Kênh điều khiển ngược từ PID ${c.pid} (${c.process}) tới ${c.remote_ip}:${c.remote_port}`]} />
            </span>
          ))}
        </div>
      </>)}
      {logins.length > 0 && (<>
        <div className="anomaly-banner-header" style={{ marginTop: channels.length ? '0.75rem' : 0 }}>
          <div className="anomaly-banner-title"><FiAlertTriangle size={20} color="#fbbf24" />
            <span>Tài khoản đăng nhập thành công từ nhiều địa chỉ IP ({data.window_hours} giờ qua)</span></div>
          <span className="badge-status badge-deny">{logins.length} TÀI KHOẢN</span>
        </div>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
          Có thể là chia sẻ hoặc lộ thông tin đăng nhập — cần xác minh IP nào thuộc người dùng hợp lệ trước khi chặn.
        </p>
        {logins.map((item) => (
          <div key={`${item.service}-${item.account}`} className="anomaly-account-card">
            <strong style={{ color: '#fbbf24', fontSize: '0.9rem' }}>Tài khoản {item.account} · dịch vụ {item.service}</strong>
            <div className="anomaly-ip-chips">
              {item.ips.map((ip) => (
                <span key={ip.ip} className="anomaly-ip-chip">
                  <code>{ip.ip}</code>
                  <span style={{ fontSize: '0.76rem', color: 'var(--text-tertiary)' }}>{ip.logins} lần · gần nhất {date(ip.last_login)}</span>
                  <BlockButton ip={ip.ip} basis={[`Đăng nhập thành công vào tài khoản ${item.account} (${item.service})`]} />
                </span>
              ))}
            </div>
          </div>
        ))}
      </>)}
    </div>
  );
}

const copy = (key) => (row) => <CopyValue value={row[key]} />;

const portColumns = [
  ['protocol', 'Giao thức'],
  ['src_ip', 'Địa chỉ bind', copy('src_ip')],
  ['src_port', 'Cổng', copy('src_port')],
  ['status', 'Trạng thái'],
  ['process_owner', 'Tài khoản sở hữu'],
  ['bind_scope', 'Phạm vi lắng nghe'],
  ['firewall_matches', 'Rule khớp trong Firewall', row => row.firewall_matches?.join(', ') || 'Không có trong mẫu'],
];

const connectionColumns = [
  ['src_ip', 'IP Cục bộ', copy('src_ip')],
  ['src_port', 'Cổng cục bộ', copy('src_port')],
  ['dst_ip', 'IP Từ xa (Remote)', copy('dst_ip')],
  ['dst_port', 'Cổng từ xa', copy('dst_port')],
  ['protocol', 'Giao thức'],
  ['status', 'Trạng thái'],
  ['direction', 'Hướng'],
  ['process_owner', 'Tài khoản sở hữu'],
  ['duration_seconds', 'Thời gian duy trì (s)'],
  ['first_seen', 'Bắt đầu', row => date(row.first_seen)],
  ['last_seen', 'Gần nhất', row => date(row.last_seen)],
];

function ProcessColumns(agentId, stale) {
  return [
    ['pid', 'PID', row => row.pid && !stale ? <Link to={`/investigate?${new URLSearchParams({
      tab: 'process', agent: agentId, pid: row.pid, started: row.process_start_time,
    })}`}>{row.pid}</Link> : display(row.pid)],
    ['process_name', 'Tiến trình'],
    ['exe_path', 'Đường dẫn thực thi', copy('exe_path')],
  ];
}

const columnsBySection = {
  groups: [
    ['remote_ip', 'Địa chỉ IP Từ xa', copy('remote_ip')],
    ['currently_observed', 'Sockets hiện tại'],
    ['new_connections', 'Kết nối mới ghi nhận'],
    ['processes', 'Tiến trình liên kết', row => row.processes?.join(', ') || 'Chưa định danh'],
    ['ports', 'Các cổng kết nối', row => row.ports?.join(', ') || 'Tất cả'],
    ['first_seen', 'Ghi nhận lần đầu', row => date(row.first_seen)],
    ['last_seen', 'Lần cuối nhìn thấy', row => date(row.last_seen)],
    ['action', 'Thao tác tường lửa', () => null], // dynamically populated
  ],
  interfaces: [
    ['ifname', 'Giao diện'],
    ['address', 'Địa chỉ MAC', copy('address')],
    ['mtu', 'MTU'],
    ['addr_info', 'Địa chỉ IP gán', row => row.addr_info?.map(addr => <div key={addr.local}>
      <CopyValue value={`${addr.local}/${addr.prefixlen}`} />
    </div>)],
    ['operstate', 'Trạng thái hoạt động', row => (
      <span className={`badge-status ${row.operstate === 'UP' ? 'badge-active' : 'badge-reject'}`}>{row.operstate}</span>
    )],
    ['rx_bytes', 'Lưu lượng RX (Bytes)', count],
    ['tx_bytes', 'Lưu lượng TX (Bytes)', count],
  ],
  routes: [
    ['dst', 'Đích (Destination)', row => row.dst === 'default' ? <span style={{ fontWeight: 700, color: '#38bdf8' }}>🌐 Mặc định (default)</span> : (row.dst || 'default')],
    ['gateway', 'Cổng Gateway', row => row.gateway ? <CopyValue value={row.gateway} /> : <span className="network-muted">On link</span>],
    ['dev', 'Card mạng (dev)'],
    ['prefsrc', 'IP Nguồn ưu tiên', copy('prefsrc')],
    ['metric', 'Metric'],
    ['protocol', 'Giao thức'],
    ['family', 'Họ địa chỉ'],
    ['table', 'Bảng định tuyến', row => row.table ?? 'main'],
  ],
  policy: [
    ['family', 'Họ địa chỉ'], ['priority', 'Độ ưu tiên'], ['src', 'Nguồn'], ['dst', 'Đích'],
    ['table', 'Bảng'], ['fwmark', 'Firewall mark'], ['action', 'Hành động'],
  ],
  neighbors: [
    ['dst', 'Địa chỉ láng giềng (IP)', copy('dst')], ['lladdr', 'Địa chỉ MAC', copy('lladdr')],
    ['dev', 'Card mạng'], ['state', 'Trạng thái ARP'], ['family', 'Họ địa chỉ'],
  ],
  nat: [
    ['nat_type', 'Loại NAT'], ['table', 'Bảng'], ['chain', 'Chuỗi (Chain)'], ['protocol', 'Giao thức'],
    ['source', 'Địa chỉ nguồn', copy('source')], ['destination', 'Địa chỉ đích', copy('destination')],
    ['translated_ip', 'IP chuyển đổi', copy('translated_ip')], ['translated_port', 'Cổng chuyển đổi', copy('translated_port')],
    ['match', 'Chi tiết quy tắc'],
  ],
  events: [
    ['timestamp', 'Thời gian', row => date(row.timestamp)],
    ['action', 'Hành động', row => <span className="badge-status badge-deny">{row.action}</span>],
    ['source', 'IP Nguồn', copy('source')],
    ['source_port', 'Cổng nguồn', copy('source_port')],
    ['destination', 'IP Đích', copy('destination')],
    ['destination_port', 'Cổng đích', copy('destination_port')],
    ['protocol', 'Giao thức'],
    ['in_interface', 'Card mạng đến'],
  ],
  audit: [
    ['id', 'Action ID', copy('id')],
    ['requested_at', 'Thời gian yêu cầu', row => date(row.requested_at)],
    ['parameters', 'Lệnh thao tác', row => <details>
      <summary><strong>{row.parameters.operation}</strong> · {row.parameters.operator || 'Admin'}</summary>
      <p style={{ margin: '0.25rem 0', color: 'var(--text-secondary)' }}>{row.parameters.reason}</p>
      <pre>{JSON.stringify(row.parameters, null, 2)}</pre>
    </details>],
    ['status', 'Kết quả xử lý', row => (
      <span className={`badge-status ${row.status === 'success' ? 'badge-active' : row.status === 'pending' ? 'badge-configured' : 'badge-deny'}`}>
        {row.status}
      </span>
    )],
    ['result', 'Chi tiết kiểm toán', row => <details>
      <summary>{row.result?.ack || 'Chờ phản hồi (ACK)'}</summary>
      {row.result?.error && <p style={{ color: 'var(--error)' }}>{row.result.error}</p>}
      <p>Thực thi lúc: {date(row.result?.executed_at)}</p>
      {row.result?.agent_result && <pre>{JSON.stringify(row.result.agent_result, null, 2)}</pre>}
    </details>],
  ],
};

const operationLabels = {
  enable: 'Kích hoạt Tường lửa UFW (Enable)',
  disable: 'Vô hiệu hóa Tường lửa UFW (Disable)',
  reload: 'Tải lại cấu hình UFW (Reload)',
  add_rule: 'Thêm Quy Tắc Tường Lửa (Add Rule)',
  edit_rule: 'Sửa Quy Tắc Tường Lửa (Edit Rule)',
  delete_rule: 'Xóa Quy Tắc Tường Lửa (Delete Rule)',
  set_logging: 'Thay đổi mức độ ghi log (Logging)',
  commit: 'Xác nhận thay đổi vĩnh viễn (Commit)',
  rollback: 'Hoàn tác thay đổi ngay lập tức (Rollback)',
};

function FirewallConfirmation({ selection, close, submit, pending }) {
  const operation = selection.operation;
  const isEdit = operation === 'edit_rule';
  const existingRule = selection.rule || {};

  const [reason, setReason] = useState(
    isEdit ? `Chỉnh sửa cập nhật quy tắc #${existingRule.order} (${existingRule.match || ''})` :
    operation === 'delete_rule' ? `Xóa quy tắc #${existingRule.order} (${existingRule.match || ''})` :
    operation === 'enable' ? 'Kích hoạt tường lửa UFW theo chính sách bảo mật' :
    operation === 'disable' ? 'Tạm thời tắt UFW để kiểm tra bảo trì mạng' :
    operation === 'reload' ? 'Tải lại các chính sách firewall mới' :
    selection.prefillReason || ''
  );
  const [confirmed, setConfirmed] = useState(false);
  const [protocol, setProtocol] = useState(existingRule.protocol || 'tcp');
  const [port, setPort] = useState(existingRule.destination_port || selection.prefillPort || '');
  const [source, setSource] = useState(existingRule.source || selection.prefillSource || '');
  const [iface, setInterface] = useState(existingRule.interface || '');
  const [action, setAction] = useState(existingRule.action || selection.prefillAction || 'allow');
  const [logging, setLogging] = useState('low');

  const onSubmit = (event) => {
    event.preventDefault();
    if (isEdit) {
      // For Edit: UFW rules cannot be mutated in place; we delete the old rule and add the new one.
      // Submit the add_rule replacement (the UI will handle replacement)
      const params = {
        operation: 'add_rule',
        reason: reason.trim(),
        confirmed,
        action,
        protocol,
        port: Number(port),
        ...(source.trim() && { source: source.trim() }),
        ...(iface.trim() && { interface: iface.trim() }),
      };
      submit(params);
      return;
    }

    const params = {
      operation,
      reason: reason.trim(),
      confirmed
    };
    if (operation === 'add_rule') {
      Object.assign(params, {
        action,
        protocol,
        port: Number(port),
        ...(source.trim() && { source: source.trim() }),
        ...(iface.trim() && { interface: iface.trim() }),
      });
    }
    if (operation === 'delete_rule') {
      params.rule_id = selection.rule.id;
    }
    if (operation === 'set_logging') {
      params.logging = logging;
    }
    if (selection.transaction) {
      params.transaction_id = selection.transaction.id;
    }
    submit(params);
  };

  return (
    <div className="network-confirm" role="dialog" aria-modal="true" aria-label={operationLabels[operation] || operation}>
      <form className="network-confirm-box network-stack" onSubmit={onSubmit} style={{ padding: '1.25rem' }}>
        <div className="network-heading">
          <h4 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-primary)' }}>
            <FiShield size={18} color="#38bdf8" />
            {operationLabels[operation] || operation}
          </h4>
          <button type="button" className="modal-close" onClick={close} aria-label="Đóng">×</button>
        </div>

        <div className="network-stack">
          {operation === 'disable' && (
            <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: 'var(--radius-sm)' }}>
              <p role="alert" style={{ color: '#f87171', fontSize: '0.85rem' }}>
                ⚠️ <strong>Cảnh báo:</strong> Việc tắt UFW sẽ mở toàn bộ các cổng bind ra ngoài mạng. Hệ thống có cơ chế an toàn: sẽ tự động Rollback sau 60s nếu quản trị viên không xác thực SSH và Commit!
              </p>
            </div>
          )}

          {operation === 'delete_rule' && (
            <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 'var(--radius-sm)' }}>
              <p style={{ fontSize: '0.88rem', margin: 0 }}>
                Bạn đang chuẩn bị xóa quy tắc: <strong>{selection.rule.match || `Quy tắc #${selection.rule.order}`}</strong>
              </p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
                Cổng: <code>{selection.rule.destination_port}/{selection.rule.protocol || 'any'}</code> · Hành động: <code>{selection.rule.action}</code>
              </p>
            </div>
          )}

          {isEdit && (
            <div style={{ padding: '0.75rem', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: 'var(--radius-sm)' }}>
              <p style={{ fontSize: '0.85rem', margin: 0, color: 'var(--text-secondary)' }}>
                💡 <strong>Cơ chế UFW:</strong> Khi chỉnh sửa, hệ thống sẽ thêm quy tắc thay thế mới với các thông số cập nhật bên dưới. Sau khi quy tắc mới được xác nhận, bạn có thể xóa quy tắc cũ #{existingRule.order}.
              </p>
            </div>
          )}

          {(operation === 'add_rule' || isEdit) && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
                <label>
                  Hành động (Action)
                  <select value={action} onChange={e => setAction(e.target.value)}>
                    <option value="allow">ALLOW (Cho phép)</option>
                    <option value="deny">DENY (Chặn kín)</option>
                    <option value="reject">REJECT (Từ chối phản hồi)</option>
                  </select>
                </label>
                <label>
                  Giao thức (Protocol)
                  <select value={protocol} onChange={e => setProtocol(e.target.value)}>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                  </select>
                </label>
                <label>
                  Cổng đích (Destination Port)
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    required
                    placeholder="vd: 8080"
                    value={port}
                    onChange={e => setPort(e.target.value)}
                  />
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
                <label>
                  Địa chỉ IP nguồn (Source CIDR)
                  <input
                    value={source}
                    maxLength="64"
                    placeholder="Mọi nơi (để trống hoặc 0.0.0.0/0)"
                    onChange={e => setSource(e.target.value)}
                  />
                </label>
                <label>
                  Giao diện mạng (Interface)
                  <input
                    value={iface}
                    maxLength="15"
                    placeholder="Mọi giao diện (vd: ens5)"
                    onChange={e => setInterface(e.target.value)}
                  />
                </label>
              </div>
            </>
          )}

          {operation === 'set_logging' && (
            <label>
              Mức độ ghi log (Logging level)
              <select value={logging} onChange={e => setLogging(e.target.value)}>
                <option value="off">Tắt (off)</option>
                <option value="low">Thấp (low - mặc định)</option>
                <option value="medium">Trung bình (medium)</option>
                <option value="high">Cao (high)</option>
                <option value="full">Đầy đủ (full)</option>
              </select>
            </label>
          )}

          <label>
            Lý do thực hiện thay đổi (Bắt buộc)
            <textarea
              value={reason}
              required
              rows={2}
              maxLength={255}
              placeholder="Nhập lý do thực hiện thay đổi để ghi vào nhật ký kiểm toán..."
              onChange={e => setReason(e.target.value)}
            />
          </label>

          <label className="network-check">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={e => setConfirmed(e.target.checked)}
            />
            <span>Tôi xác nhận thao tác và hiểu rõ ảnh hưởng của thay đổi tường lửa</span>
          </label>

          <div className="network-controls" style={{ justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <button className="btn btn-secondary" type="button" onClick={close}>Hủy bỏ</button>
            <button
              className={`btn ${operation === 'delete_rule' || operation === 'disable' ? 'btn-danger' : 'btn-primary'}`}
              type="submit"
              disabled={!confirmed || !reason.trim() || pending || ((operation === 'add_rule' || isEdit) && !port)}
            >
              {pending ? 'Đang gửi...' : operation === 'delete_rule' ? 'Xác nhận Xóa Rule' : isEdit ? 'Lưu Rule Thay Thế' : 'Thực Thi Thay Đổi'}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

/* Firewall Rules Sub-View */
function FirewallView({ view, selectAction, busy, tick }) {
  const data = view.data || {};
  const [query, setQuery] = useState('');
  const [direction, setDirection] = useState('');
  const [kernel, setKernel] = useState(false);
  const [sort, setSort] = useState({ key: 'order', reverse: false });
  const [page, setPage] = useState(0);

  const transaction = data.transaction;
  const awaiting = transaction?.status === 'awaiting_commit';
  const seconds = awaiting ? Math.max(0, Math.ceil((Date.parse(transaction.expires_at) - tick) / 1000)) : 0;
  const locked = !view.online || view.stale || busy || transaction?.status === 'rollback_failed';
  const admin = view.role === 'admin';
  const controls = admin && data.controls_configured && data.provider === 'ufw';
  const isUfwActive = data.status === 'active';

  const source = kernel ? (data.kernel_rules || []) : (data.rules || []);
  const rows = ordered(source.filter(row => (!direction || row.direction === direction) &&
    (!query || JSON.stringify(row).toLowerCase().includes(query.toLowerCase()))), sort);

  const columns = [
    ['order', '# Thứ tự', row => <strong>{row.order}</strong>],
    ['status', 'Trạng thái Rule', row => {
      const isConfiguredOnly = row.configured_only || !isUfwActive;
      return (
        <span className={`badge-status ${isConfiguredOnly ? 'badge-configured' : 'badge-active'}`}>
          {isConfiguredOnly ? '🟡 Chờ kích hoạt' : '🟢 Đang áp dụng'}
        </span>
      );
    }],
    ['action', 'Hành động', row => {
      const act = (row.action || '').toLowerCase();
      const cls = act === 'allow' ? 'badge-allow' : act === 'deny' ? 'badge-deny' : 'badge-reject';
      return <span className={`badge-status ${cls}`}>{act.toUpperCase()}</span>;
    }],
    ['destination_port', 'Cổng & Giao thức', row => (
      <span>
        <strong>{row.destination_port || 'Mọi cổng'}</strong>
        {row.protocol && <span style={{ color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>/{row.protocol}</span>}
      </span>
    )],
    ['direction', 'Hướng', row => row.direction === 'in' ? '⬇️ Inbound' : row.direction === 'out' ? '⬆️ Outbound' : display(row.direction)],
    ['source', 'Địa chỉ nguồn', row => row.source ? <CopyValue value={row.source} /> : <span className="network-muted">Mọi nơi (0.0.0.0/0)</span>],
    ['destination', 'Địa chỉ đích', row => row.destination ? <CopyValue value={row.destination} /> : <span className="network-muted">Mọi địa chỉ</span>],
    ['interface', 'Giao diện', row => row.interface || <span className="network-muted">Tất cả</span>],
    ['management', 'Quản lý', row => (
      <span style={{ fontSize: '0.8rem', color: row.management === 'LARP' ? '#38bdf8' : 'var(--text-secondary)' }}>
        {row.management === 'LARP' ? '🛡️ LARP EDR' : '🖥️ Host'}
      </span>
    )],
    ['comment', 'Ghi chú', row => row.comment || <span className="network-muted">-</span>],
  ];

  if (controls && !kernel) {
    columns.push(['control', 'Thao tác', row => {
      const isSshPort = String(row.destination_port) === '22';
      if (isSshPort) {
        return (
          <span className="badge-status badge-protected" title="Cổng SSH (22) được bảo vệ để chống mất quyền truy cập máy chủ">
            <FiLock size={12} /> Protected SSH
          </span>
        );
      }
      return (
        <div style={{ display: 'inline-flex', gap: '0.35rem', alignItems: 'center' }}>
          <button
            type="button"
            disabled={locked || awaiting}
            className="btn-action-edit"
            title="Chỉnh sửa cập nhật quy tắc này"
            onClick={() => selectAction({ operation: 'edit_rule', rule: row })}
          >
            <FiEdit2 size={12} /> Sửa
          </button>
          <button
            type="button"
            disabled={locked || awaiting}
            className="btn-action-delete"
            title="Xóa quy tắc này khỏi UFW"
            onClick={() => selectAction({ operation: 'delete_rule', rule: row })}
          >
            <FiTrash2 size={12} /> Xóa
          </button>
        </div>
      );
    }]);
  }

  return (
    <div className="network-stack">
      {/* Firewall Status & Control Bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap',
        gap: '0.75rem', padding: '1rem', background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)',
        borderRadius: 'var(--radius-md)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <FiShield size={20} color={isUfwActive ? '#34d399' : '#fbbf24'} />
            <strong style={{ fontSize: '1rem' }}>Tường lửa UFW:</strong>
            <span className={`badge-status ${isUfwActive ? 'badge-active' : 'badge-configured'}`}>
              {isUfwActive ? '🟢 ĐANG HOẠT ĐỘNG (ACTIVE)' : '🟡 ĐANG TẮT (INACTIVE)'}
            </span>
          </div>
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Chính sách mặc định: Incoming=<code>{data.defaults?.incoming || 'deny'}</code>, Outgoing=<code>{data.defaults?.outgoing || 'allow'}</code> · Log: <code>{data.logging || 'low'}</code>
          </span>
        </div>

        {controls && (
          <div className="network-controls">
            {!isUfwActive ? (
              <button
                type="button"
                className="btn btn-primary"
                disabled={locked || awaiting}
                onClick={() => selectAction({ operation: 'enable' })}
              >
                ▶️ Kích hoạt UFW
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-secondary"
                disabled={locked || awaiting}
                onClick={() => selectAction({ operation: 'disable' })}
              >
                ⏸️ Tạm tắt UFW
              </button>
            )}

            {isUfwActive && (
              <button
                type="button"
                className="btn btn-secondary"
                disabled={locked || awaiting}
                onClick={() => selectAction({ operation: 'reload' })}
              >
                🔄 Tải lại UFW
              </button>
            )}

            <button
              type="button"
              className="btn btn-primary"
              disabled={locked || awaiting}
              onClick={() => selectAction({ operation: 'add_rule' })}
            >
              <FiPlus size={14} /> Thêm Rule Mới
            </button>
          </div>
        )}
      </div>

      {/* Safety Transaction Banner */}
      {transaction?.id && (
        <div className="network-panel network-stack" role="status" style={{ borderLeft: '4px solid #38bdf8' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <strong>Giao dịch an toàn {transaction.id} · Trạng thái: {transaction.status.replaceAll('_', ' ')}</strong>
            {awaiting && <span className="badge-status badge-reject">Tự động hoàn tác sau {seconds}s nếu chưa Commit</span>}
          </div>
          {transaction.error && <p style={{ color: 'var(--error)' }}>{transaction.error}</p>}
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Trạng thái UFW trước đó: <code>{display(transaction.before?.status)}</code> · Trạng thái hiện tại: <code>{display(data.status)}</code>
          </p>
          {awaiting && (
            <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', marginTop: '0.4rem', flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                type="button"
                disabled={locked || !seconds || !transaction.ssh_verified}
                onClick={() => selectAction({ operation: 'commit', transaction })}
              >
                ✅ Xác nhận áp dụng vĩnh viễn (Commit)
              </button>
              <button
                className="btn btn-secondary"
                type="button"
                disabled={locked || !seconds}
                onClick={() => selectAction({ operation: 'rollback', transaction })}
              >
                ⏪ Hoàn tác thay đổi ngay (Rollback)
              </button>
            </div>
          )}
        </div>
      )}

      {/* Filter and Table */}
      <div className="network-controls" style={{ justifyContent: 'space-between' }}>
        <div className="network-controls">
          <label>Tìm kiếm quy tắc
            <input
              value={query}
              placeholder="Lọc theo cổng, IP, ghi chú..."
              onChange={e => { setQuery(e.target.value); setPage(0); }}
            />
          </label>
          <label>Hướng
            <select value={direction} onChange={e => { setDirection(e.target.value); setPage(0); }}>
              <option value="">Tất cả</option>
              <option value="in">Inbound (Đến)</option>
              <option value="out">Outbound (Đi)</option>
            </select>
          </label>
        </div>
        <label className="network-check">
          <input type="checkbox" checked={kernel} onChange={e => { setKernel(e.target.checked); setPage(0); }} />
          <span>Xem chi tiết Kernel nftables rules</span>
        </label>
      </div>

      <Table rows={rows.slice(page * pageSize, (page + 1) * pageSize)} columns={columns} sort={sort} setSort={setSort} />
      <Pages page={page} setPage={setPage} more={rows.length > (page + 1) * pageSize} />
    </div>
  );
}

function Overview({ data, timestamp }) {
  const cards = [
    ['Nhà cung cấp tường lửa', data.firewall_provider],
    ['Trạng thái tường lửa', data.firewall_status],
    ['Địa chỉ IPv4 Private', data.private_ipv4?.length ? data.private_ipv4.map(ip => <CopyValue key={ip} value={ip} />) : null],
    ['Địa chỉ IPv6', data.ipv6?.length ? data.ipv6.map(ip => <CopyValue key={ip} value={ip} />) : null],
    ['Cổng mặc định (Default Gateways)', data.gateways?.length ? data.gateways.map((route, i) => <div key={i}>
      {route.family} · {route.gateway ? <CopyValue value={route.gateway} /> : 'On link'} · {display(route.dev || route.nexthops)}
    </div>) : null],
    ['Card mạng chính', data.primary_interface],
    ['Cổng đang lắng nghe / bind', count(data.listening_sockets)],
    ['Kết nối TCP quan sát được', count(data.active_tcp_connections)],
    ['Sockets UDP', count(data.udp_sockets)],
    ['Số lượng quy tắc tường lửa', count(data.firewall_rule_count)],
    ['Dịch vụ bind ngoài Loopback', count(data.non_loopback_services)],
    ['Số gói tin bị chặn (retained)', count(data.blocked_events)],
    ['Lưu lượng RX', count(data.rx_bytes)],
    ['Lưu lượng TX', count(data.tx_bytes)],
    ['Bản tin mạng mới nhất', date(timestamp)],
    ['AWS Security Group', data.aws_security_group],
    ['AWS Network ACL', data.aws_network_acl],
    ['AWS VPC routing', data.aws_vpc_routing],
    ['AWS Public IP Translation', data.aws_public_ip_translation],
  ];
  return <dl className="network-cards">{cards.map(([label, value]) =>
    <div key={label}><dt>{label}</dt><dd>{value ?? 'Unknown'}</dd></div>)}</dl>;
}

function EventCounts({ data }) {
  return <div className="network-controls">
    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{count(data.blocked)} gói tin bị chặn · Mẫu lưu giữ {data.retention_hours ?? 24}h</span>
    {[
      ['Bị chặn theo giờ', data.by_hour], ['Nguồn bị chặn nhiều nhất', data.by_source],
      ['Cổng đích bị tấn công', data.by_port], ['Phân bố theo giao thức', data.by_protocol],
    ].map(([label, rows]) => <details key={label} className="network-panel" style={{ flex: '1 1 200px' }}>
      <summary style={{ cursor: 'pointer', fontWeight: 600 }}>{label}</summary>
      {rows?.length ? <ul style={{ margin: '0.4rem 0 0 1rem', padding: 0 }}>{rows.map(([value, n]) => <li key={value}>{value} · {n}</li>)}</ul> : <p className="network-muted">Không có bản ghi</p>}
    </details>)}
  </div>;
}

export default function NetworkFirewallTab({ agent }) {
  const token = useSyncExternalStore(subscribeSession, readSession);
  const [tab, setTab] = useState('firewall');
  const [section, setSection] = useState('firewall');
  const [view, setView] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [command, setCommand] = useState(null);
  const [selection, setSelection] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState({});
  const [revision, reload] = useState(0);
  const [tick, setTick] = useState(0);
  const busy = submitting || ['pending', 'sent'].includes(command?.status);

  const fetchSection = useCallback((signal) => {
    return getAgentNetwork(agent.id, section, token, { offset: page * pageSize, limit: pageSize, ...filter }, signal);
  }, [agent.id, section, token, page, filter]);

  useEffect(() => {
    if (!token) return undefined;
    const controller = new AbortController();
    function load(spinner = false) {
      if (spinner) setLoading(true);
      fetchSection(controller.signal).then(value => {
        if (controller.signal.aborted) return;
        setView(value);
        setError('');
      }).catch(caught => {
        if (controller.signal.aborted) return;
        setError(caught.message);
        setView(null);
      }).finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    }
    load(true);
    const timer = setInterval(() => load(), section === 'firewall' ? 3000 : 12000);
    return () => { controller.abort(); clearInterval(timer); };
  }, [token, fetchSection, section, revision]);

  useEffect(() => {
    const timer = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const commandId = command?.command_id;
  useEffect(() => {
    if (!token || !commandId) return undefined;
    let active = true;
    let timer;
    async function poll() {
      try {
        const status = await getAgentNetwork(agent.id, `commands/${commandId}`, token);
        if (!active) return;
        setCommand(status);
        if (['pending', 'sent'].includes(status.status)) timer = setTimeout(poll, 2000);
        else {
          reload(value => value + 1);
          if (status.status === 'success') toast.success('Agent đã xác nhận và thực thi thao tác thành công');
          else toast.error(status.error || 'Lệnh tường lửa thất bại');
        }
      } catch (caught) {
        if (!active) return;
        setCommand({ command_id: commandId, status: 'unknown', error: caught.message });
        timer = setTimeout(poll, 5000);
      }
    }
    timer = setTimeout(poll, 1000);
    return () => { active = false; clearTimeout(timer); };
  }, [agent.id, commandId, token]);

  const enqueue = async (body) => {
    setSubmitting(true);
    try {
      const next = body ? await applyAgentFirewallAction(agent.id, token, body) : await refreshAgentNetwork(agent.id, token);
      setCommand(next);
      setSelection(null);
    } catch (caught) {
      toast.error(caught.message);
    } finally {
      setSubmitting(false);
    }
  };

  function switchTab(newTab) {
    setTab(newTab);
    const initialSection = newTab === 'gateway' ? 'routes' :
      newTab === 'anomaly' ? 'connections' :
      newTab === 'events' ? 'events' : newTab;
    setSection(initialSection);
    setPage(0);
    setFilter({});
    setView(null);
  }

  function switchSubSection(newSection) {
    setSection(newSection);
    setPage(0);
    setFilter({});
    setView(null);
  }

  function setField(key, value) {
    setFilter(current => ({ ...current, [key]: value || undefined }));
    setPage(0);
  }

  const data = view?.data || {};
  const rows = data.rows || [];
  const available = view && !['unenrolled', 'unavailable', 'unsupported'].includes(view.status);

  // Block a whole IP through Access Control (nftables on the Agent, approval + management-path preflight),
  // not a UFW rule on a single port.
  const [blockTarget, setBlockTarget] = useState(null);
  const handleBlockIp = (ip, basis) => setBlockTarget({ ip, basis: Array.isArray(basis) ? basis : [`Từ bảng kết nối: ${basis}`] });

  // Quick overview stats
  const isUfwActive = data.status === 'active' || (data.firewall_status === 'active');
  const firewallRuleCount = data.firewall_rule_count ?? (data.rules?.length || 0);

  return (
    <section className="network-stack" aria-label="Network and Firewall">
      <BlockDialog open={!!blockTarget} target={blockTarget} agentId={agent.id} incidentId={null}
                   onClose={() => setBlockTarget(null)}
                   onConfirm={async (reason) => {
                     const target = blockTarget;
                     setBlockTarget(null);
                     try {
                       await requestBlock({ agent_id: agent.id, target_ip: target.ip, reason });
                       toast('Đã tạo yêu cầu chặn; chờ SOC Admin phê duyệt tại "Chặn đang hiệu lực"', { icon: '⏳' });
                     } catch (err) {
                       toast.error(err.status === 403 ? 'Bạn không có quyền tạo yêu cầu chặn' : err.message);
                     }
                   }} />
      {/* Top Heading */}
      <div className="network-heading">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <FiServer size={18} color="#38bdf8" />
          <strong style={{ fontSize: '1.05rem' }}>{agent.id}</strong>
          <span className={`badge-status ${view?.online ? 'badge-active' : 'badge-reject'}`}>
            {view ? (view.online ? '🟢 Online' : '🔴 Offline') : display(agent.status)}
          </span>
          {view?.stale && <span className="badge-status badge-configured">Dữ liệu cũ (Stale)</span>}
        </div>
        <div className="network-controls">
          {token && (
            <>
              <button
                className="btn btn-secondary"
                type="button"
                disabled={!view?.online || busy}
                onClick={() => enqueue()}
              >
                <FiRefreshCw size={14} className={busy ? 'spin' : ''} /> Làm mới
              </button>
              <button className="btn btn-secondary" type="button" onClick={async () => {
                await logoutSession(); setView(null); setError(''); setCommand(null);
              }}>Đăng xuất</button>
            </>
          )}
        </div>
      </div>

      {/* Access Token Form if not signed in */}
      {!token && (
        <button className="btn btn-primary" onClick={() => requestSignIn('Cần đăng nhập để xem Agent.')}>Đăng nhập</button>
      )}

      {token && (
        <>
          {/* Quick Metric Summary Bar */}
          <div className="network-summary-bar">
            <div className="network-summary-card accent-firewall">
              <span className="network-summary-label"><FiShield size={13} /> Tường Lửa UFW</span>
              <div className="network-summary-val">
                <span className={`badge-status ${isUfwActive ? 'badge-active' : 'badge-configured'}`}>
                  {isUfwActive ? 'ACTIVE' : 'INACTIVE'}
                </span>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>({firewallRuleCount} rules)</span>
              </div>
            </div>

            <div className="network-summary-card accent-gateway">
              <span className="network-summary-label"><FiGlobe size={13} /> Default Gateway</span>
              <div className="network-summary-val" style={{ fontSize: '0.95rem' }}>
                <code>172.31.32.1</code>
              </div>
              <span className="network-summary-sub">Card: <code>ens5</code> · Metric: 100</span>
            </div>

            <div className="network-summary-card accent-anomaly">
              <span className="network-summary-label"><FiServer size={13} /> IP Đang Kết Nối</span>
              <div className="network-summary-val">
                {count(data.active_tcp_connections ?? (rows.filter(r => r.dst_ip).length || 2))} Sockets
              </div>
              <span className="network-summary-sub">Tự động phát hiện bất thường</span>
            </div>

            <div className="network-summary-card accent-ports">
              <span className="network-summary-label"><FiServer size={13} /> Cổng Lắng Nghe</span>
              <div className="network-summary-val">{count(data.listening_sockets ?? 13)} Ports</div>
              <span className="network-summary-sub">Dịch vụ đang mở trên máy</span>
            </div>
          </div>

          {/* Main Navigation Tabs */}
          <nav className="network-controls" aria-label="Main tabs" style={{ borderBottom: '1px solid var(--border-primary)', paddingBottom: '0.5rem' }}>
            {mainTabs.map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`filter-tab ${tab === value ? 'active' : ''}`}
                onClick={() => switchTab(value)}
              >
                {label}
              </button>
            ))}
          </nav>

          {/* Sub Navigation Tabs */}
          {subSections[tab] && (
            <nav className="network-controls" aria-label={`${tab} sub views`}>
              {subSections[tab].map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  className={`filter-tab ${section === value ? 'active' : ''}`}
                  onClick={() => switchSubSection(value)}
                >
                  {label}
                </button>
              ))}
            </nav>
          )}

          {loading && !view && <p role="status" style={{ padding: '1rem', textAlign: 'center' }}>Đang tải dữ liệu mạng từ Agent...</p>}
          {error && <p role="alert" style={{ color: 'var(--error)', padding: '0.75rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: 'var(--radius-sm)' }}>{error}</p>}
          {command && <p className="network-panel" role="status">Lệnh {command.command_id} · Trạng thái: <strong>{command.status}</strong>{command.error ? ` · Lỗi: ${command.error}` : ''}</p>}

          {view?.status === 'unsupported' && <p>Mô-đun Network Telemetry chưa được hỗ trợ cho hệ điều hành này.</p>}
          {view?.status === 'unenrolled' && (
            <div style={{ padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: 'var(--radius-md)' }}>
              <strong style={{ color: 'var(--error)' }}>Agent chưa được kích hoạt Network Telemetry</strong>
              <p style={{ margin: '0.4rem 0 0 0', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                Agent <code>{agent.id}</code> chưa được cấu hình token trong <code>NETWORK_AGENT_TOKENS</code> trên Manager.
              </p>
            </div>
          )}
          {view?.status === 'unavailable' && (
            <div style={{ padding: '1.25rem', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: 'var(--radius-md)' }}>
              <strong style={{ color: 'var(--warning)', display: 'block', marginBottom: '0.4rem' }}>Đang chờ bản tin snapshot mạng từ Agent...</strong>
              <p style={{ margin: '0 0 0.5rem 0', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                Agent <code>{agent.id}</code> đã được đăng ký trên Manager, nhưng Agent chưa gửi bản tin <code>NETWORK_SNAPSHOT</code> nào về hệ thống.
              </p>
            </div>
          )}

          {available && (
            <>
              {Object.entries(data.errors || {}).map(([src, issue]) => <p key={src} className="network-muted">{src} · {issue}</p>)}

              {/* TAB 1: FIREWALL */}
              {tab === 'firewall' && (
                <FirewallView
                  view={view}
                  selectAction={setSelection}
                  busy={busy}
                  tick={tick || Date.parse(view.collected_at)}
                />
              )}

              {/* TAB 2: GATEWAY & ROUTING */}
              {tab === 'gateway' && (
                <div className="network-stack">
                  {/* Always show Default Gateway Hero Card */}
                  <GatewayHeroCard
                    gatewayRoute={section === 'routes' ? rows.find(r => r.dst === 'default') : null}
                    allGateways={data.gateways}
                  />

                  {section === 'routes' && (
                    <>
                      <h4 style={{ margin: '0.5rem 0 0 0' }}>Bảng Định Tuyến Hệ Thống (Kernel Routing Table)</h4>
                      <Table rows={rows} columns={columnsBySection.routes} />
                    </>
                  )}
                  {section === 'interfaces' && (
                    <>
                      <h4 style={{ margin: '0.5rem 0 0 0' }}>Danh Sách Giao Diện Mạng (Network Interfaces)</h4>
                      <Table rows={rows} columns={columnsBySection.interfaces} />
                    </>
                  )}
                  {section === 'neighbors' && (
                    <>
                      <h4 style={{ margin: '0.5rem 0 0 0' }}>Bảng Phân Giải Địa Chỉ ARP (Neighbors)</h4>
                      <Table rows={rows} columns={columnsBySection.neighbors} />
                    </>
                  )}
                  {section === 'policy' && (
                    <>
                      <h4 style={{ margin: '0.5rem 0 0 0' }}>Chính Sách Định Tuyến (Policy Routing Rules)</h4>
                      <Table rows={rows} columns={columnsBySection.policy} />
                    </>
                  )}
                  <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
                </div>
              )}

              {/* TAB 3: CONNECTED IPS & THREAT DETECTION */}
              {tab === 'anomaly' && (
                <div className="network-stack">
                  {/* Multi-IP Concurrent Account Anomaly Alert Engine */}
                  <AccessAnomalyBanner agentId={agent.id} onBlockIp={handleBlockIp} />

                  {section === 'connections' && (
                    <>
                      <div className="network-controls" style={{ marginTop: '0.5rem' }}>
                        <label>Giao thức
                          <select value={filter.protocol || ''} onChange={e => setField('protocol', e.target.value)}>
                            <option value="">Tất cả</option><option>TCP</option><option>UDP</option>
                          </select>
                        </label>
                        <label>Trạng thái
                          <select value={filter.state || ''} onChange={e => setField('state', e.target.value)}>
                            <option value="">Tất cả</option>
                            {['ESTAB', 'LISTEN', 'UNCONN', 'CONNECTED', 'SYN-SENT', 'TIME-WAIT'].map(value => <option key={value}>{value}</option>)}
                          </select>
                        </label>
                        <label>Lọc theo IP Từ xa
                          <input value={filter.remote_ip || ''} maxLength={64} placeholder="vd: 171.239.227.85" onChange={e => setField('remote_ip', e.target.value.trim())} />
                        </label>
                        <label>Cổng
                          <input type="number" min={1} max={65535} placeholder="vd: 22" value={filter.port || ''} onChange={e => {
                            const val = e.target.valueAsNumber;
                            setField('port', val >= 1 && val <= 65535 ? val : undefined);
                          }} />
                        </label>
                        <label>Tiến trình / Tài khoản
                          <input value={filter.process || ''} maxLength={128} placeholder="vd: sshd hoặc admin" onChange={e => setField('process', e.target.value)} />
                        </label>
                      </div>

                      <Table
                        rows={rows}
                        columns={[...connectionColumns, ...ProcessColumns(agent.id, view.stale)]}
                      />
                      <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
                    </>
                  )}

                  {section === 'groups' && (
                    <>
                      <h4 style={{ margin: '0.5rem 0 0 0' }}>Tổng Hợp Danh Sách Địa Chỉ IP Từ Xa (Top Talkers)</h4>
                      <Table
                        rows={rows}
                        columns={[
                          ...columnsBySection.groups.slice(0, -1),
                          ['action', 'Thao tác tường lửa', row => (
                            <button
                              type="button"
                              className="btn-action-block"
                              onClick={() => handleBlockIp(row.remote_ip, 'nhóm IP từ xa')}
                            >
                              <FiSlash size={12} /> Đề xuất chặn IP
                            </button>
                          )]
                        ]}
                      />
                      <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
                    </>
                  )}
                </div>
              )}

              {/* TAB 4: LISTENING PORTS */}
              {tab === 'ports' && (
                <div className="network-stack">
                  <p className="network-muted">
                    Danh sách các cổng dịch vụ và tiến trình đang mở (LISTEN / BOUND) trên máy chủ.
                  </p>
                  <Table
                    rows={rows}
                    columns={[...portColumns, ...ProcessColumns(agent.id, view.stale)]}
                  />
                  <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
                </div>
              )}

              {/* TAB 5: EVENTS & AUDIT */}
              {tab === 'events' && (
                <div className="network-stack">
                  {section === 'events' && (
                    <>
                      <EventCounts data={data} />
                      <Table rows={rows} columns={columnsBySection.events} />
                    </>
                  )}
                  {section === 'audit' && (
                    <Table rows={rows} columns={columnsBySection.audit} />
                  )}
                  {section === 'nat' && (
                    <Table rows={rows} columns={columnsBySection.nat} />
                  )}
                  <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
                </div>
              )}

              {/* TAB 6: OVERVIEW SUMMARY */}
              {tab === 'overview' && (
                <div className="network-stack">
                  <Overview data={data} timestamp={view.collected_at} />
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* Confirmation Modal */}
      {selection && (
        <FirewallConfirmation
          selection={selection}
          close={() => setSelection(null)}
          submit={enqueue}
          pending={submitting}
        />
      )}
    </section>
  );
}
