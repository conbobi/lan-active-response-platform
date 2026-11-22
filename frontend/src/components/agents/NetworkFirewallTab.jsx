import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FiCopy, FiRefreshCw } from 'react-icons/fi';
import toast from 'react-hot-toast';
import {
  applyAgentFirewallAction, getAgentNetwork, refreshAgentNetwork,
} from '../../api/network';
import './NetworkFirewallTab.css';

const tabs = [
  ['overview', 'Overview'], ['firewall', 'Firewall Rules'], ['ports', 'Listening Ports'],
  ['connections', 'Active Connections'], ['interfaces', 'Interfaces & Routing'],
  ['nat', 'NAT / Port Forwarding'], ['events', 'Firewall Events'], ['audit', 'Audit History'],
];
const subSections = {
  interfaces: [['interfaces', 'Interfaces'], ['routes', 'Routes'], ['policy', 'Policy routing'], ['neighbors', 'Neighbors']],
  connections: [['connections', 'Sockets'], ['groups', 'Remote IPs']],
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

function CopyValue({ value }) {
  if (value == null || value === '') return 'Unknown';
  return <span className="network-copy">
    <code>{value}</code>
    <button type="button" className="modal-close" aria-label={`Copy ${value}`} onClick={async () => {
      try {
        await navigator.clipboard.writeText(String(value));
        toast.success('Copied');
      } catch {
        toast.error('Clipboard is unavailable');
      }
    }}><FiCopy size={13} /></button>
  </span>;
}

function Table({ rows, columns, sort, setSort }) {
  if (!rows.length) return <p className="network-muted">No records match this view.</p>;
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

function Overview({ data, timestamp }) {
  const cards = [
    ['Host firewall provider', data.firewall_provider], ['Reported firewall status', data.firewall_status],
    ['Private IPv4', data.private_ipv4?.length ? data.private_ipv4.map(ip => <CopyValue key={ip} value={ip} />) : null],
    ['IPv6 addresses', data.ipv6?.length ? data.ipv6.map(ip => <CopyValue key={ip} value={ip} />) : null],
    ['Default routes', data.gateways?.length ? data.gateways.map((route, i) => <div key={i}>
      {route.family} · {route.gateway ? <CopyValue value={route.gateway} /> : 'On link'} · {display(route.dev || route.nexthops)}
    </div>) : null],
    ['Primary interface', data.primary_interface], ['Listening / bound sockets', count(data.listening_sockets)],
    ['Observed TCP connections', count(data.active_tcp_connections)], ['UDP sockets', count(data.udp_sockets)],
    ['Firewall rules', count(data.firewall_rule_count)], ['Non-loopback bound sockets', count(data.non_loopback_services)],
    ['External reachability', 'Unverified'], ['Blocked events (retained sample)', count(data.blocked_events)],
    ['RX bytes', count(data.rx_bytes)], ['TX bytes', count(data.tx_bytes)], ['Latest network snapshot', date(timestamp)],
    ['AWS Security Group', data.aws_security_group], ['AWS Network ACL', data.aws_network_acl],
    ['AWS VPC routing', data.aws_vpc_routing], ['AWS public IP translation', data.aws_public_ip_translation],
  ];
  return <dl className="network-cards">{cards.map(([label, value]) =>
    <div key={label}><dt>{label}</dt><dd>{value ?? 'Unknown'}</dd></div>)}</dl>;
}

const copy = (key) => (row) => <CopyValue value={row[key]} />;
const portColumns = [
  ['protocol', 'Protocol'], ['src_ip', 'Bind address', copy('src_ip')], ['src_port', 'Port', copy('src_port')],
  ['status', 'Socket state'], ['process_owner', 'Owner'], ['bind_scope', 'Bind scope'],
  ['firewall_matches', 'Candidate rule IDs', row => row.firewall_matches?.join(', ') || 'None in the sample'],
];
const connectionColumns = [
  ['src_ip', 'Local IP', copy('src_ip')], ['src_port', 'Local port', copy('src_port')],
  ['dst_ip', 'Remote IP', copy('dst_ip')], ['dst_port', 'Remote port', copy('dst_port')],
  ['protocol', 'Protocol'], ['status', 'State'], ['direction', 'Direction'],
  ['first_seen', 'First seen', row => date(row.first_seen)], ['last_seen', 'Last seen', row => date(row.last_seen)],
  ['duration_seconds', 'Observed seconds'], ['asn', 'ASN'], ['organization', 'Organization'],
  ['dns_hostname', 'DNS evidence'], ['risk_context', 'Risk context'],
];
const columnsBySection = {
  groups: [
    ['remote_ip', 'Remote IP', copy('remote_ip')], ['currently_observed', 'Current sockets'],
    ['new_connections', 'Observed connection starts'], ['processes', 'Processes'], ['ports', 'Remote ports'],
    ['first_seen', 'First seen', row => date(row.first_seen)], ['last_seen', 'Last seen', row => date(row.last_seen)],
    ['incidents', 'Related incidents', row => row.incidents?.length ? row.incidents.map(incident =>
      <div key={incident.id}><Link to={`/incidents/${encodeURIComponent(incident.id)}`}>{incident.title}</Link></div>) : 'None linked'],
  ],
  interfaces: [
    ['ifname', 'Interface'], ['ifindex', 'Index'], ['address', 'MAC', copy('address')], ['mtu', 'MTU'],
    ['addr_info', 'Addresses', row => row.addr_info?.map(addr => <div key={addr.local}>
      <CopyValue value={`${addr.local}/${addr.prefixlen}`} />
    </div>)], ['admin_state', 'Admin state'], ['operstate', 'Operational state'], ['rx_bytes', 'RX bytes'], ['tx_bytes', 'TX bytes'],
  ],
  routes: [
    ['family', 'Family'], ['dst', 'Destination', row => row.dst || 'default'], ['gateway', 'Gateway', copy('gateway')],
    ['nexthops', 'Multipath next hops'], ['dev', 'Interface'], ['table', 'Table', row => row.table ?? 'main'],
    ['metric', 'Metric'], ['protocol', 'Protocol'], ['type', 'Type'],
  ],
  policy: [
    ['family', 'Family'], ['priority', 'Priority'], ['src', 'Source'], ['dst', 'Destination'],
    ['table', 'Table'], ['fwmark', 'Firewall mark'], ['iif', 'Input interface'], ['oif', 'Output interface'],
    ['action', 'Action'],
  ],
  neighbors: [
    ['family', 'Family'], ['dst', 'Neighbor', copy('dst')], ['dev', 'Interface'], ['lladdr', 'MAC', copy('lladdr')], ['state', 'State'],
  ],
  nat: [
    ['nat_type', 'Type'], ['provider', 'Backend'], ['family', 'Family'], ['table', 'Table'], ['chain', 'Chain'],
    ['hook', 'Hook'], ['id', 'Handle / ID'], ['protocol', 'Protocol'], ['source', 'Source', copy('source')],
    ['destination', 'Destination', copy('destination')], ['destination_port', 'Original port', copy('destination_port')],
    ['translated_ip', 'Translated IP', copy('translated_ip')], ['translated_port', 'Translated port', copy('translated_port')],
    ['interface', 'Interface'], ['packets', 'Packets'], ['bytes', 'Bytes'], ['management', 'Owner'], ['match', 'Rule details'],
  ],
  events: [
    ['timestamp', 'Timestamp', row => date(row.timestamp)], ['action', 'Action'],
    ['source', 'Source IP', copy('source')], ['source_port', 'Source port', copy('source_port')],
    ['destination', 'Destination IP', copy('destination')], ['destination_port', 'Destination port', copy('destination_port')],
    ['protocol', 'Protocol'], ['in_interface', 'Incoming'], ['out_interface', 'Outgoing'],
    ['prefix', 'Rule prefix'], ['reference', 'Log reference'],
  ],
  audit: [
    ['id', 'Action ID', copy('id')], ['agent_id', 'Agent'], ['requested_at', 'Requested', row => date(row.requested_at)],
    ['parameters', 'Parameters', row => <details>
      <summary>{row.parameters.operation} · {row.parameters.operator}</summary>
      <p>{row.parameters.reason}</p><pre>{JSON.stringify(row.parameters, null, 2)}</pre>
    </details>],
    ['status', 'Result'],
    ['result', 'Verification and audit', row => <details>
      <summary>{row.result?.ack || 'Awaiting ACK'}</summary>
      <p>{row.result?.error}</p>
      <p>Executed {date(row.result?.executed_at)}</p>
      <ul>{row.events?.map((event, i) => <li key={i}>{date(event.timestamp)} · {event.event} · {event.actor}</li>)}</ul>
      {row.result?.agent_result && <pre>{JSON.stringify(row.result.agent_result, null, 2)}</pre>}
    </details>],
  ],
};

function ProcessColumns(agentId, stale) {
  return [
    ['pid', 'PID', row => row.pid && !stale ? <Link to={`/investigate?${new URLSearchParams({
      tab: 'process', agent: agentId, pid: row.pid, started: row.process_start_time,
    })}`}>{row.pid}</Link> : display(row.pid)],
    ['process_name', 'Process'], ['exe_path', 'Executable', copy('exe_path')],
    ['process_start_time', 'Process started', row => unixDate(row.process_start_time)], ['attribution', 'Attribution'],
  ];
}

const operationLabels = {
  enable: 'Enable UFW', disable: 'Temporarily disable UFW', reload: 'Reload UFW', add_rule: 'Add rule',
  delete_rule: 'Delete rule', set_logging: 'Change logging', set_policy: 'Change default policy',
  commit: 'Commit change', rollback: 'Roll back now',
};

function FirewallConfirmation({ selection, close, submit, pending }) {
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [protocol, setProtocol] = useState('tcp');
  const [port, setPort] = useState('');
  const [source, setSource] = useState('');
  const [iface, setInterface] = useState('');
  const [action, setAction] = useState('allow');
  const [direction, setDirection] = useState('incoming');
  const [logging, setLogging] = useState('low');
  const operation = selection.operation;
  const onSubmit = (event) => {
    event.preventDefault();
    const params = { operation, reason: reason.trim(), confirmed };
    if (operation === 'add_rule') Object.assign(params, {
      action, protocol, port: Number(port), ...(source.trim() && { source: source.trim() }), ...(iface.trim() && { interface: iface.trim() }),
    });
    if (operation === 'delete_rule') params.rule_id = selection.rule.id;
    if (operation === 'set_policy') Object.assign(params, { direction, action });
    if (operation === 'set_logging') params.logging = logging;
    if (selection.transaction) params.transaction_id = selection.transaction.id;
    submit(params);
  };
  return <div className="network-confirm" role="dialog" aria-modal="true" aria-label={operationLabels[operation]}>
    <form className="modal-box network-confirm-box" onSubmit={onSubmit}>
      <div className="modal-header"><h4>{operationLabels[operation]}</h4>
        <button type="button" className="modal-close" onClick={close} aria-label="Close">×</button></div>
      <div className="modal-body network-stack">
        {operation === 'disable' && <p role="alert">Disabling UFW may expose bound services. UFW is restored automatically unless an administrator verifies SSH and commits.</p>}
        {operation === 'delete_rule' && <p>Delete UFW rule {selection.rule.order} · {selection.rule.comment}</p>}
        {operation === 'commit' && <p>Commit the current verified firewall state permanently.</p>}
        {['add_rule', 'set_policy'].includes(operation) && <label>Action
          <select value={action} onChange={e => setAction(e.target.value)}>
            {['allow', 'deny', 'reject'].map(value => <option key={value}>{value}</option>)}
          </select>
        </label>}
        {operation === 'add_rule' && <div className="network-controls">
          <label>Protocol<select value={protocol} onChange={e => setProtocol(e.target.value)}><option>tcp</option><option>udp</option></select></label>
          <label>Destination port<input type="number" min="1" max="65535" required value={port} onChange={e => setPort(e.target.value)} /></label>
          <label>Source IP or CIDR<input value={source} maxLength="64" placeholder="Any" onChange={e => setSource(e.target.value)} /></label>
          <label>Interface<input value={iface} maxLength="15" placeholder="Any" onChange={e => setInterface(e.target.value)} /></label>
        </div>}
        {operation === 'set_policy' && <label>Direction
          <select value={direction} onChange={e => setDirection(e.target.value)}>
            {['incoming', 'outgoing', 'routed'].map(value => <option key={value}>{value}</option>)}
          </select>
        </label>}
        {operation === 'set_logging' && <label>Logging level
          <select value={logging} onChange={e => setLogging(e.target.value)}>
            {['off', 'low', 'medium', 'high', 'full'].map(value => <option key={value}>{value}</option>)}
          </select>
        </label>}
        <label>Reason<textarea value={reason} required maxLength={255} onChange={e => setReason(e.target.value)} /></label>
        <label className="network-check"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />
          Confirm the requested change</label>
        <div className="network-controls"><button className="btn btn-secondary" type="button" onClick={close}>Cancel</button>
          <button className="btn btn-primary" type="submit" disabled={!confirmed || !reason.trim() || pending}>Submit</button></div>
      </div>
    </form>
  </div>;
}

function Firewall({ view, selectAction, busy, tick }) {
  const data = view.data;
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
  const source = kernel ? data.kernel_rules : data.rules;
  const rows = ordered((source || []).filter(row => (!direction || row.direction === direction) &&
    (!query || JSON.stringify(row).toLowerCase().includes(query.toLowerCase()))), sort);
  const columns = [
    ['id', 'Rule ID', copy('id')], ['order', 'Order'], ['direction', 'Direction'], ['action', 'Action'],
    ['protocol', 'Protocol'], ['source', 'Source', copy('source')], ['destination', 'Destination', copy('destination')],
    ['source_port', 'Source port', copy('source_port')], ['destination_port', 'Destination port', copy('destination_port')],
    ['interface', 'Interface'], ['comment', 'Comment'], ['provider', 'Provider'], ['management', 'Management'],
  ];
  if (controls && !kernel) columns.push(['control', 'Action', row => row.management === 'LARP' && <button type="button"
    disabled={locked || awaiting} className="btn btn-secondary" onClick={() => selectAction({ operation: 'delete_rule', rule: row })}>Delete</button>]);
  return <>
    <dl className="network-cards">
      {[
        ['Provider', data.provider], ['Verified provider status', data.status], ['Kernel policy status', data.kernel_status], ['Incoming policy', data.defaults?.incoming],
        ['Outgoing policy', data.defaults?.outgoing], ['Forwarding policy', data.defaults?.routed],
        ['Logging', data.logging], ['IPv4', data.ipv4], ['IPv6', data.ipv6],
        ['Last configuration change', unixDate(data.configuration_mtime)], ['Kernel backends', data.kernel_backends?.join(', ')],
      ].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{display(value)}</dd></div>)}
    </dl>
    {data.provider === 'ufw' && <p className="network-muted">
      {data.status === 'inactive' ? 'Showing configured UFW user rules. ' : 'Showing active UFW user rules. '}
      View the kernel inventory for other policies.
    </p>}
    {controls ? <div className="network-controls">
      {['enable', 'disable', 'reload', 'add_rule', 'set_logging'].map(operation => <button key={operation}
        type="button" className="btn btn-secondary" disabled={locked || awaiting || ['queued', 'applying', 'rolling_back'].includes(transaction?.status)
          || (operation === 'enable' && data.status !== 'inactive')
          || (['disable', 'reload', 'add_rule'].includes(operation) && data.status !== 'active')}
        onClick={() => selectAction({ operation })}>{operationLabels[operation]}</button>)}
    </div> : admin && data.provider && <p className="network-muted">Firewall controls require protected SSH rules, a local rollback timer and an external SSH verifier.</p>}
    {transaction?.id && <div className="network-panel network-stack" role="status">
      <strong>Transaction {transaction.id} · {transaction.status.replaceAll('_', ' ')}</strong>
      {transaction.error && <p>{transaction.error}</p>}
      <p>Previous UFW state {display(transaction.before?.status)} · Current verified state {display(data.status)}</p>
      {awaiting && <>
        <p>Rollback scheduled in {seconds}s unless committed. SSH verification {transaction.ssh_verified ? 'complete' : 'pending'}.</p>
        {controls && !transaction.ssh_verified && <p>Open a fresh authorized SSH session. Run the local approval command documented for this Agent with transaction ID <CopyValue value={transaction.id} />.</p>}
        {controls && <div className="network-controls">
          <button className="btn btn-primary" type="button" disabled={locked || !seconds || !transaction.ssh_verified}
            onClick={() => selectAction({ operation: 'commit', transaction })}>Commit change</button>
          <button className="btn btn-secondary" type="button" disabled={locked || !seconds}
            onClick={() => selectAction({ operation: 'rollback', transaction })}>Roll back now</button>
        </div>}
      </>}
    </div>}
    <div className="network-controls">
      <label>Search rules<input value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} /></label>
      <label>Direction<select value={direction} onChange={e => { setDirection(e.target.value); setPage(0); }}>
        <option value="">All</option><option value="in">Inbound</option><option value="out">Outbound</option><option value="fwd">Forward</option>
      </select></label>
      <label className="network-check"><input type="checkbox" checked={kernel} onChange={e => { setKernel(e.target.checked); setPage(0); }} /> Kernel rule inventory</label>
    </div>
    <Table rows={rows.slice(page * pageSize, (page + 1) * pageSize)} columns={columns} sort={sort} setSort={setSort} />
    <Pages page={page} setPage={setPage} more={rows.length > (page + 1) * pageSize} />
  </>;
}

function Pages({ page, setPage, more }) {
  if (!page && !more) return null;
  return <div className="network-controls">
    <button type="button" className="btn btn-secondary" disabled={!page} onClick={() => setPage(page - 1)}>Previous</button>
    <span>Page {page + 1}</span>
    <button type="button" className="btn btn-secondary" disabled={!more} onClick={() => setPage(page + 1)}>Next</button>
  </div>;
}

function EventCounts({ data }) {
  return <div className="network-controls">
    <span>{count(data.blocked)} blocked · {data.retention_hours ?? 24}h retained sample</span>
    {[
      ['Blocked by hour', data.by_hour], ['Top blocked sources', data.by_source],
      ['Top targeted ports', data.by_port], ['Blocked by protocol', data.by_protocol],
    ].map(([label, rows]) => <details key={label} className="network-panel">
      <summary>{label}</summary>
      {rows?.length ? <ul>{rows.map(([value, n]) => <li key={value}>{value} · {n}</li>)}</ul> : <p>No records</p>}
    </details>)}
  </div>;
}

export default function NetworkFirewallTab({ agent }) {
  const [token, setToken] = useState('');
  const [draftToken, setDraftToken] = useState('');
  useEffect(() => { localStorage.removeItem('larp_network_token'); }, []);

  const [tab, setTab] = useState('overview');
  const [section, setSection] = useState('overview');
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
          if (status.status === 'success') toast.success('Agent acknowledged and verified the operation');
          else toast.error(status.error || 'Network command failed');
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

  function changeSection(value, newTab = tab) {
    setTab(newTab);
    setSection(value);
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
  return <section className="network-stack" aria-label="Network and Firewall">
    <div className="network-controls network-heading">
      <div><strong>{agent.id}</strong> · {view ? (view.online ? 'Online' : 'Offline') : display(agent.status)}</div>
      {view && <span className="network-muted">{view.stale && view.collected_at ? 'Stale · ' : ''}{view.status} · {date(view.collected_at)}</span>}
      {token && <button className="btn btn-secondary" type="button" disabled={!view?.online || busy}
        onClick={() => enqueue()}><FiRefreshCw size={14} /> Refresh</button>}
      {token && <button className="btn btn-secondary" type="button" onClick={() => {
        setToken(''); setView(null); setError(''); setCommand(null);
      }}>Clear access</button>}
    </div>
    {!token && <form className="network-controls" onSubmit={event => {
      event.preventDefault();
      setToken(draftToken.trim());
      setDraftToken('');
    }}>
      <label>Network access token<input type="password" value={draftToken} onChange={e => setDraftToken(e.target.value)}
        autoComplete="off" required /></label>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <button type="submit" className="btn btn-primary" disabled={!draftToken.trim()}>Open Network &amp; Firewall</button>

      </div>
    </form>}
    {token && <>
      <nav className="network-controls" aria-label="Network views">{tabs.map(([value, label]) => <button
        key={value} type="button" className={`filter-tab ${tab === value ? 'active' : ''}`}
        onClick={() => changeSection(value, value)}>{label}</button>)}</nav>
      {subSections[tab] && <nav className="network-controls" aria-label={`${tab} views`}>{subSections[tab].map(([value, label]) => <button
        key={value} type="button" className={`filter-tab ${section === value ? 'active' : ''}`} onClick={() => changeSection(value)}>{label}</button>)}</nav>}
      {loading && !view && <p role="status">Loading network data…</p>}
      {error && <p role="alert" style={{ color: 'var(--error)' }}>{error}</p>}
      {command && <p className="network-panel" role="status">Command {command.command_id} · {command.status}{command.error ? ` · ${command.error}` : ''}</p>}
      {view?.status === 'unsupported' && <p>Network telemetry is unsupported for this operating system.</p>}
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
          <p style={{ margin: 0, color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
            💡 Hướng dẫn: Đảm bảo trên máy chủ Agent tệp <code>/etc/larp-agent/network.env</code> đã có <code>LARP_NETWORK_AGENT_TOKEN</code> và dịch vụ <code>larp-agent.service</code> đang hoạt động.
          </p>
        </div>
      )}
      {available && <>
        {Object.entries(data.errors || {}).map(([source, issue]) => <p key={source} className="network-muted">{source} · {issue}</p>)}
        {section === 'overview' && <Overview data={data} timestamp={view.collected_at} />}
        {section === 'firewall' && <Firewall view={view} selectAction={setSelection} busy={busy} tick={tick || Date.parse(view.collected_at)} />}
        {section === 'ports' && <p className="network-muted">Bind scope and candidate firewall rules describe local observations. Internet reachability is unverified.</p>}
        {section === 'nat' && <p className="network-muted">Guest NAT rules. AWS public address translation and Security Group visibility require AWS integration.</p>}
        {section === 'groups' && <p className="network-muted">Connection starts are counted from the most recent retained observations.</p>}
        {section === 'events' && <EventCounts data={data} />}
        {section === 'connections' && <div className="network-controls">
          <label>Protocol<select value={filter.protocol || ''} onChange={e => setField('protocol', e.target.value)}>
            <option value="">All</option><option>TCP</option><option>UDP</option>
          </select></label>
          <label>Direction<select value={filter.direction || ''} onChange={e => setField('direction', e.target.value)}>
            <option value="">All</option><option>inbound</option><option>outbound</option><option>unknown</option>
          </select></label>
          <label>State<select value={filter.state || ''} onChange={e => setField('state', e.target.value)}>
            <option value="">All</option>{['ESTAB', 'LISTEN', 'UNCONN', 'CONNECTED', 'SYN-SENT', 'TIME-WAIT'].map(value => <option key={value}>{value}</option>)}
          </select></label>
          <label>Remote IP<input value={filter.remote_ip || ''} maxLength={64} onChange={e => setField('remote_ip', e.target.value.trim())} /></label>
          <label>Port<input type="number" min={1} max={65535} value={filter.port || ''} onChange={e => {
            const value = e.target.valueAsNumber;
            setField('port', value >= 1 && value <= 65535 ? value : undefined);
          }} /></label>
          <label>Process<input value={filter.process || ''} maxLength={128} onChange={e => setField('process', e.target.value)} /></label>
        </div>}
        {section !== 'overview' && section !== 'firewall' && <>
          <Table rows={rows} columns={section === 'ports' ? [...portColumns, ...ProcessColumns(agent.id, view.stale)] :
            section === 'connections' ? [...connectionColumns, ...ProcessColumns(agent.id, view.stale)] : columnsBySection[section]} />
          <Pages page={page} setPage={setPage} more={data.has_more || data.matched > (page + 1) * pageSize} />
          {data.total > data.matched && !Object.values(filter).some(Boolean) && section !== 'groups' &&
            <p className="network-muted">{count(data.matched)} rows retained from {count(data.total)} observations.</p>}
        </>}
      </>}
    </>}
    {selection && <FirewallConfirmation selection={selection} close={() => setSelection(null)} submit={enqueue} pending={submitting} />}
  </section>;
}
