// src/pages/Notifications.jsx
import React, { useState } from 'react';
import useNotifications from '../hooks/useNotifications';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import Dropdown from '../components/ui/Dropdown';
import FilterTabs from '../components/ui/FilterTabs';
import { FiBell, FiSend, FiPlus, FiRotateCw, FiCheckCircle } from 'react-icons/fi';

const CHANNEL_OPTIONS = [
  { value: 'email', label: 'Email SMTP Dispatch' },
  { value: 'webhook', label: 'HTTP Webhook Endpoint' },
  { value: 'slack', label: 'Slack Webhook Bot' },
  { value: 'telegram', label: 'Telegram Bot API' },
];

export default function Notifications() {
  const { configs, logs, loading, refreshNotifications, createConfig } = useNotifications();

  const [activeTab, setActiveTab] = useState('configs');
  const [modalOpen, setModalOpen] = useState(false);

  // Form State
  const [channel, setChannel] = useState('email');
  const [recipient, setRecipient] = useState('');

  const tabs = [
    { value: 'configs', label: 'Notification Channels', count: configs.length },
    { value: 'logs', label: 'Dispatch Audit Logs', count: logs.length },
  ];

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (!recipient.trim()) return;
    await createConfig({
      channel,
      recipient: recipient.trim(),
    });
    setModalOpen(false);
    setRecipient('');
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">SOC Notifications & Dispatch</h1>
        </div>
        <div className="card skeleton" style={{ height: '350px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">SOC Notifications & Dispatch</h1>
          <p className="page-subtitle">Configure real-time alerting notification channels, webhooks, and review dispatch logs</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshNotifications}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlus size={15} />} onClick={() => setModalOpen(true)}>
            Add Notification Channel
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)' }}>
          <FilterTabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
        </div>

        {activeTab === 'configs' ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Config ID</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Channel Type</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Recipient / Webhook Destination</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Status</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Created At</th>
                </tr>
              </thead>
              <tbody>
                {configs.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                      No notification channels configured
                    </td>
                  </tr>
                ) : (
                  configs.map((cfg) => (
                    <tr key={cfg.config_id || cfg.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.85rem 1.25rem', fontWeight: 700, color: 'var(--primary)' }}>
                        {cfg.config_id || cfg.id}
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem' }}>
                        <Badge status="info" label={(cfg.channel || 'email').toUpperCase()} showDot={false} />
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem', fontWeight: 500, fontFamily: 'monospace' }}>
                        {cfg.recipient}
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem' }}>
                        <Badge status={cfg.enabled !== false ? 'online' : 'offline'} label={cfg.enabled !== false ? 'ACTIVE' : 'DISABLED'} />
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                        {cfg.created_at ? new Date(cfg.created_at).toLocaleString() : 'N/A'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Log ID</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Triggered Event</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Destination</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Delivery Status</th>
                  <th style={{ padding: '0.85rem 1.25rem' }}>Sent Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                      No notification logs recorded
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.log_id || log.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.85rem 1.25rem', fontWeight: 700, color: 'var(--primary)' }}>
                        {log.log_id || log.id}
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>
                        {log.event_type}
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                        {log.recipient}
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem' }}>
                        <Badge status={log.status === 'DELIVERED' ? 'online' : 'critical'} label={log.status} />
                      </td>
                      <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                        {new Date(log.sent_at).toLocaleString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Config Modal */}
      <Modal isOpen={modalOpen} onClose={() => setModalOpen(false)} title="Create Alert Notification Channel">
        <form onSubmit={handleCreateSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Dropdown
            label="Notification Channel Type"
            options={CHANNEL_OPTIONS}
            value={channel}
            onChange={setChannel}
          />

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Recipient / Webhook URL
            </label>
            <input
              type="text"
              placeholder={channel === 'email' ? 'admin@larp-soc.lan' : 'https://hooks.slack.com/...'}
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
                fontFamily: channel !== 'email' ? 'monospace' : 'inherit',
              }}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" iconLeft={<FiBell size={15} />}>
              Save Channel
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
