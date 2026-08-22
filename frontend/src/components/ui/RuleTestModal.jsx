// src/components/ui/RuleTestModal.jsx
import React, { useState } from 'react';
import Modal from './Modal';
import Button from './Button';
import Badge from './Badge';
import { FiPlay, FiCheckCircle, FiAlertCircle, FiShield } from 'react-icons/fi';

export default function RuleTestModal({ isOpen, onClose, onSimulate }) {
  const [testPayload, setTestPayload] = useState({
    ip: '198.51.100.45',
    domain: 'malware-c2-domain.com',
    port: '53',
    protocol: 'DNS',
    process: 'powershell.exe',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    rate: '6000',
  });

  const [matches, setMatches] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setTestPayload((prev) => ({ ...prev, [name]: value }));
  };

  const handleRunTest = (e) => {
    e.preventDefault();
    const results = onSimulate({
      ...testPayload,
      port: Number(testPayload.port) || 0,
      rate: Number(testPayload.rate) || 0,
    });
    setMatches(results);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Rule Simulation & Test Laboratory" maxWidth={650}>
      <form onSubmit={handleRunTest} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
          Enter mock traffic event attributes to evaluate rule triggers prior to production deployment.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Target / Source IP
            </label>
            <input
              type="text"
              name="ip"
              value={testPayload.ip}
              onChange={handleChange}
              placeholder="e.g. 198.51.100.45"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Domain Name
            </label>
            <input
              type="text"
              name="domain"
              value={testPayload.domain}
              onChange={handleChange}
              placeholder="e.g. badactor.com"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Dest Port
            </label>
            <input
              type="number"
              name="port"
              value={testPayload.port}
              onChange={handleChange}
              placeholder="53"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Protocol
            </label>
            <input
              type="text"
              name="protocol"
              value={testPayload.protocol}
              onChange={handleChange}
              placeholder="DNS, TCP, HTTP"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Rate (req/sec)
            </label>
            <input
              type="number"
              name="rate"
              value={testPayload.rate}
              onChange={handleChange}
              placeholder="6000"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Process Pattern
            </label>
            <input
              type="text"
              name="process"
              value={testPayload.process}
              onChange={handleChange}
              placeholder="powershell.exe"
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Signature Hash
            </label>
            <input
              type="text"
              name="hash"
              value={testPayload.hash}
              onChange={handleChange}
              placeholder="e3b0c442..."
              style={{
                width: '100%',
                padding: '0.45rem 0.65rem',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                background: 'var(--bg)',
                color: 'var(--text-primary)',
                outline: 'none',
                fontFamily: 'monospace',
              }}
            />
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.25rem' }}>
          <Button variant="primary" size="md" type="submit" iconLeft={<FiPlay size={14} />}>
            Run Simulation Test
          </Button>
        </div>

        {matches !== null && (
          <div style={{ marginTop: '1rem', borderTop: '1px solid var(--border)', paddingTop: '1rem' }}>
            <div style={{ fontWeight: 700, fontSize: '0.9rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              {matches.length > 0 ? (
                <>
                  <FiAlertCircle color="var(--error)" size={16} />
                  <span>Matched {matches.length} Rule(s)</span>
                </>
              ) : (
                <>
                  <FiCheckCircle color="var(--success)" size={16} />
                  <span>No Rules Triggered (Traffic Allowed)</span>
                </>
              )}
            </div>

            {matches.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: 180, overflowY: 'auto' }}>
                {matches.map((rule) => (
                  <div
                    key={rule.id}
                    style={{
                      padding: '0.6rem 0.75rem',
                      background: 'rgba(239,68,68,0.06)',
                      border: '1px solid rgba(239,68,68,0.2)',
                      borderRadius: 'var(--radius-sm)',
                      display: 'flex',
                      alignItems: 'center',
                      justify: 'space-between',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                        [{rule.id}] {rule.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        Type: {rule.type.toUpperCase()} | Action: <strong style={{ color: 'var(--error)' }}>{rule.action.toUpperCase()}</strong>
                      </div>
                    </div>
                    <Badge status={rule.severity} label={rule.severity} showDot={false} />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </form>
    </Modal>
  );
}
