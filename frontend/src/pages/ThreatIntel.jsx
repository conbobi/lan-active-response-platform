// src/pages/ThreatIntel.jsx
import React, { useState } from 'react';
import useThreatIntel from '../hooks/useThreatIntel';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import RiskGauge from '../components/ui/RiskGauge';
import { FiSearch, FiGlobe, FiDatabase, FiAlertTriangle, FiCheckCircle } from 'react-icons/fi';

const INDICATOR_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain Name / DGA' },
  { value: 'hash', label: 'File Hash (MD5 / SHA256)' },
  { value: 'url', label: 'Full Egress URL' },
];

export default function ThreatIntel() {
  const { loading, result, checkIndicator } = useThreatIntel();
  const [indicatorType, setIndicatorType] = useState('ip');
  const [indicatorValue, setIndicatorValue] = useState('185.220.101.5');

  const setSample = (type, val) => {
    setIndicatorType(type);
    setIndicatorValue(val);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!indicatorValue.trim()) return;
    await checkIndicator(indicatorType, indicatorValue.trim());
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Intelligence Lookup</h1>
          <p className="page-subtitle">Verify network IP indicators, domain hashes, and C2 threat reputation via LARP Cyber Intel</p>
        </div>
      </div>

      {/* Quick Sample Indicators */}
      <div className="card" style={{ padding: '0.85rem 1.25rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Quick Indicators:</span>
        <Button variant="danger" size="sm" onClick={() => setSample('ip', '185.220.101.5')}>
          Malicious C2 IP (185.220.101.5)
        </Button>
        <Button variant="warning" size="sm" onClick={() => setSample('hash', '8f34b2c12a890e00115599aa')}>
          Ransomware MD5 Hash
        </Button>
        <Button variant="outline" size="sm" onClick={() => setSample('domain', 'github.com')}>
          Clean Domain (github.com)
        </Button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Input Card */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiSearch color="var(--primary)" /> Query Indicator
          </h3>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <Dropdown
              label="Indicator Type"
              options={INDICATOR_TYPES}
              value={indicatorType}
              onChange={setIndicatorType}
            />

            <div>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
                Indicator Value
              </label>
              <input
                type="text"
                value={indicatorValue}
                onChange={(e) => setIndicatorValue(e.target.value)}
                placeholder="Enter IP, Domain, Hash or URL..."
                style={{
                  width: '100%',
                  padding: '0.65rem 0.8rem',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                  fontFamily: indicatorType === 'hash' || indicatorType === 'ip' ? 'monospace' : 'inherit',
                }}
                required
              />
            </div>

            <Button variant="primary" type="submit" disabled={loading} iconLeft={<FiSearch size={16} />}>
              {loading ? 'Checking Intelligence...' : 'Check Indicator Reputation'}
            </Button>
          </form>
        </div>

        {/* Output Result Card */}
        <div className="card">
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FiDatabase color="var(--primary)" /> Intelligence Report
          </h3>

          {!result ? (
            <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
              <FiGlobe size={48} style={{ opacity: 0.2, marginBottom: '0.75rem' }} />
              <div>Enter an indicator value above to query Threat Intelligence reputation.</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Indicator Verdict:</div>
                  <div style={{ marginTop: '0.25rem' }}>
                    <Badge
                      status={result.status === 'MALICIOUS' ? 'critical' : 'online'}
                      label={result.status || 'CLEAN'}
                    />
                  </div>
                </div>
                <RiskGauge value={result.risk_score || (result.status === 'MALICIOUS' ? 90 : 10)} size={110} />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Indicator Value:</span>
                  <span style={{ fontWeight: 600, fontFamily: 'monospace' }}>{result.value}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Threat Category:</span>
                  <span style={{ fontWeight: 600 }}>{result.threat_category || 'Clean Traffic'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Reputation Summary:</span>
                  <span style={{ fontWeight: 500, textAlign: 'right', maxWidth: '60%' }}>{result.reputation || 'No known threats recorded'}</span>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>Raw Threat Payload</label>
                <pre style={{ background: 'var(--bg-secondary)', padding: '0.65rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', fontSize: '0.75rem', overflowX: 'auto', color: 'var(--text-secondary)' }}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
