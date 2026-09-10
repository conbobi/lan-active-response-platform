// src/pages/ThreatIntel.jsx
import React, { useState, useEffect } from 'react';
import useThreatIntel from '../hooks/useThreatIntel';
import Dropdown from '../components/ui/Dropdown';
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import RiskGauge from '../components/ui/RiskGauge';
import axios from 'axios';
import {
  FiSearch,
  FiGlobe,
  FiDatabase,
  FiRefreshCw,
  FiPlus,
  FiCheckCircle,
  FiAlertCircle,
  FiRadio,
  FiList

} from 'react-icons/fi';

const API_BASE = '/api/v1/threat-intel';

const INDICATOR_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain Name / DGA' },
  { value: 'hash', label: 'File Hash (MD5 / SHA256)' },
  { value: 'url', label: 'Full Egress URL' },
];

export default function ThreatIntel() {
  const { loading: queryLoading, result, checkIndicator } = useThreatIntel();
  const [activeTab, setActiveTab] = useState('lookup'); // 'lookup', 'feeds', 'indicators'

  // Lookup state
  const [indicatorType, setIndicatorType] = useState('ip');
  const [indicatorValue, setIndicatorValue] = useState('185.220.101.5');

  // Feeds state
  const [feeds, setFeeds] = useState([]);
  const [feedsLoading, setFeedsLoading] = useState(false);
  const [syncingFeedId, setSyncingFeedId] = useState(null);
  const [showAddFeedModal, setShowAddFeedModal] = useState(false);
  const [newFeed, setNewFeed] = useState({ name: '', url: '', feed_type: 'ip', interval_hours: 6 });

  // Indicators state
  const [indicators, setIndicators] = useState([]);
  const [totalIndicators, setTotalIndicators] = useState(0);
  const [indicatorSearch, setIndicatorSearch] = useState('');
  const [filterType, setFilterType] = useState('');
  const [page, setPage] = useState(0);

  const fetchFeeds = async () => {
    setFeedsLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/feeds`);
      setFeeds(res.data);
    } catch (err) {
      console.error('Failed to load threat feeds:', err);
    } finally {
      setFeedsLoading(false);
    }
  };

  const fetchIndicators = async () => {
    try {
      const params = { skip: page * 20, limit: 20 };
      if (indicatorSearch) params.query = indicatorSearch;
      if (filterType) params.indicator_type = filterType;
      const res = await axios.get(`${API_BASE}/indicators`, { params });
      setIndicators(res.data.items || []);
      setTotalIndicators(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load indicators:', err);
    }
  };

  useEffect(() => {
    if (activeTab === 'feeds') {
      fetchFeeds();
    } else if (activeTab === 'indicators') {
      fetchIndicators();
    }
  }, [activeTab, page, filterType]);

  const handleLookupSubmit = async (e) => {
    e.preventDefault();
    if (!indicatorValue.trim()) return;
    await checkIndicator(indicatorType, indicatorValue.trim());
  };

  const handleSyncFeed = async (feedId) => {
    setSyncingFeedId(feedId);
    try {
      await axios.post(`${API_BASE}/feeds/${feedId}/sync`);
      await fetchFeeds();
    } catch (err) {
      alert('Error syncing feed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setSyncingFeedId(null);
    }
  };

  const handleSyncAll = async () => {
    setSyncingFeedId('all');
    try {
      await axios.post(`${API_BASE}/sync-all`);
      await fetchFeeds();
    } catch (err) {
      alert('Error syncing feeds: ' + (err.response?.data?.detail || err.message));
    } finally {
      setSyncingFeedId(null);
    }
  };

  const handleToggleFeed = async (feed) => {
    try {
      await axios.put(`${API_BASE}/feeds/${feed.id}`, { enabled: !feed.enabled });
      setFeeds(feeds.map(f => f.id === feed.id ? { ...f, enabled: !f.enabled } : f));
    } catch (err) {
      alert('Failed to update feed: ' + err.message);
    }
  };

  const handleCreateFeed = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_BASE}/feeds`, newFeed);
      setShowAddFeedModal(false);
      setNewFeed({ name: '', url: '', feed_type: 'ip', interval_hours: 6 });
      fetchFeeds();
    } catch (err) {
      alert('Failed to add feed: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Threat Intelligence Center</h1>
          <p className="page-subtitle">Automated IoC Feed ingestion, reputation lookup, and real-time C2 blacklist database</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button
            variant={activeTab === 'lookup' ? 'primary' : 'outline'}
            size="sm"
            onClick={() => setActiveTab('lookup')}
            iconLeft={<FiSearch size={14} />}
          >
            Reputation Query
          </Button>
          <Button
            variant={activeTab === 'feeds' ? 'primary' : 'outline'}
            size="sm"
            onClick={() => setActiveTab('feeds')}
            iconLeft={<FiRadio size={14} />}
          >
            Automated Feeds
          </Button>
          <Button
            variant={activeTab === 'indicators' ? 'primary' : 'outline'}
            size="sm"
            onClick={() => setActiveTab('indicators')}
            iconLeft={<FiList size={14} />}
          >
            IoC Database
          </Button>
        </div>
      </div>

      {/* TAB 1: REPUTATION LOOKUP */}
      {activeTab === 'lookup' && (
        <>
          <div className="card" style={{ padding: '0.85rem 1.25rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Quick Indicators:</span>
            <Button variant="danger" size="sm" onClick={() => { setIndicatorType('ip'); setIndicatorValue('185.220.101.5'); }}>
              Malicious C2 IP (185.220.101.5)
            </Button>
            <Button variant="warning" size="sm" onClick={() => { setIndicatorType('hash'); setIndicatorValue('8f34b2c12a890e00115599aa'); }}>
              Ransomware MD5 Hash
            </Button>
            <Button variant="outline" size="sm" onClick={() => { setIndicatorType('domain'); setIndicatorValue('github.com'); }}>
              Clean Domain (github.com)
            </Button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            <div className="card">
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FiSearch color="var(--primary)" /> Query Indicator
              </h3>

              <form onSubmit={handleLookupSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
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

                <Button variant="primary" type="submit" disabled={queryLoading} iconLeft={<FiSearch size={16} />}>
                  {queryLoading ? 'Checking Intelligence...' : 'Check Indicator Reputation'}
                </Button>
              </form>
            </div>

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
                      <span style={{ color: 'var(--text-secondary)' }}>Source:</span>
                      <span style={{ fontWeight: 500 }}>{result.source || 'Local Threat DB'}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* TAB 2: AUTOMATED FEEDS */}
      {activeTab === 'feeds' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Open-Source Threat Feeds</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Automated background subscriptions syncing malicious IoCs into local cache</p>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <Button
                variant="outline"
                size="sm"
                onClick={handleSyncAll}
                disabled={syncingFeedId === 'all'}
                iconLeft={<FiRefreshCw className={syncingFeedId === 'all' ? 'spin' : ''} size={14} />}
              >
                Sync All Feeds
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => setShowAddFeedModal(true)}
                iconLeft={<FiPlus size={14} />}
              >
                Add Feed
              </Button>
            </div>
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Feed Name</th>
                  <th>Type</th>
                  <th>Sync Interval</th>
                  <th>Last Sync</th>
                  <th>Cached IoCs</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {feeds.map((feed) => (
                  <tr key={feed.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{feed.name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {feed.url}
                      </div>
                    </td>
                    <td>
                      <span className="badge badge-neutral" style={{ textTransform: 'uppercase' }}>{feed.feed_type}</span>
                    </td>
                    <td>Every {feed.interval_hours}h</td>
                    <td>{feed.last_sync_at ? new Date(feed.last_sync_at).toLocaleString() : 'Never'}</td>
                    <td style={{ fontWeight: 600 }}>{feed.indicator_count.toLocaleString()}</td>
                    <td>
                      <Badge
                        status={feed.status === 'success' ? 'online' : feed.status === 'syncing' ? 'warning' : 'offline'}
                        label={feed.status.toUpperCase()}
                      />
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleSyncFeed(feed.id)}
                          disabled={syncingFeedId === feed.id}
                        >
                          {syncingFeedId === feed.id ? 'Syncing...' : 'Sync Now'}
                        </Button>
                        <Button
                          variant={feed.enabled ? 'warning' : 'outline'}
                          size="sm"
                          onClick={() => handleToggleFeed(feed)}
                        >
                          {feed.enabled ? 'Disable' : 'Enable'}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: IOC DATABASE */}
      {activeTab === 'indicators' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', gap: '1rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: '0.75rem', flex: 1, maxWidth: '500px' }}>
              <input
                type="text"
                placeholder="Search IoC value, threat type, or source..."
                value={indicatorSearch}
                onChange={(e) => setIndicatorSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchIndicators()}
                style={{
                  flex: 1,
                  padding: '0.5rem 0.8rem',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              />
              <Button variant="primary" size="sm" onClick={fetchIndicators}>
                Search
              </Button>
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Total Active Indicators: <strong>{totalIndicators.toLocaleString()}</strong>
            </div>
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Threat Category</th>
                  <th>Confidence</th>
                  <th>Source Feed</th>
                  <th>Import Date</th>
                </tr>
              </thead>
              <tbody>
                {indicators.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '2rem' }}>No threat indicators found.</td>
                  </tr>
                ) : (
                  indicators.map((ind) => (
                    <tr key={ind.id}>
                      <td><span className="badge badge-neutral" style={{ textTransform: 'uppercase' }}>{ind.indicator_type}</span></td>
                      <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{ind.value}</td>
                      <td>{ind.threat_type}</td>
                      <td>
                        <Badge
                          status={ind.confidence >= 80 ? 'critical' : 'warning'}
                          label={`${ind.confidence}%`}
                        />
                      </td>
                      <td style={{ fontSize: '0.8rem' }}>{ind.source}</td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {new Date(ind.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem' }}>
            <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button>
            <span style={{ fontSize: '0.85rem' }}>Page {page + 1}</span>
            <Button variant="outline" size="sm" disabled={(page + 1) * 20 >= totalIndicators} onClick={() => setPage(page + 1)}>Next</Button>
          </div>
        </div>
      )}

      {/* Modal Add Feed */}
      {showAddFeedModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '450px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '1rem' }}>Add Threat Intelligence Feed</h3>
            <form onSubmit={handleCreateFeed} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Feed Name</label>
                <input
                  type="text"
                  required
                  value={newFeed.name}
                  onChange={(e) => setNewFeed({ ...newFeed, name: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Feed URL (Raw text / CSV)</label>
                <input
                  type="url"
                  required
                  value={newFeed.url}
                  onChange={(e) => setNewFeed({ ...newFeed, url: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                />
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Feed Type</label>
                <select
                  value={newFeed.feed_type}
                  onChange={(e) => setNewFeed({ ...newFeed, feed_type: e.target.value })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                >
                  <option value="ip">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="hash">File Hash</option>
                  <option value="url">Malicious URL</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Sync Interval (Hours)</label>
                <input
                  type="number"
                  min="1"
                  max="168"
                  value={newFeed.interval_hours}
                  onChange={(e) => setNewFeed({ ...newFeed, interval_hours: parseInt(e.target.value) || 6 })}
                  style={{ width: '100%', padding: '0.5rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', color: 'inherit' }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <Button variant="outline" size="sm" type="button" onClick={() => setShowAddFeedModal(false)}>Cancel</Button>
                <Button variant="primary" size="sm" type="submit">Save & Subscribe</Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
