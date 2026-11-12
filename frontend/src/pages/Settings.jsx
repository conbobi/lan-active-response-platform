import React, { useState, useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import useSettings from '../hooks/useSettings';
import Button from '../components/ui/Button';
import CollapsibleSection from '../components/ui/CollapsibleSection';
import Whitelist from './Whitelist';
import Notifications from './Notifications';
import Reports from './Reports';
import DockerMonitorTable from '../components/ui/DockerMonitorTable';
import { getDockerStatus } from '../api/docker';
import {
  FiSave,
  FiShield,
  FiSliders,
  FiFileText,
  FiCheckSquare,
  FiBell,
  FiActivity,
  FiRotateCw,
  FiCheck,
  FiEye,
  FiAlertTriangle,
  FiZap,
} from 'react-icons/fi';

const SETTINGS_TABS = [
  { id: 'thresholds', label: 'Thresholds & Automation', icon: FiSliders },
  { id: 'whitelist', label: 'Process & IP Exclusions', icon: FiCheckSquare },
  { id: 'notifications', label: 'Alert Channels & Webhooks', icon: FiBell },
  { id: 'reports', label: 'Executive Reports', icon: FiFileText },
  { id: 'system', label: 'System & Docker Health', icon: FiActivity },
];

export default function Settings({ initialTab }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryTab = searchParams.get('tab') || initialTab || 'thresholds';
  const [activeTab, setActiveTab] = useState(queryTab);

  useEffect(() => {
    if (queryTab && queryTab !== activeTab) {
      setActiveTab(queryTab);
    }
  }, [queryTab]);

  const switchTab = (tabId) => {
    setActiveTab(tabId);
    setSearchParams((prev) => {
      const p = new URLSearchParams(prev);
      p.set('tab', tabId);
      return p;
    });
  };

  // Settings hook
  const {
    settings,
    loading: settingsLoading,
    saving,
    updateSettingKey,
    updateRiskThresholds,
    updateFileChangesThresholds,
  } = useSettings();

  // Mode state: 'monitor' | 'semi' | 'auto'
  const [mode, setMode] = useState('auto');

  // Sliders state
  const [alertThreshold, setAlertThreshold] = useState(50);
  const [suggestAt, setSuggestAt] = useState(70);
  const [autoAt, setAutoAt] = useState(85);
  const [logThreshold, setLogThreshold] = useState(20);

  // Advanced File changes thresholds
  const [fileCritical, setFileCritical] = useState(100);
  const [fileElevated, setFileElevated] = useState(30);

  // Advanced Notifications
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [adminEmail, setAdminEmail] = useState('admin@larp-soc.lan');
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Docker status state for System Health tab
  const [dockerContainers, setDockerContainers] = useState([]);
  const [dockerLoading, setDockerLoading] = useState(false);
  const [dockerError, setDockerError] = useState(null);

  const fetchDocker = async () => {
    setDockerLoading(true);
    setDockerError(null);
    try {
      const data = await getDockerStatus();
      setDockerContainers(data.containers || []);
    } catch (err) {
      setDockerError(err.message || 'Failed to fetch container telemetry');
    } finally {
      setDockerLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'system') {
      fetchDocker();
    }
  }, [activeTab]);

  // Load initial settings
  useEffect(() => {
    if (settings) {
      const isAuto = settings.auto_response_enabled !== false;
      const btnTh = settings.risk_thresholds?.alert_with_buttons ?? 70;
      if (isAuto) {
        setMode('auto');
      } else if (btnTh < 900) {
        setMode('semi');
      } else {
        setMode('monitor');
      }

      if (settings.risk_thresholds) {
        setAlertThreshold(settings.risk_thresholds.alert ?? 50);
        setSuggestAt(btnTh < 900 ? btnTh : 70);
        setAutoAt(settings.risk_thresholds.auto_kill_threshold ?? 85);
        setLogThreshold(settings.risk_thresholds.log ?? 20);
      }
      if (settings.file_changes_thresholds) {
        setFileCritical(settings.file_changes_thresholds.file_changes_critical ?? 100);
        setFileElevated(settings.file_changes_thresholds.file_changes_elevated ?? 30);
      }
      setNotifyEmail(settings.email_notifications_enabled ?? true);
      setAdminEmail(settings.admin_email || 'admin@larp-soc.lan');
    }
  }, [settings]);

  // Save changes
  const handleSaveAll = async () => {
    let autoResponseVal = true;
    let alertWithButtonsVal = Number(suggestAt);
    let autoKillVal = Number(autoAt);
    let autoIsolateVal = Number(autoAt);

    if (mode === 'monitor') {
      autoResponseVal = false;
      alertWithButtonsVal = 999;
    } else if (mode === 'semi') {
      autoResponseVal = false;
      alertWithButtonsVal = Number(suggestAt);
    } else {
      autoResponseVal = true;
      alertWithButtonsVal = Number(suggestAt);
      autoKillVal = Number(autoAt);
      autoIsolateVal = Number(autoAt);
    }

    await updateRiskThresholds({
      incident_creation_threshold: Number(alertThreshold),
      auto_kill_threshold: autoKillVal,
      auto_isolate: autoIsolateVal,
      alert_with_buttons: alertWithButtonsVal,
      alert: Number(alertThreshold),
      log: Number(logThreshold),
    });

    await updateFileChangesThresholds({
      file_changes_critical: Number(fileCritical),
      file_changes_elevated: Number(fileElevated),
    });

    await updateSettingKey('auto_response_enabled', autoResponseVal);
    await updateSettingKey('email_notifications_enabled', notifyEmail);
    await updateSettingKey('admin_email', adminEmail);

    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  // Preview messages for timeline
  const previewData = useMemo(() => {
    let autoActionMsg = '';
    if (mode === 'auto') {
      autoActionMsg = `🔴 AUTO: Tự động cách ly mạng & diệt process tree (score >= ${autoAt})`;
    } else if (mode === 'semi') {
      autoActionMsg = `🟡 SEMI: Tạo incident rủi ro cao + hiển thị AI gợi ý, chờ Analyst bấm Apply`;
    } else {
      autoActionMsg = `🟢 MONITOR: Ghi nhận incident rủi ro cao, KHÔNG tự động can thiệp`;
    }

    return [
      { score: 'Score < ' + alertThreshold, text: '• Ghi log telemetry kiểm toán' },
      { score: `Score >= ${alertThreshold}`, text: `• Tạo incident + Gửi Alert cho SOC Analyst` },
      {
        score: `Score >= ${suggestAt}`,
        text:
          mode === 'monitor'
            ? '• Cảnh báo ưu tiên cao (chế độ giám sát thụ động)'
            : '• Alert + hiển thị gợi ý hành động & nút thao tác nhanh (Isolate/Kill)',
      },
      { score: `Score >= ${autoAt}`, text: `• ${autoActionMsg}` },
    ];
  }, [mode, alertThreshold, suggestAt, autoAt]);

  const MODES = [
    {
      id: 'monitor',
      title: 'Monitor Only',
      tag: '🟢 Chỉ cảnh báo',
      desc: 'Chỉ ghi log & tạo alert cảnh báo. Tuyệt đối KHÔNG tự động can thiệp hay chặn máy trạm.',
      border: '#10b981',
      bg: 'rgba(16, 185, 129, 0.08)',
      icon: FiEye,
    },
    {
      id: 'semi',
      title: 'Semi-Auto',
      tag: '🟡 Alert + Gợi ý',
      desc: 'Tự động alert + AI gợi ý action phản ứng. Chờ Analyst bấm xác nhận trước khi dispatch.',
      border: '#f59e0b',
      bg: 'rgba(245, 158, 11, 0.08)',
      icon: FiAlertTriangle,
    },
    {
      id: 'auto',
      title: 'Full Auto',
      tag: '🔴 Tự động chặn',
      desc: 'Tự động cô lập host và kill process độc hại khi điểm rủi ro vượt ngưỡng an toàn.',
      border: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.08)',
      icon: FiZap,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', paddingBottom: '2.5rem' }}>
      {/* Page Header */}
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <h1 className="page-title">Platform Settings & Administration</h1>
          <p className="page-subtitle">
            Cấu hình chế độ phản ứng tự động, ngưỡng rủi ro, danh sách loại trừ và hạ tầng giám sát
          </p>
        </div>
        {activeTab === 'thresholds' && (
          <Button
            variant="primary"
            size="md"
            iconLeft={<FiSave size={14} />}
            onClick={handleSaveAll}
            disabled={saving}
          >
            {saving ? 'Saving...' : savedSuccess ? '✓ Settings Saved' : 'Save Changes'}
          </Button>
        )}
      </div>

      {/* Settings Navigation Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '0.4rem',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '0.5rem',
          overflowX: 'auto',
        }}
      >
        {SETTINGS_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => switchTab(tab.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.55rem 1rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                background: isActive ? 'var(--primary)' : 'transparent',
                color: isActive ? '#fff' : 'var(--text-secondary)',
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
              }}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab Contents */}
      {activeTab === 'thresholds' && (
        <div style={{ maxWidth: 900 }}>
          {settingsLoading ? (
            <div className="card skeleton" style={{ height: '350px' }} />
          ) : (
            <>
              {/* 1. Response Mode Selection (3 Cards) */}
              <div
                className="card"
                style={{
                  marginBottom: '1.25rem',
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md, 8px)',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <FiShield size={18} style={{ color: 'var(--primary)' }} />
                  <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>🎯 Response Mode (Chọn 1 trong 3)</div>
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                  Xác định cách thức EDR phản ứng khi phát hiện hành vi tấn công hoặc bất thường rủi ro cao.
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '1rem',
                  }}
                >
                  {MODES.map((m) => {
                    const isSelected = mode === m.id;
                    const Icon = m.icon;
                    return (
                      <div
                        key={m.id}
                        onClick={() => setMode(m.id)}
                        style={{
                          padding: '1.1rem',
                          borderRadius: 'var(--radius-md, 8px)',
                          border: isSelected ? `2px solid ${m.border}` : '1px solid var(--border)',
                          background: isSelected ? m.bg : 'var(--bg-primary)',
                          cursor: 'pointer',
                          transition: 'all 0.2s ease',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.65rem',
                          position: 'relative',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span
                            style={{
                              fontSize: '0.78rem',
                              fontWeight: 700,
                              padding: '0.2rem 0.55rem',
                              borderRadius: '4px',
                              background: 'rgba(255,255,255,0.06)',
                              color: m.border,
                            }}
                          >
                            {m.tag}
                          </span>
                          {isSelected && (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                width: 22,
                                height: 22,
                                borderRadius: '50%',
                                background: m.border,
                                color: '#fff',
                              }}
                            >
                              <FiCheck size={14} />
                            </span>
                          )}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Icon size={20} style={{ color: m.border }} />
                          <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                            {m.title}
                          </div>
                        </div>

                        <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                          {m.desc}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* 2. Risk Score Timeline & Sliders (Hiển thị khi Semi-Auto hoặc Full-Auto, hoặc điều chỉnh ngưỡng) */}
              <div
                className="card"
                style={{
                  marginBottom: '1.25rem',
                  padding: '1.25rem',
                  borderRadius: 'var(--radius-md, 8px)',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                }}
              >
                <div style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                  📊 Risk Score Timeline & Thresholds
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                  Cân chỉnh các mốc điểm kích hoạt hành động phản ứng theo từng cấp độ nguy cơ.
                </div>

                {/* Visual Timeline Bar */}
                <div
                  style={{
                    background: 'var(--bg-primary)',
                    borderRadius: '8px',
                    padding: '1rem 1.25rem',
                    marginBottom: '1.5rem',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                      marginBottom: '0.5rem',
                    }}
                  >
                    <span>Score: 0</span>
                    <span style={{ color: 'var(--primary)' }}>50 (Alert)</span>
                    <span style={{ color: 'var(--warning)' }}>70 (Gợi ý)</span>
                    <span style={{ color: 'var(--error)' }}>85 (Auto chặn)</span>
                    <span>100</span>
                  </div>

                  <div
                    style={{
                      height: 8,
                      width: '100%',
                      background: 'linear-gradient(to right, #10b981 0%, #3b82f6 40%, #f59e0b 70%, #ef4444 100%)',
                      borderRadius: 4,
                      position: 'relative',
                    }}
                  />
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '0.75rem',
                      color: 'var(--text-secondary)',
                      marginTop: '0.4rem',
                    }}
                  >
                    <span>Log</span>
                    <span>Alert</span>
                    <span>Gợi ý Action</span>
                    <span>Auto Chặn</span>
                  </div>
                </div>

                {/* Slider Controls */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                  {/* Alert Slider */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                        Alert Analyst khi score &ge; [{alertThreshold}]
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Tự động tạo sự cố an ninh và gửi cảnh báo tới SOC dashboard
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <input
                        type="range"
                        min={30}
                        max={80}
                        value={alertThreshold}
                        onChange={(e) => setAlertThreshold(+e.target.value)}
                        style={{ width: 160, accentColor: 'var(--primary)' }}
                      />
                      <span
                        style={{
                          fontWeight: 700,
                          color: 'var(--primary)',
                          minWidth: 36,
                          textAlign: 'right',
                        }}
                      >
                        {alertThreshold}
                      </span>
                    </div>
                  </div>

                  {/* Suggest Action Slider */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                        Gợi ý action & nút thao tác khi score &ge; [{suggestAt}]
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Kích hoạt AI Assistant gợi ý và mở nút hành động nhanh (Isolate/Kill)
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <input
                        type="range"
                        min={50}
                        max={90}
                        value={suggestAt}
                        onChange={(e) => setSuggestAt(+e.target.value)}
                        style={{ width: 160, accentColor: '#f59e0b' }}
                      />
                      <span
                        style={{
                          fontWeight: 700,
                          color: '#f59e0b',
                          minWidth: 36,
                          textAlign: 'right',
                        }}
                      >
                        {suggestAt}
                      </span>
                    </div>
                  </div>

                  {/* Auto Block Slider (Active when Full Auto) */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '0.75rem',
                      opacity: mode === 'auto' ? 1 : 0.5,
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                        🔴 Auto chặn (Kill & Isolate) khi score &ge; [{autoAt}]
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        {mode === 'auto'
                          ? 'Tự động dispatch cô lập mạng và diệt tiến trình độc hại'
                          : 'Chỉ có hiệu lực khi bật chế độ Full Auto'}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <input
                        type="range"
                        min={70}
                        max={100}
                        value={autoAt}
                        disabled={mode !== 'auto'}
                        onChange={(e) => setAutoAt(+e.target.value)}
                        style={{ width: 160, accentColor: '#ef4444' }}
                      />
                      <span
                        style={{
                          fontWeight: 700,
                          color: '#ef4444',
                          minWidth: 36,
                          textAlign: 'right',
                        }}
                      >
                        {autoAt}
                      </span>
                    </div>
                  </div>
                </div>

                {/* 📖 Live Preview Box */}
                <div
                  style={{
                    marginTop: '1.5rem',
                    background: 'var(--bg-primary)',
                    borderRadius: '8px',
                    padding: '1rem 1.25rem',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '0.88rem',
                      fontWeight: 700,
                      marginBottom: '0.65rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem',
                    }}
                  >
                    <span>📖 Preview kịch bản xử lý ({mode.toUpperCase()} MODE):</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.82rem' }}>
                    {previewData.map((item, idx) => (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          alignItems: 'baseline',
                          gap: '0.5rem',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)', minWidth: 100 }}>
                          {item.score}
                        </span>
                        <span>{item.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* 3. Advanced Settings (Collapsible, collapsed by default) */}
              <CollapsibleSection
                title="File Change Thresholds (Ransomware FIM)"
                desc="Cấu hình ngưỡng số lượng file sửa đổi hàng loạt để nhận diện hành vi mã hoá Ransomware"
                defaultOpen={false}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '1rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Critical File Changes Threshold</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Ngưỡng số tệp thay đổi tối đa kích hoạt cảnh báo nguy cơ nghiêm trọng (mặc định: 100)
                      </div>
                    </div>
                    <input
                      type="number"
                      min="10"
                      max="10000"
                      value={fileCritical}
                      onChange={(e) => setFileCritical(+e.target.value)}
                      style={{
                        width: 100,
                        padding: '0.4rem 0.6rem',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-primary)',
                        fontWeight: 600,
                      }}
                    />
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '1rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Elevated File Changes Threshold</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Ngưỡng số tệp thay đổi bất thường mức độ cảnh giác (mặc định: 30)
                      </div>
                    </div>
                    <input
                      type="number"
                      min="5"
                      max="1000"
                      value={fileElevated}
                      onChange={(e) => setFileElevated(+e.target.value)}
                      style={{
                        width: 100,
                        padding: '0.4rem 0.6rem',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-primary)',
                        fontWeight: 600,
                      }}
                    />
                  </div>
                </div>
              </CollapsibleSection>

              <CollapsibleSection
                title="Notification Settings & Channels"
                desc="Cấu hình gửi email cảnh báo tự động tới đội ngũ phản ứng sự cố SOC"
                defaultOpen={false}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '1rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>Email Notifications Dispatch</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Gửi cảnh báo sự cố nghiêm trọng qua email đến SOC team
                      </div>
                    </div>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={notifyEmail}
                        onChange={(e) => setNotifyEmail(e.target.checked)}
                      />
                      <span className="switch-slider" />
                    </label>
                  </div>

                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: '1rem',
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>SOC Admin Email Address</div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        Địa chỉ email người nhận cảnh báo khẩn cấp và báo cáo tự động
                      </div>
                    </div>
                    <input
                      type="email"
                      value={adminEmail}
                      onChange={(e) => setAdminEmail(e.target.value)}
                      style={{
                        width: 240,
                        padding: '0.45rem 0.65rem',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-primary)',
                        fontSize: '0.85rem',
                      }}
                    />
                  </div>
                </div>
              </CollapsibleSection>
            </>
          )}
        </div>
      )}

      {activeTab === 'whitelist' && <Whitelist embedded={true} />}

      {activeTab === 'notifications' && <Notifications embedded={true} />}

      {activeTab === 'reports' && <Reports embedded={true} />}

      {activeTab === 'system' && (
        <div>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '1rem',
            }}
          >
            <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Backend Microservices & Docker Infrastructure Telemetry
            </span>
            <Button
              variant="outline"
              size="sm"
              iconLeft={<FiRotateCw size={14} className={dockerLoading ? 'spin' : ''} />}
              onClick={fetchDocker}
            >
              Refresh Containers
            </Button>
          </div>
          <DockerMonitorTable
            containers={dockerContainers}
            loading={dockerLoading}
            error={dockerError}
            onRefresh={fetchDocker}
          />
        </div>
      )}
    </div>
  );
}
