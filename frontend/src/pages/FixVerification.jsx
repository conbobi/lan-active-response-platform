// src/pages/FixVerification.jsx
import React, { useState, useEffect } from 'react';
import { verifyPhase2 } from '../api/risk';
import { FiCheckCircle, FiXCircle, FiRefreshCw, FiShield, FiInfo } from 'react-icons/fi';

export function CheckItem({ label, status, detail }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        padding: '16px',
        borderRadius: '8px',
        backgroundColor: status ? '#f0fdf4' : '#fef2f2',
        border: status ? '1px solid #bbf7d0' : '1px solid #fecaca'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '24px', display: 'flex' }}>
          {status ? (
            <FiCheckCircle style={{ color: '#16a34a' }} />
          ) : (
            <FiXCircle style={{ color: '#dc2626' }} />
          )}
        </span>
        <div>
          <div style={{ fontWeight: 600, fontSize: '15px', color: status ? '#14532d' : '#7f1d1d' }}>
            {label}
          </div>
          {detail && (
            <div style={{ fontSize: '13px', color: '#64748b', marginTop: '2px' }}>
              {detail}
            </div>
          )}
        </div>
      </div>
      <span
        style={{
          padding: '4px 10px',
          borderRadius: '9999px',
          fontSize: '12px',
          fontWeight: 700,
          backgroundColor: status ? '#dcfce7' : '#fee2e2',
          color: status ? '#15803d' : '#b91c1c'
        }}
      >
        {status ? 'PASS' : 'FAIL'}
      </span>
    </div>
  );
}

export default function FixVerification() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function runCheck() {
    try {
      setLoading(true);
      setError(null);
      const data = await verifyPhase2();
      setResults(data);
    } catch (err) {
      setError(err.message || 'Không thể kết nối đến API verify-phase2');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    runCheck();
  }, []);

  const allPassed =
    results &&
    results.manager_ip_bypassed &&
    results.idle_agents_safe &&
    results.baseline_fresh &&
    results.ema_working;

  return (
    <div style={{ padding: '24px', maxWidth: '1000px', margin: '0 auto', color: '#1e293b' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FiShield style={{ color: '#2563eb' }} /> Phase 2 Fix Verification Dashboard
          </h1>
          <p style={{ color: '#64748b', fontSize: '14px', marginTop: '4px' }}>
            Kiểm tra và nghiệm thu tự động các bản vá: HttpBeaconing Manager IP bypass, Category Cap, và EMA Smoothing.
          </p>
        </div>
        <button
          onClick={runCheck}
          disabled={loading}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: '#2563eb',
            color: '#fff',
            padding: '10px 18px',
            borderRadius: '6px',
            border: 'none',
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: '14px',
            boxShadow: '0 2px 4px rgba(37,99,235,0.2)'
          }}
        >
          <FiRefreshCw className={loading ? 'animate-spin' : ''} />
          {loading ? 'Đang kiểm tra...' : 'Chạy kiểm tra'}
        </button>
      </div>

      {error && (
        <div style={{ backgroundColor: '#fee2e2', color: '#b91c1c', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px' }}>
          ⚠️ Lỗi: {error}
        </div>
      )}

      {results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div
            style={{
              padding: '16px 20px',
              borderRadius: '8px',
              backgroundColor: allPassed ? '#f0fdf4' : '#fffbeb',
              border: allPassed ? '2px solid #22c55e' : '2px solid #f59e0b',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}
          >
            <div>
              <div style={{ fontWeight: 700, fontSize: '18px', color: allPassed ? '#15803d' : '#b45309' }}>
                {allPassed ? '🎉 TẤT CẢ CÁC TIÊU CHÍ VERIFY ĐÃ PASS!' : '⚠️ CẦN CHỜ THÊM TELEMETRY HOẶC KIỂM TRA LẠI'}
              </div>
              <div style={{ fontSize: '13px', color: '#64748b', marginTop: '4px' }}>
                {allPassed
                  ? 'Hệ thống đã loại bỏ hoàn toàn false positive từ kết nối Manager và áp dụng EMA mượt mà.'
                  : 'Một số tiêu chuẩn có thể cần 1-2 phút chu kỳ để đồng bộ sạch dữ liệu cũ.'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <CheckItem
              label="1. Manager IP không còn trong beaconing"
              status={results.manager_ip_bypassed}
              detail={`Số bản ghi bắt nhầm Manager IP trong 5 phút qua: ${results.details?.manager_ip_records ?? 0} (yêu cầu: 0)`}
            />

            <CheckItem
              label="2. Idle agents có score < 5 (Loại trừ False Positive)"
              status={results.idle_agents_safe}
              detail={`Điểm tối đa của các agent nhàn rỗi (client1-client4): ${results.details?.max_idle_score ?? 0} (yêu cầu: < 5.0)`}
            />

            <CheckItem
              label="3. Baseline ML đã retrain (< 1h)"
              status={results.baseline_fresh}
              detail={`Thời điểm cập nhật baseline mới nhất: ${results.details?.latest_baseline ?? 'Chưa có'} (yêu cầu: < 1 giờ)`}
            />

            <CheckItem
              label="4. Smoothed score khác raw score (EMA đang hoạt động)"
              status={results.ema_working}
              detail={`Số bản ghi thể hiện độ chênh làm mượt (|raw - smooth| > 0.01): ${results.details?.ema_diff_records ?? 0} (yêu cầu: > 0)`}
            />
          </div>

          {/* Details JSON */}
          <div
            style={{
              marginTop: '16px',
              backgroundColor: '#fff',
              borderRadius: '8px',
              border: '1px solid #e2e8f0',
              padding: '16px'
            }}
          >
            <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <FiInfo style={{ color: '#64748b' }} /> Chi tiết phản hồi từ Backend (Diagnostic Payload)
            </h3>
            <pre
              style={{
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                padding: '12px',
                borderRadius: '6px',
                fontSize: '12px',
                overflowX: 'auto'
              }}
            >
              {JSON.stringify(results, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
