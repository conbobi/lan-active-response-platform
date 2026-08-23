// src/pages/Reports.jsx
import React, { useState } from 'react';
import useReports from '../hooks/useReports';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import Dropdown from '../components/ui/Dropdown';
import { FiFileText, FiDownload, FiPlusCircle, FiRotateCw } from 'react-icons/fi';

const MONTH_OPTIONS = [
  { value: '1', label: 'January' },
  { value: '2', label: 'February' },
  { value: '3', label: 'March' },
  { value: '4', label: 'April' },
  { value: '5', label: 'May' },
  { value: '6', label: 'June' },
  { value: '7', label: 'July' },
  { value: '8', label: 'August' },
  { value: '9', label: 'September' },
  { value: '10', label: 'October' },
  { value: '11', label: 'November' },
  { value: '12', label: 'December' },
];

export default function Reports() {
  const { reports, loading, generating, refreshReports, generateReport, downloadReport } = useReports();
  const [modalOpen, setModalOpen] = useState(false);
  const [selectedMonth, setSelectedMonth] = useState('8');
  const [selectedYear, setSelectedYear] = useState('2026');

  const onGenerateSubmit = async (e) => {
    e.preventDefault();
    await generateReport({
      month: Number(selectedMonth),
      year: Number(selectedYear),
    });
    setModalOpen(false);
  };

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Executive SOC Reports</h1>
        </div>
        <div className="card skeleton" style={{ height: '350px' }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Executive SOC Reports</h1>
          <p className="page-subtitle">Generate and download monthly SOC incident, risk trend, and network health reports</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <Button variant="outline" iconLeft={<FiRotateCw size={15} />} onClick={refreshReports}>
            Refresh
          </Button>
          <Button variant="primary" iconLeft={<FiPlusCircle size={15} />} onClick={() => setModalOpen(true)}>
            Generate New Report
          </Button>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.85rem 1.25rem' }}>Report ID</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Period</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Generated At</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Total Incidents</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Average Risk Index</th>
                <th style={{ padding: '0.85rem 1.25rem' }}>Status</th>
                <th style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                    No generated reports available
                  </td>
                </tr>
              ) : (
                reports.map((rep) => (
                  <tr key={rep.report_id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 700, color: 'var(--primary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <FiFileText size={16} />
                        {rep.report_id}
                      </div>
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>
                      {MONTH_OPTIONS.find((m) => m.value === String(rep.month))?.label || `Month ${rep.month}`} {rep.year}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-tertiary)', fontSize: '0.8rem' }}>
                      {new Date(rep.generated_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600 }}>
                      {rep.total_incidents} incidents
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600, color: 'var(--warning)' }}>
                      {rep.risk_index}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      <Badge status="online" label={rep.status || 'COMPLETED'} />
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'right' }}>
                      <Button
                        variant="outline"
                        size="sm"
                        iconLeft={<FiDownload size={14} />}
                        onClick={() => downloadReport(rep.report_id)}
                      >
                        Download PDF
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Generate Report Modal */}
      <Modal isOpen={modalOpen} onClose={() => setModalOpen(false)} title="Generate Monthly SOC Report">
        <form onSubmit={onGenerateSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Dropdown
            label="Select Month"
            options={MONTH_OPTIONS}
            value={selectedMonth}
            onChange={setSelectedMonth}
          />

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.25rem' }}>
              Select Year
            </label>
            <input
              type="number"
              value={selectedYear}
              onChange={(e) => setSelectedYear(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                color: 'var(--text-primary)',
              }}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={generating} iconLeft={<FiFileText size={15} />}>
              {generating ? 'Generating PDF...' : 'Generate Report'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
