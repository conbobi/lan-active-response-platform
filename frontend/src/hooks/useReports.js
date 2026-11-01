// src/hooks/useReports.js
import { useState, useEffect, useCallback } from 'react';
import { getReports, generateReport, downloadReport } from '../api/reports';

export const useReports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getReports();
      setReports(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Failed to load reports:', err);
      setError(err.message || 'Failed to load reports');
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleGenerateReport = async (payload) => {
    setGenerating(true);
    try {
      const res = await generateReport(payload);
      await loadReports();
      return res;
    } catch (err) {
      console.error('Failed to generate report:', err);
      setError(err.message || 'Failed to generate report');
      throw err;
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadReport = (reportId) => {
    downloadReport(reportId);
  };

  return {
    reports,
    loading,
    generating,
    error,
    refreshReports: loadReports,
    generateReport: handleGenerateReport,
    downloadReport: handleDownloadReport,
  };
};

export default useReports;
