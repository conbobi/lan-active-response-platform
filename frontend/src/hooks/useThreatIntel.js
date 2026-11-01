// src/hooks/useThreatIntel.js
import { useState } from 'react';
import { checkThreatIndicator } from '../api/threatIntel';

export const useThreatIntel = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const checkIndicator = async (indicatorType, value) => {
    setLoading(true);
    setError(null);
    try {
      const res = await checkThreatIndicator(indicatorType, value);
      setResult(res);
      return res;
    } catch (err) {
      setError(err.message || 'Error checking threat indicator');
      setResult(null);
      return null;
    } finally {
      setLoading(false);
    }
  };

  return {
    loading,
    error,
    result,
    checkIndicator,
  };
};

export default useThreatIntel;
