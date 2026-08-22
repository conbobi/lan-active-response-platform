import { useState, useEffect, useMemo, useCallback } from 'react';
import { getRules as apiGetRules, addRule as apiAddRule, deleteRule as apiDeleteRule } from '../api/rules';
import {
  getRules as mockGetRules,
  getAuditLogs,
  addRule as mockAddRule,
  updateRule as apiUpdateRule,
  deleteRule as mockDeleteRule,
  toggleRuleStatus as apiToggleRuleStatus,
  checkRuleConflicts,
  simulateRuleTest,
  importRulesList,
} from '../mock/rules';

export const useRules = (initialPageSize = 8) => {
  const [rulesList, setRulesList] = useState([]);
  const [auditLogsList, setAuditLogsList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [page, setPage] = useState(1);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      let data = await apiGetRules();
      if (!data || data.length === 0) {
        data = await mockGetRules();
      }
      const logs = await getAuditLogs();
      setRulesList(data);
      setAuditLogsList(logs);
    } catch (err) {
      console.error('Failed to fetch rules', err);
      const fallback = await mockGetRules();
      setRulesList(fallback);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // Filter rules
  const filteredRules = useMemo(() => {
    return rulesList.filter((rule) => {
      const matchesSearch =
        !search ||
        rule.name.toLowerCase().includes(search.toLowerCase()) ||
        rule.description.toLowerCase().includes(search.toLowerCase()) ||
        rule.id.toLowerCase().includes(search.toLowerCase());

      const matchesType = typeFilter === 'all' || rule.type === typeFilter;
      const matchesSeverity = severityFilter === 'all' || rule.severity === severityFilter;
      const matchesStatus = statusFilter === 'all' || rule.status === statusFilter;

      return matchesSearch && matchesType && matchesSeverity && matchesStatus;
    });
  }, [rulesList, search, typeFilter, severityFilter, statusFilter]);

  // Reset page to 1 when filters change
  useEffect(() => {
    setPage(1);
  }, [search, typeFilter, severityFilter, statusFilter]);

  const totalPages = Math.ceil(filteredRules.length / initialPageSize) || 1;
  const paginatedRules = useMemo(() => {
    const start = (page - 1) * initialPageSize;
    return filteredRules.slice(start, start + initialPageSize);
  }, [filteredRules, page, initialPageSize]);

  // Actions
  const createRule = async (ruleData, user = 'admin') => {
    const created = await apiAddRule(ruleData, user);
    await fetchRules();
    return created;
  };

  const editRule = async (id, updatedFields, user = 'admin') => {
    const updated = await apiUpdateRule(id, updatedFields, user);
    await fetchRules();
    return updated;
  };

  const removeRule = async (id, user = 'admin') => {
    await apiDeleteRule(id, user);
    await fetchRules();
  };

  const toggleRule = async (id, user = 'admin') => {
    await apiToggleRuleStatus(id, user);
    await fetchRules();
  };

  const checkConflicts = (ruleCandidate) => {
    return checkRuleConflicts(ruleCandidate);
  };

  const testSimulation = (payload) => {
    return simulateRuleTest(payload);
  };

  const exportRulesJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rulesList, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `larp_security_rules_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const importRulesJson = async (jsonArray, user = 'admin') => {
    const count = await importRulesList(jsonArray, user);
    await fetchRules();
    return count;
  };

  return {
    rules: paginatedRules,
    allRules: rulesList,
    auditLogs: auditLogsList,
    filteredCount: filteredRules.length,
    totalCount: rulesList.length,
    loading,
    search,
    setSearch,
    typeFilter,
    setTypeFilter,
    severityFilter,
    setSeverityFilter,
    statusFilter,
    setStatusFilter,
    page,
    setPage,
    totalPages,
    createRule,
    editRule,
    removeRule,
    toggleRule,
    checkConflicts,
    testSimulation,
    exportRulesJson,
    importRulesJson,
    refetch: fetchRules,
  };
};

export default useRules;
