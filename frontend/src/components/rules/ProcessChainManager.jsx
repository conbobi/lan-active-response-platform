// src/components/rules/ProcessChainManager.jsx
import React, { useState } from 'react';
import FilterTabs from '../ui/FilterTabs';
import ProcessChainRulesTab from './ProcessChainRulesTab';
import ProcessGroupsTab from './ProcessGroupsTab';
import useProcessGroups from '../../hooks/useProcessGroups';
import useProcessChainRules from '../../hooks/useProcessChainRules';
import { FiCheckCircle, FiAlertTriangle } from 'react-icons/fi';

export default function ProcessChainManager() {
  const [subTab, setSubTab] = useState('rules');
  const [notice, setNotice] = useState(null);

  const {
    groups,
    loading: groupsLoading,
    error: groupsError,
    refreshGroups,
    handleCreateGroup,
    handleUpdateGroup,
    handleDeleteGroup,
  } = useProcessGroups();

  const {
    chainRules,
    loading: rulesLoading,
    error: rulesError,
    refreshChainRules,
    handleToggleActive,
    handleCreateChainRule,
    handleUpdateChainRule,
    handleDeleteChainRule,
  } = useProcessChainRules();

  const showNotice = (msg, isError = false) => {
    setNotice({ msg, isError });
    setTimeout(() => setNotice(null), 5000);
  };

  const tabs = [
    { value: 'rules', label: 'Process Chain Rules', count: chainRules.length },
    { value: 'groups', label: 'Process Groups', count: groups.length },
  ];

  return (
    <div>
      {notice && (
        <div
          style={{
            marginBottom: '1rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-md, 6px)',
            background: notice.isError ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 192, 123, 0.15)',
            border: `1px solid ${notice.isError ? 'var(--error)' : 'var(--success)'}`,
            color: notice.isError ? 'var(--error)' : 'var(--success)',
            fontSize: '0.875rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          {notice.isError ? <FiAlertTriangle size={16} /> : <FiCheckCircle size={16} />}
          {notice.msg}
        </div>
      )}

      {/* Subtabs bar */}
      <div style={{ marginBottom: '1.25rem' }}>
        <FilterTabs tabs={tabs} active={subTab} onChange={setSubTab} />
      </div>

      {subTab === 'rules' ? (
        <ProcessChainRulesTab
          chainRules={chainRules}
          groups={groups}
          loading={rulesLoading}
          error={rulesError}
          refreshChainRules={refreshChainRules}
          handleToggleActive={handleToggleActive}
          handleCreateChainRule={handleCreateChainRule}
          handleUpdateChainRule={handleUpdateChainRule}
          handleDeleteChainRule={handleDeleteChainRule}
          onSwitchToGroupsTab={() => setSubTab('groups')}
          onNotice={showNotice}
        />
      ) : (
        <ProcessGroupsTab
          groups={groups}
          loading={groupsLoading}
          error={groupsError}
          refreshGroups={refreshGroups}
          handleCreateGroup={handleCreateGroup}
          handleUpdateGroup={handleUpdateGroup}
          handleDeleteGroup={handleDeleteGroup}
          onNotice={showNotice}
        />
      )}
    </div>
  );
}
