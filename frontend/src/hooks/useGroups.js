// src/hooks/useGroups.js
import { useState, useCallback, useEffect } from 'react';
import {
  listGroups,
  getGroup,
  createGroup as apiCreateGroup,
  updateGroup as apiUpdateGroup,
  deleteGroup as apiDeleteGroup,
  addAgentToGroup as apiAddAgentToGroup,
  removeAgentFromGroup as apiRemoveAgentFromGroup,
  executeGroupAction,
  undoAllGroupActions,
} from '../api/groups';

export const useGroups = ({ autoFetch = true } = {}) => {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchGroups = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listGroups();
      const rawGroups = Array.isArray(data) ? data : [];
      // Enrich with isolation status and member list in parallel
      const enriched = await Promise.all(
        rawGroups.map(async (grp) => {
          try {
            if (!grp.member_count) {
              return { ...grp, has_isolated_agents: false, members: [] };
            }
            const detail = await getGroup(grp.id);
            const hasIsolated = detail.members?.some((m) => m.is_isolated === true);
            return { ...grp, has_isolated_agents: !!hasIsolated, members: detail.members || [] };
          } catch {
            return { ...grp, has_isolated_agents: false, members: [] };
          }
        })
      );
      setGroups(enriched);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch agent groups', err);
      setError(err.message || 'Failed to fetch agent groups');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (autoFetch) {
      fetchGroups();
    }
  }, [autoFetch, fetchGroups]);

  const fetchGroupDetail = useCallback(async (groupId) => {
    if (!groupId) {
      setSelectedGroup(null);
      return null;
    }
    setDetailLoading(true);
    try {
      const data = await getGroup(groupId);
      setSelectedGroup(data);
      return data;
    } catch (err) {
      console.error(`Failed to fetch detail for group ${groupId}`, err);
      setError(err.message || 'Failed to fetch group details');
      return null;
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const handleCreateGroup = async (data) => {
    setActionLoading(true);
    try {
      const newGroup = await apiCreateGroup(data);
      // Optimistic addition
      setGroups((prev) => [...prev, newGroup]);
      await fetchGroups();
      return newGroup;
    } catch (err) {
      console.error('Failed to create group', err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleUpdateGroup = async (groupId, data) => {
    setActionLoading(true);
    try {
      const updated = await apiUpdateGroup(groupId, data);
      setGroups((prev) =>
        prev.map((g) => (g.id === groupId ? { ...g, ...updated } : g))
      );
      if (selectedGroup?.id === groupId) {
        setSelectedGroup((prev) => ({ ...prev, ...updated }));
      }
      return updated;
    } catch (err) {
      console.error(`Failed to update group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteGroup = async (groupId) => {
    setActionLoading(true);
    try {
      await apiDeleteGroup(groupId);
      setGroups((prev) => prev.filter((g) => g.id !== groupId));
      if (selectedGroup?.id === groupId) {
        setSelectedGroup(null);
      }
    } catch (err) {
      console.error(`Failed to delete group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddMember = async (groupId, agentIds) => {
    setActionLoading(true);
    try {
      const updatedDetail = await apiAddAgentToGroup(groupId, agentIds);
      setSelectedGroup(updatedDetail);
      // Cập nhật member_count trong danh sách tổng
      setGroups((prev) =>
        prev.map((g) =>
          g.id === groupId
            ? { ...g, member_count: updatedDetail.members?.length ?? (g.member_count + 1) }
            : g
        )
      );
      return updatedDetail;
    } catch (err) {
      console.error(`Failed to add agent to group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemoveMember = async (groupId, agentId) => {
    setActionLoading(true);
    try {
      await apiRemoveAgentFromGroup(groupId, agentId);
      if (selectedGroup?.id === groupId) {
        setSelectedGroup((prev) => ({
          ...prev,
          members: prev.members?.filter((m) => m.agent_id !== agentId) || [],
        }));
      }
      setGroups((prev) =>
        prev.map((g) =>
          g.id === groupId
            ? { ...g, member_count: Math.max(0, (g.member_count || 1) - 1) }
            : g
        )
      );
    } catch (err) {
      console.error(`Failed to remove agent ${agentId} from group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleBatchIsolate = async (groupId, reason, autoRollbackSecs = 300) => {
    setActionLoading(true);
    try {
      const res = await executeGroupAction(groupId, 'isolate', { reason }, autoRollbackSecs);
      await fetchGroupDetail(groupId);
      await fetchGroups();
      return res;
    } catch (err) {
      console.error(`Failed to isolate group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  const handleBatchUndo = async (groupId, reason) => {
    setActionLoading(true);
    try {
      const res = await undoAllGroupActions(groupId, reason);
      await fetchGroupDetail(groupId);
      await fetchGroups();
      return res;
    } catch (err) {
      console.error(`Failed to rollback group ${groupId}`, err);
      throw err;
    } finally {
      setActionLoading(false);
    }
  };

  return {
    groups,
    loading,
    error,
    selectedGroup,
    detailLoading,
    actionLoading,
    fetchGroups,
    fetchGroupDetail,
    setSelectedGroup,
    createGroup: handleCreateGroup,
    updateGroup: handleUpdateGroup,
    deleteGroup: handleDeleteGroup,
    addMember: handleAddMember,
    removeMember: handleRemoveMember,
    batchIsolate: handleBatchIsolate,
    batchUndo: handleBatchUndo,
  };
};

export default useGroups;
