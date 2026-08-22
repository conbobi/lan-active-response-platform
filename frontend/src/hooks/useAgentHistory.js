// src/hooks/useAgentHistory.js
import { useState, useEffect } from 'react';
import { getAgentHistory } from '../api/agents';

export const useAgentHistory = (agentId) => {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (!agentId) {
            setHistory([]);
            setLoading(false);
            return;
        }
        const fetchHistory = async () => {
            setLoading(true);
            try {
                const data = await getAgentHistory(agentId);
                setHistory(data);
            } catch (error) {
                console.error('Failed to fetch agent history', error);
            } finally {
                setLoading(false);
            }
        };
        fetchHistory();
    }, [agentId]);

    return { history, loading };
};