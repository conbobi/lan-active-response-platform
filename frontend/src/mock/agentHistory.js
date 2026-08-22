// src/mock/agentHistory.js
const generateHistory = (agentId, points = 60) => {
    const now = Date.now();
    const data = [];
    for (let i = points - 1; i >= 0; i--) {
        const timestamp = new Date(now - i * 60 * 1000).toISOString(); // mỗi điểm cách nhau 1 phút
        data.push({
            timestamp,
            cpu: Math.min(100, Math.max(0, 40 + (Math.random() - 0.5) * 40)), // 20-60%
            ram: Math.min(100, Math.max(20, 50 + (Math.random() - 0.5) * 30)), // 35-65%
        });
    }
    return data;
};

const agentHistory = {
    'agent-1': generateHistory('agent-1'),
    'agent-2': generateHistory('agent-2'),
    'agent-3': generateHistory('agent-3'),
    // thêm các agent khác nếu cần
};

export default agentHistory;