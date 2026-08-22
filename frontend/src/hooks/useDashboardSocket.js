// src/hooks/useDashboardSocket.js
import { useEffect, useRef, useState } from 'react';

export const useDashboardSocket = (onMessage) => {
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef(null);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    // Vite proxy handles /ws or connect directly to 8002
    const wsUrl = window.location.port === '5173' || window.location.port === '3000'
      ? `${protocol}//localhost:8002/ws/dashboard`
      : `${protocol}//${host}/ws/dashboard`;

    let ws;
    try {
      ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        console.log('[WebSocket] Connected to /ws/dashboard');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onMessage) onMessage(data);
        } catch (e) {
          console.error('[WebSocket] Failed to parse message:', event.data);
        }
      };

      ws.onerror = (err) => {
        console.warn('[WebSocket] Dashboard WS connection error:', err);
      };

      ws.onclose = () => {
        setIsConnected(false);
        console.log('[WebSocket] Dashboard WS connection closed');
      };
    } catch (err) {
      console.warn('[WebSocket] Failed to initialize WebSocket:', err);
    }

    return () => {
      if (ws) ws.close();
    };
  }, [onMessage]);

  return { isConnected };
};

export default useDashboardSocket;
