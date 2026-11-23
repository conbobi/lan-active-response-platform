import { useEffect, useRef, useState } from 'react';

export function connectDashboard(url, handlers, transport = globalThis) {
  let socket;
  let retry;
  let stopped = false;

  function connect() {
    if (stopped) return;
    try {
      const current = new transport.WebSocket(url);
      socket = current;
      current.onopen = () => {
        if (!stopped && socket === current) handlers.open();
      };
      current.onmessage = ({ data }) => {
        if (stopped || socket !== current) return;
        try {
          handlers.message(JSON.parse(data));
        } catch (error) {
          console.warn('Invalid Dashboard WebSocket event', error);
        }
      };
      current.onclose = () => {
        if (stopped || socket !== current) return;
        socket = null;
        handlers.close();
        retry = transport.setTimeout(connect, 3000);
      };
    } catch (error) {
      console.warn('Could not connect Dashboard WebSocket', error);
      retry = transport.setTimeout(connect, 3000);
    }
  }

  connect();
  return () => {
    stopped = true;
    transport.clearTimeout(retry);
    socket?.close();
  };
}

export const useDashboardSocket = (onMessage, onConnect) => {
  const [isConnected, setIsConnected] = useState(false);
  const callbacks = useRef({ onMessage, onConnect });
  useEffect(() => {
    callbacks.current = { onMessage, onConnect };
  }, [onMessage, onConnect]);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return connectDashboard(`${protocol}//${window.location.host}/ws/dashboard`, {
      open: () => {
        setIsConnected(true);
        callbacks.current.onConnect?.();
      },
      message: (data) => callbacks.current.onMessage?.(data),
      close: () => setIsConnected(false),
    });
  }, []);

  return { isConnected };
};

export default useDashboardSocket;
