/**
 * React hook for real-time WebSocket connections.
 *
 * Provides auto-reconnect, keepalive, and typed event handling.
 */

import { useEffect, useRef, useState, useCallback } from 'react';

interface WebSocketEvent {
  type: string;
  [key: string]: unknown;
}

interface UseWebSocketOptions {
  /** Auto-reconnect on disconnect */
  reconnect?: boolean;
  /** Reconnect interval in ms */
  reconnectInterval?: number;
  /** Max reconnect attempts */
  maxRetries?: number;
}

interface UseWebSocketReturn {
  /** Whether the WebSocket is connected */
  connected: boolean;
  /** Last received event */
  lastEvent: WebSocketEvent | null;
  /** All received events (newest first, capped at 100) */
  events: WebSocketEvent[];
  /** Send a message to the WebSocket */
  send: (data: string | object) => void;
}

export function useWebSocket(
  url: string,
  options: UseWebSocketOptions = {},
): UseWebSocketReturn {
  const {
    reconnect = true,
    reconnectInterval = 3000,
    maxRetries = 10,
  } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const [connected, setConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<WebSocketEvent | null>(null);
  const [events, setEvents] = useState<WebSocketEvent[]>([]);

  const connect = useCallback(() => {
    // Build full WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = url.startsWith('ws')
      ? url
      : `${protocol}//${window.location.host}${url}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      retriesRef.current = 0;
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as WebSocketEvent;
        if (data.type === 'keepalive') return; // Ignore keepalives

        setLastEvent(data);
        setEvents((prev) => [data, ...prev].slice(0, 100));
      } catch {
        // Non-JSON message (e.g. "pong")
      }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;

      if (reconnect && retriesRef.current < maxRetries) {
        retriesRef.current += 1;
        setTimeout(connect, reconnectInterval);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url, reconnect, reconnectInterval, maxRetries]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: string | object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data));
    }
  }, []);

  return { connected, lastEvent, events, send };
}
