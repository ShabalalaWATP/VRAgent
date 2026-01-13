/**
 * Kanban WebSocket Hook
 * Provides real-time collaboration for Kanban boards
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import { kanbanApi, KanbanCard, KanbanColumn } from '../api/client';

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface KanbanUser {
  user_id: number;
  username: string;
  color: string;
  viewing_column_id?: number | null;
}

export interface KanbanWebSocketMessage {
  type: string;
  user_id?: number;
  timestamp?: string;
  [key: string]: any;
}

export interface UseKanbanWebSocketProps {
  boardId: number;
  enabled?: boolean;
  onCardCreated?: (card: KanbanCard, userId: number) => void;
  onCardUpdated?: (cardId: number, updates: Partial<KanbanCard>, userId: number) => void;
  onCardMoved?: (cardId: number, sourceColumnId: number, targetColumnId: number, position: number, userId: number) => void;
  onCardDeleted?: (cardId: number, userId: number) => void;
  onColumnCreated?: (column: KanbanColumn, userId: number) => void;
  onColumnUpdated?: (columnId: number, updates: Partial<KanbanColumn>, userId: number) => void;
  onColumnDeleted?: (columnId: number, userId: number) => void;
  onColumnsReordered?: (columnIds: number[], userId: number) => void;
  onUserJoined?: (user: KanbanUser) => void;
  onUserLeft?: (userId: number) => void;
  onUserViewingColumn?: (userId: number, columnId: number | null) => void;
}

export interface UseKanbanWebSocketReturn {
  status: ConnectionStatus;
  activeUsers: KanbanUser[];
  connect: () => void;
  disconnect: () => void;
  sendViewingColumn: (columnId: number | null) => void;
}

const MAX_RECONNECT_ATTEMPTS = 5;
const PING_INTERVAL = 30000; // 30 seconds

export function useKanbanWebSocket({
  boardId,
  enabled = true,
  onCardCreated,
  onCardUpdated,
  onCardMoved,
  onCardDeleted,
  onColumnCreated,
  onColumnUpdated,
  onColumnDeleted,
  onColumnsReordered,
  onUserJoined,
  onUserLeft,
  onUserViewingColumn,
}: UseKanbanWebSocketProps): UseKanbanWebSocketReturn {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [activeUsers, setActiveUsers] = useState<KanbanUser[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const manualDisconnectRef = useRef(false);

  // Clear any pending timeouts
  const clearTimeouts = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
  }, []);

  // Handle incoming messages
  const handleMessage = useCallback((event: MessageEvent) => {
    // Handle pong
    if (event.data === 'pong') {
      return;
    }

    try {
      const message: KanbanWebSocketMessage = JSON.parse(event.data);
      const { type, user_id } = message;

      switch (type) {
        case 'current_users':
          setActiveUsers(message.users || []);
          break;

        case 'user_joined':
          if (onUserJoined && message.user_id !== undefined) {
            onUserJoined({
              user_id: message.user_id,
              username: message.username,
              color: message.color,
            });
          }
          setActiveUsers(prev => {
            // Avoid duplicates or undefined user_id
            if (message.user_id === undefined || prev.some(u => u.user_id === message.user_id)) {
              return prev;
            }
            return [...prev, {
              user_id: message.user_id,
              username: message.username,
              color: message.color,
            }];
          });
          break;

        case 'user_left':
          if (onUserLeft && message.user_id !== undefined) {
            onUserLeft(message.user_id);
          }
          setActiveUsers(prev => prev.filter(u => u.user_id !== message.user_id));
          break;

        case 'user_viewing_column':
          if (onUserViewingColumn && message.user_id !== undefined) {
            onUserViewingColumn(message.user_id, message.column_id);
          }
          setActiveUsers(prev => prev.map(u =>
            u.user_id === message.user_id
              ? { ...u, viewing_column_id: message.column_id }
              : u
          ));
          break;

        case 'card_created':
          if (onCardCreated && message.user_id !== undefined) {
            onCardCreated(message.card, message.user_id);
          }
          break;

        case 'card_updated':
          if (onCardUpdated && message.user_id !== undefined) {
            onCardUpdated(message.card_id, message.updates, message.user_id);
          }
          break;

        case 'card_moved':
          if (onCardMoved && message.user_id !== undefined) {
            onCardMoved(
              message.card_id,
              message.source_column_id,
              message.target_column_id,
              message.position,
              message.user_id
            );
          }
          break;

        case 'card_deleted':
          if (onCardDeleted && message.user_id !== undefined) {
            onCardDeleted(message.card_id, message.user_id);
          }
          break;

        case 'column_created':
          if (onColumnCreated && message.user_id !== undefined) {
            onColumnCreated(message.column, message.user_id);
          }
          break;

        case 'column_updated':
          if (onColumnUpdated && message.user_id !== undefined) {
            onColumnUpdated(message.column_id, message.updates, message.user_id);
          }
          break;

        case 'column_deleted':
          if (onColumnDeleted && message.user_id !== undefined) {
            onColumnDeleted(message.column_id, message.user_id);
          }
          break;

        case 'columns_reordered':
          if (onColumnsReordered && message.user_id !== undefined) {
            onColumnsReordered(message.column_ids, message.user_id);
          }
          break;

        case 'error':
          console.error('Kanban WebSocket error:', message.message);
          break;

        default:
          console.log('Unknown Kanban WebSocket message type:', type);
      }
    } catch (err) {
      console.error('Failed to parse Kanban WebSocket message:', err);
    }
  }, [
    onCardCreated, onCardUpdated, onCardMoved, onCardDeleted,
    onColumnCreated, onColumnUpdated, onColumnDeleted, onColumnsReordered,
    onUserJoined, onUserLeft, onUserViewingColumn
  ]);

  // Attempt reconnection with exponential backoff
  const attemptReconnect = useCallback(() => {
    if (manualDisconnectRef.current) {
      return;
    }

    if (reconnectAttemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
      console.log('Max Kanban WebSocket reconnection attempts reached');
      setStatus('error');
      return;
    }

    const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
    console.log(`Attempting Kanban WebSocket reconnection in ${delay}ms...`);

    reconnectTimeoutRef.current = setTimeout(() => {
      reconnectAttemptsRef.current += 1;
      connect();
    }, delay);
  }, []);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    if (!boardId || !enabled) {
      return;
    }

    manualDisconnectRef.current = false;
    setStatus('connecting');

    try {
      const wsUrl = kanbanApi.getWebSocketUrl(boardId);
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('Kanban WebSocket connected');
        setStatus('connected');
        reconnectAttemptsRef.current = 0;

        // Start ping interval
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, PING_INTERVAL);
      };

      ws.onmessage = handleMessage;

      ws.onerror = (error) => {
        console.error('Kanban WebSocket error:', error);
        setStatus('error');
      };

      ws.onclose = (event) => {
        console.log('Kanban WebSocket closed:', event.code, event.reason);
        setStatus('disconnected');
        clearTimeouts();
        setActiveUsers([]);

        // Attempt reconnection if not manually disconnected
        if (!manualDisconnectRef.current) {
          attemptReconnect();
        }
      };
    } catch (err) {
      console.error('Failed to create Kanban WebSocket:', err);
      setStatus('error');
    }
  }, [boardId, enabled, handleMessage, clearTimeouts, attemptReconnect]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    manualDisconnectRef.current = true;
    clearTimeouts();

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus('disconnected');
    setActiveUsers([]);
    reconnectAttemptsRef.current = 0;
  }, [clearTimeouts]);

  // Send viewing column update
  const sendViewingColumn = useCallback((columnId: number | null) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'viewing_column',
        column_id: columnId,
      }));
    }
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (enabled && boardId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [boardId, enabled]);

  // Reconnect when enabled changes
  useEffect(() => {
    if (enabled && boardId && status === 'disconnected' && !manualDisconnectRef.current) {
      connect();
    } else if (!enabled) {
      disconnect();
    }
  }, [enabled]);

  return {
    status,
    activeUsers,
    connect,
    disconnect,
    sendViewingColumn,
  };
}

export default useKanbanWebSocket;
