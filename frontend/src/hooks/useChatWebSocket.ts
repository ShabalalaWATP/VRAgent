import { useCallback, useEffect, useRef, useState } from 'react';
import { socialApi, WSEvent, SocialMessage, ReactionSummary } from '../api/client';

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export type TypingUser = {
  userId: number;
  username: string;
  timestamp: number;
};

// Offline message queue types
export type QueuedMessage = {
  id: string; // Temporary client-side ID
  conversationId: number;
  content: string;
  messageType: string;
  attachmentData?: Record<string, any>;
  replyToId?: number;
  timestamp: number;
  status: 'pending' | 'sending' | 'failed';
  retryCount: number;
};

const QUEUE_STORAGE_KEY = 'vragent_message_queue';
const MAX_RETRY_COUNT = 3;

export type ChatWebSocketCallbacks = {
  onNewMessage?: (message: SocialMessage, conversationId: number) => void;
  onMessageEdited?: (messageId: number, conversationId: number, content: string, updatedAt: string) => void;
  onMessageDeleted?: (messageId: number, conversationId: number) => void;
  onReactionAdded?: (messageId: number, conversationId: number, emoji: string, userId: number, username: string) => void;
  onReactionRemoved?: (messageId: number, conversationId: number, emoji: string, userId: number, username: string) => void;
  onTyping?: (conversationId: number, userId: number, username: string, isTyping: boolean) => void;
  onPresence?: (userId: number, username: string, isOnline: boolean) => void;
  onReadReceipt?: (conversationId: number, userId: number, lastReadMessageId: number) => void;
  onConnectionChange?: (status: ConnectionStatus) => void;
  onQueuedMessageSent?: (tempId: string, message: SocialMessage) => void;
  onQueuedMessageFailed?: (tempId: string, error: string) => void;
};

export function useChatWebSocket(callbacks: ChatWebSocketCallbacks = {}) {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [onlineUsers, setOnlineUsers] = useState<Set<number>>(new Set());
  const [typingUsers, setTypingUsers] = useState<Map<number, TypingUser[]>>(new Map());
  const [messageQueue, setMessageQueue] = useState<QueuedMessage[]>([]);
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const callbacksRef = useRef(callbacks);
  const typingTimeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const processingQueueRef = useRef(false);

  // Load queued messages from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(QUEUE_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as QueuedMessage[];
        setMessageQueue(parsed.filter(m => m.status !== 'sending'));
      }
    } catch (e) {
      console.error('Failed to load message queue:', e);
    }
  }, []);

  // Save queue to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem(QUEUE_STORAGE_KEY, JSON.stringify(messageQueue));
    } catch (e) {
      console.error('Failed to save message queue:', e);
    }
  }, [messageQueue]);

  // Listen for online/offline events
  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      // Trigger queue processing when back online
      processQueue();
    };
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Update callbacks ref when they change
  useEffect(() => {
    callbacksRef.current = callbacks;
  }, [callbacks]);

  // Clean up typing indicators after 3 seconds
  const clearTypingTimeout = useCallback((key: string) => {
    const existing = typingTimeoutsRef.current.get(key);
    if (existing) {
      clearTimeout(existing);
      typingTimeoutsRef.current.delete(key);
    }
  }, []);

  const handleTypingTimeout = useCallback((conversationId: number, userId: number, username: string) => {
    const key = `${conversationId}-${userId}`;
    clearTypingTimeout(key);
    
    const timeout = setTimeout(() => {
      setTypingUsers(prev => {
        const newMap = new Map(prev);
        const conversationTypers = newMap.get(conversationId) || [];
        newMap.set(conversationId, conversationTypers.filter(t => t.userId !== userId));
        return newMap;
      });
      typingTimeoutsRef.current.delete(key);
    }, 3000);
    
    typingTimeoutsRef.current.set(key, timeout);
  }, [clearTypingTimeout]);

  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data) as WSEvent;
      
      switch (data.type) {
        case 'new_message':
          callbacksRef.current.onNewMessage?.(data.message, data.conversation_id);
          break;
          
        case 'message_edited':
          callbacksRef.current.onMessageEdited?.(
            data.message_id,
            data.conversation_id,
            data.content,
            data.updated_at
          );
          break;
          
        case 'message_deleted':
          callbacksRef.current.onMessageDeleted?.(data.message_id, data.conversation_id);
          break;
          
        case 'reaction_added':
          callbacksRef.current.onReactionAdded?.(
            data.message_id,
            data.conversation_id,
            data.emoji,
            data.user_id,
            data.username
          );
          break;
          
        case 'reaction_removed':
          callbacksRef.current.onReactionRemoved?.(
            data.message_id,
            data.conversation_id,
            data.emoji,
            data.user_id,
            data.username
          );
          break;
          
        case 'typing':
          if (data.is_typing) {
            setTypingUsers(prev => {
              const newMap = new Map(prev);
              const conversationTypers = newMap.get(data.conversation_id) || [];
              const existing = conversationTypers.find(t => t.userId === data.user_id);
              if (existing) {
                existing.timestamp = Date.now();
              } else {
                conversationTypers.push({
                  userId: data.user_id,
                  username: data.username,
                  timestamp: Date.now(),
                });
              }
              newMap.set(data.conversation_id, conversationTypers);
              return newMap;
            });
            handleTypingTimeout(data.conversation_id, data.user_id, data.username);
          } else {
            const key = `${data.conversation_id}-${data.user_id}`;
            clearTypingTimeout(key);
            setTypingUsers(prev => {
              const newMap = new Map(prev);
              const conversationTypers = newMap.get(data.conversation_id) || [];
              newMap.set(data.conversation_id, conversationTypers.filter(t => t.userId !== data.user_id));
              return newMap;
            });
          }
          callbacksRef.current.onTyping?.(
            data.conversation_id,
            data.user_id,
            data.username,
            data.is_typing
          );
          break;
          
        case 'presence':
          setOnlineUsers(prev => {
            const newSet = new Set(prev);
            if (data.is_online) {
              newSet.add(data.user_id);
            } else {
              newSet.delete(data.user_id);
            }
            return newSet;
          });
          callbacksRef.current.onPresence?.(data.user_id, data.username, data.is_online);
          break;
          
        case 'read_receipt':
          callbacksRef.current.onReadReceipt?.(
            data.conversation_id,
            data.user_id,
            data.last_read_message_id
          );
          break;
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  }, [handleTypingTimeout, clearTypingTimeout]);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    const wsUrl = socialApi.getWebSocketUrl();
    if (!wsUrl.includes('token=') || wsUrl.endsWith('token=null')) {
      console.warn('No auth token available, skipping WebSocket connection');
      return;
    }

    setStatus('connecting');
    callbacksRef.current.onConnectionChange?.('connecting');

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('Chat WebSocket connected');
      setStatus('connected');
      callbacksRef.current.onConnectionChange?.('connected');
      reconnectAttemptsRef.current = 0;
    };

    ws.onmessage = handleMessage;

    ws.onerror = (error) => {
      console.error('Chat WebSocket error:', error);
      setStatus('error');
      callbacksRef.current.onConnectionChange?.('error');
    };

    ws.onclose = (event) => {
      console.log('Chat WebSocket closed:', event.code, event.reason);
      setStatus('disconnected');
      callbacksRef.current.onConnectionChange?.('disconnected');
      wsRef.current = null;

      // Reconnect with exponential backoff
      if (reconnectAttemptsRef.current < 5) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current), 30000);
        reconnectAttemptsRef.current++;
        console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`);
        reconnectTimeoutRef.current = setTimeout(connect, delay);
      }
    };
  }, [handleMessage]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    reconnectAttemptsRef.current = 5; // Prevent auto-reconnect
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    // Clear all typing timeouts
    typingTimeoutsRef.current.forEach(timeout => clearTimeout(timeout));
    typingTimeoutsRef.current.clear();
    
    setStatus('disconnected');
    setOnlineUsers(new Set());
    setTypingUsers(new Map());
  }, []);

  const sendTypingIndicator = useCallback((conversationId: number, isTyping: boolean) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'typing',
        conversation_id: conversationId,
        is_typing: isTyping,
      }));
    }
  }, []);

  const sendViewingConversation = useCallback((conversationId: number | null) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'viewing',
        conversation_id: conversationId,
      }));
    }
  }, []);

  const sendReadReceipt = useCallback((conversationId: number, messageId: number) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'read',
        conversation_id: conversationId,
        message_id: messageId,
      }));
    }
  }, []);

  const getTypingUsersForConversation = useCallback((conversationId: number): TypingUser[] => {
    return typingUsers.get(conversationId) || [];
  }, [typingUsers]);

  const checkUserOnline = useCallback((userId: number): boolean => {
    return onlineUsers.has(userId);
  }, [onlineUsers]);

  // Process queued messages
  const processQueue = useCallback(async () => {
    if (processingQueueRef.current || !isOnline || status !== 'connected') {
      return;
    }

    processingQueueRef.current = true;

    try {
      const pendingMessages = messageQueue.filter(m => m.status === 'pending' || m.status === 'failed');
      
      for (const queuedMsg of pendingMessages) {
        if (queuedMsg.retryCount >= MAX_RETRY_COUNT) {
          // Mark as permanently failed
          setMessageQueue(prev => prev.filter(m => m.id !== queuedMsg.id));
          callbacksRef.current.onQueuedMessageFailed?.(queuedMsg.id, 'Max retries exceeded');
          continue;
        }

        // Mark as sending
        setMessageQueue(prev => 
          prev.map(m => m.id === queuedMsg.id ? { ...m, status: 'sending' as const } : m)
        );

        try {
          let sentMessage: SocialMessage;
          
          if (queuedMsg.replyToId) {
            sentMessage = await socialApi.replyToMessage(
              queuedMsg.conversationId,
              queuedMsg.replyToId,
              queuedMsg.content,
              queuedMsg.messageType as any,
              queuedMsg.attachmentData
            );
          } else {
            sentMessage = await socialApi.sendMessage(
              queuedMsg.conversationId,
              queuedMsg.content,
              queuedMsg.messageType as any,
              queuedMsg.attachmentData
            );
          }

          // Remove from queue on success
          setMessageQueue(prev => prev.filter(m => m.id !== queuedMsg.id));
          callbacksRef.current.onQueuedMessageSent?.(queuedMsg.id, sentMessage);
        } catch (error) {
          // Increment retry count
          setMessageQueue(prev => 
            prev.map(m => m.id === queuedMsg.id 
              ? { ...m, status: 'failed' as const, retryCount: m.retryCount + 1 } 
              : m
            )
          );
          console.error('Failed to send queued message:', error);
        }
      }
    } finally {
      processingQueueRef.current = false;
    }
  }, [messageQueue, isOnline, status]);

  // Add message to queue (for offline sending)
  const queueMessage = useCallback((
    conversationId: number,
    content: string,
    messageType: string = 'text',
    attachmentData?: Record<string, any>,
    replyToId?: number
  ): QueuedMessage => {
    const queuedMsg: QueuedMessage = {
      id: `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      conversationId,
      content,
      messageType,
      attachmentData,
      replyToId,
      timestamp: Date.now(),
      status: 'pending',
      retryCount: 0,
    };

    setMessageQueue(prev => [...prev, queuedMsg]);

    // Try to send immediately if online
    if (isOnline && status === 'connected') {
      setTimeout(() => processQueue(), 100);
    }

    return queuedMsg;
  }, [isOnline, status, processQueue]);

  // Remove a queued message
  const removeQueuedMessage = useCallback((tempId: string) => {
    setMessageQueue(prev => prev.filter(m => m.id !== tempId));
  }, []);

  // Retry a failed message
  const retryQueuedMessage = useCallback((tempId: string) => {
    setMessageQueue(prev => 
      prev.map(m => m.id === tempId ? { ...m, status: 'pending' as const } : m)
    );
    setTimeout(() => processQueue(), 100);
  }, [processQueue]);

  // Get queued messages for a conversation
  const getQueuedMessagesForConversation = useCallback((conversationId: number): QueuedMessage[] => {
    return messageQueue.filter(m => m.conversationId === conversationId);
  }, [messageQueue]);

  // Process queue when connection is established
  useEffect(() => {
    if (status === 'connected' && isOnline && messageQueue.length > 0) {
      processQueue();
    }
  }, [status, isOnline, processQueue, messageQueue.length]);

  // Auto-connect on mount, disconnect on unmount
  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    status,
    connect,
    disconnect,
    sendTypingIndicator,
    sendViewingConversation,
    sendReadReceipt,
    getTypingUsersForConversation,
    isUserOnline: checkUserOnline,
    onlineUsers,
    typingUsers,
    // Offline queue functions
    isOnline,
    messageQueue,
    queueMessage,
    removeQueuedMessage,
    retryQueuedMessage,
    getQueuedMessagesForConversation,
    processQueue,
  };
}

export default useChatWebSocket;
