/**
 * Rate limit constants synchronized with backend/core/rate_limit.py and websocket_manager.py
 *
 * Backend Rate Limits (HTTP):
 * - Authenticated: 100 requests per minute
 * - Unauthenticated: 20 requests per minute
 *
 * Special Endpoint Limits:
 * - /api/scans: 5 per minute
 * - /api/projects: 20 per minute
 * - /api/exploitability: 10 per minute
 * - /api/fuzzing: 5 per minute
 *
 * WebSocket Rate Limits:
 * - Messages: 60 per minute per user (increased for active team discussions)
 * - Max connections: 10 per user (tabs/devices, increased for teams)
 * - Heartbeat interval: 30 seconds
 * - Connection timeout: 90 seconds
 */

// HTTP rate limits (from rate_limit.py)
export const HTTP_RATE_LIMITS = {
  authenticated: {
    limit: 100,
    windowSeconds: 60,
  },
  unauthenticated: {
    limit: 20,
    windowSeconds: 60,
  },
  endpoints: {
    '/api/scans': 5,
    '/api/projects': 20,
    '/api/exploitability': 10,
    '/api/fuzzing': 5,
  },
} as const;

// WebSocket rate limits (from websocket_manager.py)
export const WEBSOCKET_RATE_LIMITS = {
  messagesPerMinute: 60,
  maxConnectionsPerUser: 10,
  windowSeconds: 60,
  heartbeatIntervalSeconds: 30,
  connectionTimeoutSeconds: 90,
} as const;

// Message queue retry limits
export const MESSAGE_QUEUE_LIMITS = {
  maxRetryCount: 3,
  maxQueueSize: 100,
  maxQueueSizeBytes: 2 * 1024 * 1024, // 2MB max queue size in bytes
} as const;

// Reconnection limits
export const RECONNECTION_LIMITS = {
  maxAttempts: 10,  // Increased for better resilience with team environments
  baseDelayMs: 1000,
  maxDelayMs: 30000,
} as const;

/**
 * Calculate exponential backoff delay for reconnection
 */
export function getReconnectDelay(attemptNumber: number): number {
  const delay = RECONNECTION_LIMITS.baseDelayMs * Math.pow(2, attemptNumber);
  return Math.min(delay, RECONNECTION_LIMITS.maxDelayMs);
}

/**
 * Check if we should retry based on attempt count
 */
export function shouldRetryConnection(attemptNumber: number): boolean {
  return attemptNumber < RECONNECTION_LIMITS.maxAttempts;
}

/**
 * Check if we should retry a queued message
 */
export function shouldRetryMessage(retryCount: number): boolean {
  return retryCount < MESSAGE_QUEUE_LIMITS.maxRetryCount;
}
