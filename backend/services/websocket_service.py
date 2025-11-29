"""
WebSocket service for real-time scan progress updates.
Provides live feedback during long-running vulnerability scans.
Uses Redis pub/sub to communicate between worker processes and the FastAPI backend.
"""
import asyncio
import json
import os
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

import redis
from fastapi import WebSocket, WebSocketDisconnect
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Redis connection for pub/sub
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SCAN_PROGRESS_CHANNEL = "scan_progress"


class ScanPhase(str, Enum):
    """Phases of a vulnerability scan."""
    QUEUED = "queued"
    EXTRACTING = "extracting"
    PARSING_FILES = "parsing_files"
    GENERATING_EMBEDDINGS = "generating_embeddings"
    DETECTING_SECRETS = "detecting_secrets"
    RUNNING_SEMGREP = "running_semgrep"
    RUNNING_ESLINT = "running_eslint"
    PARSING_DEPENDENCIES = "parsing_dependencies"
    LOOKING_UP_CVES = "looking_up_cves"
    FETCHING_EPSS = "fetching_epss"
    GENERATING_REPORT = "generating_report"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ScanProgress:
    """Represents the current progress of a scan."""
    scan_run_id: int
    project_id: int
    phase: ScanPhase
    phase_progress: int  # 0-100 within current phase
    overall_progress: int  # 0-100 overall
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))


class ConnectionManager:
    """Manages WebSocket connections for scan progress updates."""
    
    def __init__(self):
        # Map of scan_run_id -> set of connected WebSockets
        self._connections: Dict[int, Set[WebSocket]] = {}
        # Map of project_id -> set of connected WebSockets (for project-level subscriptions)
        self._project_connections: Dict[int, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, scan_run_id: Optional[int] = None, project_id: Optional[int] = None):
        """Accept a WebSocket connection and register it for updates."""
        await websocket.accept()
        
        async with self._lock:
            if scan_run_id:
                if scan_run_id not in self._connections:
                    self._connections[scan_run_id] = set()
                self._connections[scan_run_id].add(websocket)
                logger.debug(f"WebSocket connected for scan_run {scan_run_id}")
            
            if project_id:
                if project_id not in self._project_connections:
                    self._project_connections[project_id] = set()
                self._project_connections[project_id].add(websocket)
                logger.debug(f"WebSocket connected for project {project_id}")
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        async with self._lock:
            # Remove from scan connections
            for scan_id in list(self._connections.keys()):
                self._connections[scan_id].discard(websocket)
                if not self._connections[scan_id]:
                    del self._connections[scan_id]
            
            # Remove from project connections
            for project_id in list(self._project_connections.keys()):
                self._project_connections[project_id].discard(websocket)
                if not self._project_connections[project_id]:
                    del self._project_connections[project_id]
    
    async def broadcast_progress(self, progress: ScanProgress):
        """Send progress update to all connected clients for this scan/project."""
        message = progress.to_json()
        disconnected = []
        
        async with self._lock:
            # Send to scan-specific subscribers
            for ws in self._connections.get(progress.scan_run_id, set()):
                try:
                    await ws.send_text(message)
                except Exception:
                    disconnected.append(ws)
            
            # Send to project-level subscribers
            for ws in self._project_connections.get(progress.project_id, set()):
                try:
                    await ws.send_text(message)
                except Exception:
                    disconnected.append(ws)
        
        # Clean up disconnected clients
        for ws in disconnected:
            await self.disconnect(ws)
    
    def get_connection_count(self, scan_run_id: Optional[int] = None, project_id: Optional[int] = None) -> int:
        """Get the number of active connections."""
        count = 0
        if scan_run_id and scan_run_id in self._connections:
            count += len(self._connections[scan_run_id])
        if project_id and project_id in self._project_connections:
            count += len(self._project_connections[project_id])
        return count


# Global connection manager instance
manager = ConnectionManager()


# Phase weights for overall progress calculation
PHASE_WEIGHTS = {
    ScanPhase.QUEUED: 0,
    ScanPhase.EXTRACTING: 5,
    ScanPhase.PARSING_FILES: 15,
    ScanPhase.GENERATING_EMBEDDINGS: 25,
    ScanPhase.DETECTING_SECRETS: 35,
    ScanPhase.RUNNING_SEMGREP: 45,
    ScanPhase.RUNNING_ESLINT: 55,
    ScanPhase.PARSING_DEPENDENCIES: 65,
    ScanPhase.LOOKING_UP_CVES: 80,
    ScanPhase.FETCHING_EPSS: 90,
    ScanPhase.GENERATING_REPORT: 95,
    ScanPhase.COMPLETE: 100,
    ScanPhase.FAILED: -1,
}


def calculate_overall_progress(phase: ScanPhase, phase_progress: int) -> int:
    """Calculate overall progress based on phase and progress within phase."""
    if phase == ScanPhase.FAILED:
        return -1
    
    phases = list(PHASE_WEIGHTS.keys())
    current_idx = phases.index(phase)
    
    if current_idx >= len(phases) - 2:  # COMPLETE or FAILED
        return PHASE_WEIGHTS[phase]
    
    phase_start = PHASE_WEIGHTS[phase]
    next_phase = phases[current_idx + 1]
    phase_end = PHASE_WEIGHTS[next_phase]
    phase_range = phase_end - phase_start
    
    return phase_start + int(phase_range * phase_progress / 100)


class ProgressTracker:
    """
    Helper class for tracking and reporting scan progress.
    
    Use as a context manager or call methods directly.
    """
    
    def __init__(self, scan_run_id: int, project_id: int):
        self.scan_run_id = scan_run_id
        self.project_id = project_id
        self.current_phase = ScanPhase.QUEUED
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create an event loop."""
        try:
            return asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop
    
    def update(
        self,
        phase: ScanPhase,
        phase_progress: int = 0,
        message: str = "",
        details: Optional[Dict[str, Any]] = None
    ):
        """Send a progress update."""
        self.current_phase = phase
        overall = calculate_overall_progress(phase, phase_progress)
        
        progress = ScanProgress(
            scan_run_id=self.scan_run_id,
            project_id=self.project_id,
            phase=phase,
            phase_progress=phase_progress,
            overall_progress=overall,
            message=message or f"Phase: {phase.value}",
            details=details,
        )
        
        # Send via WebSocket (non-blocking)
        try:
            loop = self._get_loop()
            if loop.is_running():
                asyncio.create_task(manager.broadcast_progress(progress))
            else:
                loop.run_until_complete(manager.broadcast_progress(progress))
        except Exception as e:
            logger.debug(f"Could not send WebSocket update: {e}")
    
    def start(self):
        """Mark scan as starting."""
        self.update(ScanPhase.EXTRACTING, 0, "Starting scan...")
    
    def complete(self, report_id: Optional[int] = None):
        """Mark scan as complete."""
        self.update(
            ScanPhase.COMPLETE,
            100,
            "Scan complete!",
            {"report_id": report_id} if report_id else None
        )
    
    def fail(self, error: str):
        """Mark scan as failed."""
        self.update(ScanPhase.FAILED, 0, f"Scan failed: {error}", {"error": error})


def get_progress_tracker(scan_run_id: int, project_id: int) -> ProgressTracker:
    """Create a progress tracker for a scan."""
    return ProgressTracker(scan_run_id, project_id)


class SimpleProgressManager:
    """
    Simple progress manager for broadcasting updates without requiring a ProgressTracker.
    Uses Redis pub/sub to communicate between worker processes and the FastAPI backend.
    
    - Worker process: publishes progress updates to Redis channel
    - FastAPI process: subscribes to Redis channel and broadcasts to WebSocket clients
    """
    
    def __init__(self):
        self._redis_client = None
        self._subscriber_task = None
        self._running = False
    
    def _get_redis(self):
        """Get or create Redis client (lazily initialized)."""
        if self._redis_client is None:
            self._redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        return self._redis_client
    
    def publish_progress(self, scan_run_id: int, phase: str, progress: int, message: str = ""):
        """
        Publish a progress update to Redis (called by worker process).
        This is a synchronous method for use in the worker.
        """
        progress_obj = {
            "scan_run_id": scan_run_id,
            "phase": phase,
            "progress": progress,
            "message": message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        try:
            r = self._get_redis()
            r.publish(SCAN_PROGRESS_CHANNEL, json.dumps(progress_obj))
            logger.debug(f"Published progress: scan={scan_run_id}, phase={phase}, progress={progress}")
        except Exception as e:
            logger.error(f"Failed to publish progress to Redis: {e}")
    
    async def update_progress(self, scan_run_id: int, phase: str, progress: int, message: str = ""):
        """
        Send a progress update for a scan (async version).
        Publishes to Redis for cross-process communication.
        """
        # Run the synchronous publish in a thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.publish_progress, scan_run_id, phase, progress, message)
    
    async def start_subscriber(self):
        """
        Start the Redis subscriber in the FastAPI process.
        This listens for progress updates from workers and broadcasts to WebSocket clients.
        """
        if self._running:
            return
        
        self._running = True
        logger.info("Starting Redis pub/sub subscriber for scan progress")
        
        async def subscriber_loop():
            while self._running:
                try:
                    # Create a separate Redis connection for subscribing
                    r = redis.from_url(REDIS_URL, decode_responses=True)
                    pubsub = r.pubsub()
                    pubsub.subscribe(SCAN_PROGRESS_CHANNEL)
                    
                    logger.info(f"Subscribed to Redis channel: {SCAN_PROGRESS_CHANNEL}")
                    
                    while self._running:
                        # Use get_message with timeout to allow checking _running flag
                        message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                        if message and message['type'] == 'message':
                            try:
                                progress_data = json.loads(message['data'])
                                scan_run_id = progress_data.get('scan_run_id')
                                
                                # Broadcast to WebSocket clients
                                disconnected = []
                                async with manager._lock:
                                    for ws in manager._connections.get(scan_run_id, set()):
                                        try:
                                            await ws.send_text(json.dumps(progress_data))
                                        except Exception:
                                            disconnected.append(ws)
                                
                                for ws in disconnected:
                                    await manager.disconnect(ws)
                                    
                            except json.JSONDecodeError as e:
                                logger.error(f"Invalid JSON in progress message: {e}")
                        
                        # Small sleep to prevent tight loop
                        await asyncio.sleep(0.01)
                        
                except redis.ConnectionError as e:
                    logger.error(f"Redis connection error in subscriber: {e}")
                    await asyncio.sleep(5)  # Wait before reconnecting
                except Exception as e:
                    logger.error(f"Error in Redis subscriber: {e}")
                    await asyncio.sleep(1)
        
        self._subscriber_task = asyncio.create_task(subscriber_loop())
    
    async def stop_subscriber(self):
        """Stop the Redis subscriber."""
        self._running = False
        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped Redis pub/sub subscriber")


# Global simple progress manager for use by scan_service
progress_manager = SimpleProgressManager()
