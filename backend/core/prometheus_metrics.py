"""
Prometheus Metrics Export for VRAgent
Provides detailed metrics for monitoring and alerting
"""

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Summary,
    Info,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from typing import Optional
import time
import psutil
from functools import wraps


# Create custom registry (optional - can use default)
registry = CollectorRegistry()


# ============================================================================
# System Metrics
# ============================================================================

# Memory metrics
memory_usage_bytes = Gauge(
    'vragent_memory_usage_bytes',
    'Memory usage in bytes',
    ['type'],  # 'rss', 'vms', 'available'
    registry=registry
)

memory_usage_percent = Gauge(
    'vragent_memory_usage_percent',
    'Memory usage percentage',
    registry=registry
)

# CPU metrics
cpu_usage_percent = Gauge(
    'vragent_cpu_usage_percent',
    'CPU usage percentage',
    registry=registry
)

cpu_count = Gauge(
    'vragent_cpu_count',
    'Number of CPU cores',
    registry=registry
)

# Disk metrics
disk_usage_bytes = Gauge(
    'vragent_disk_usage_bytes',
    'Disk usage in bytes',
    ['type'],  # 'total', 'used', 'free'
    registry=registry
)

disk_usage_percent = Gauge(
    'vragent_disk_usage_percent',
    'Disk usage percentage',
    registry=registry
)


# ============================================================================
# Application Metrics
# ============================================================================

# Request metrics
http_requests_total = Counter(
    'vragent_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status'],
    registry=registry
)

http_request_duration_seconds = Histogram(
    'vragent_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
    registry=registry
)

http_request_size_bytes = Summary(
    'vragent_http_request_size_bytes',
    'HTTP request size in bytes',
    ['method', 'endpoint'],
    registry=registry
)

http_response_size_bytes = Summary(
    'vragent_http_response_size_bytes',
    'HTTP response size in bytes',
    ['method', 'endpoint'],
    registry=registry
)


# ============================================================================
# Analysis Metrics
# ============================================================================

# Binary analysis
binaries_analyzed_total = Counter(
    'vragent_binaries_analyzed_total',
    'Total binaries analyzed',
    ['status'],  # 'success', 'failed'
    registry=registry
)

binary_analysis_duration_seconds = Histogram(
    'vragent_binary_analysis_duration_seconds',
    'Binary analysis duration in seconds',
    ['analysis_type'],  # 'quick', 'standard', 'deep'
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
    registry=registry
)

binary_size_bytes = Histogram(
    'vragent_binary_size_bytes',
    'Size of analyzed binaries in bytes',
    buckets=(1024, 10240, 102400, 1048576, 10485760, 104857600, 1073741824, 5368709120),
    registry=registry
)

yara_matches_total = Counter(
    'vragent_yara_matches_total',
    'Total YARA rule matches',
    ['rule_category'],  # 'malware', 'packer', 'exploit', etc.
    registry=registry
)


# ============================================================================
# Fuzzing Metrics
# ============================================================================

fuzzing_campaigns_total = Counter(
    'vragent_fuzzing_campaigns_total',
    'Total fuzzing campaigns',
    ['status'],  # 'started', 'completed', 'failed'
    registry=registry
)

fuzzing_executions_total = Counter(
    'vragent_fuzzing_executions_total',
    'Total fuzzing executions',
    ['campaign_id'],
    registry=registry
)

fuzzing_crashes_total = Counter(
    'vragent_fuzzing_crashes_total',
    'Total crashes found',
    ['crash_type', 'exploitability'],
    registry=registry
)

fuzzing_coverage_percent = Gauge(
    'vragent_fuzzing_coverage_percent',
    'Fuzzing code coverage percentage',
    ['campaign_id'],
    registry=registry
)


# ============================================================================
# Database Metrics
# ============================================================================

database_connections = Gauge(
    'vragent_database_connections',
    'Number of active database connections',
    registry=registry
)

database_query_duration_seconds = Histogram(
    'vragent_database_query_duration_seconds',
    'Database query duration in seconds',
    ['operation'],  # 'select', 'insert', 'update', 'delete'
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
    registry=registry
)

database_errors_total = Counter(
    'vragent_database_errors_total',
    'Total database errors',
    ['error_type'],
    registry=registry
)


# ============================================================================
# Cache Metrics
# ============================================================================

cache_hits_total = Counter(
    'vragent_cache_hits_total',
    'Total cache hits',
    ['namespace'],
    registry=registry
)

cache_misses_total = Counter(
    'vragent_cache_misses_total',
    'Total cache misses',
    ['namespace'],
    registry=registry
)

cache_size_bytes = Gauge(
    'vragent_cache_size_bytes',
    'Cache size in bytes',
    ['namespace'],
    registry=registry
)


# ============================================================================
# AI Service Metrics
# ============================================================================

ai_requests_total = Counter(
    'vragent_ai_requests_total',
    'Total AI service requests',
    ['service', 'status'],  # service: gemini/openai, status: success/failed
    registry=registry
)

ai_request_duration_seconds = Histogram(
    'vragent_ai_request_duration_seconds',
    'AI service request duration in seconds',
    ['service'],
    buckets=(0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0),
    registry=registry
)

ai_tokens_used_total = Counter(
    'vragent_ai_tokens_used_total',
    'Total AI tokens consumed',
    ['service', 'type'],  # type: input/output
    registry=registry
)


# ============================================================================
# Error Metrics
# ============================================================================

errors_total = Counter(
    'vragent_errors_total',
    'Total errors',
    ['error_code', 'severity'],  # severity: low/medium/high/critical
    registry=registry
)

resource_limit_exceeded_total = Counter(
    'vragent_resource_limit_exceeded_total',
    'Total resource limit violations',
    ['resource'],  # 'memory', 'cpu', 'timeout'
    registry=registry
)


# ============================================================================
# Business Metrics
# ============================================================================

active_users = Gauge(
    'vragent_active_users',
    'Number of active users',
    ['time_range'],  # 'last_hour', 'last_day', 'last_week'
    registry=registry
)

scans_per_user = Histogram(
    'vragent_scans_per_user',
    'Number of scans per user',
    buckets=(1, 5, 10, 25, 50, 100, 250, 500),
    registry=registry
)


# ============================================================================
# Application Info
# ============================================================================

app_info = Info(
    'vragent_app',
    'VRAgent application information',
    registry=registry
)


# ============================================================================
# Metric Collection Functions
# ============================================================================

def collect_system_metrics():
    """Collect and update system metrics"""
    # Memory
    mem = psutil.virtual_memory()
    memory_usage_bytes.labels(type='total').set(mem.total)
    memory_usage_bytes.labels(type='available').set(mem.available)
    memory_usage_bytes.labels(type='used').set(mem.used)
    memory_usage_percent.set(mem.percent)

    # CPU
    cpu_usage_percent.set(psutil.cpu_percent(interval=0.1))
    cpu_count.set(psutil.cpu_count())

    # Disk
    disk = psutil.disk_usage('/')
    disk_usage_bytes.labels(type='total').set(disk.total)
    disk_usage_bytes.labels(type='used').set(disk.used)
    disk_usage_bytes.labels(type='free').set(disk.free)
    disk_usage_percent.set(disk.percent)


def collect_process_metrics():
    """Collect process-specific metrics"""
    process = psutil.Process()

    # Process memory
    mem_info = process.memory_info()
    memory_usage_bytes.labels(type='rss').set(mem_info.rss)
    memory_usage_bytes.labels(type='vms').set(mem_info.vms)


def set_app_info(version: str, commit: Optional[str] = None, branch: Optional[str] = None):
    """Set application information"""
    info = {
        'version': version,
        'python_version': f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}.{psutil.sys.version_info.micro}"
    }

    if commit:
        info['git_commit'] = commit
    if branch:
        info['git_branch'] = branch

    app_info.info(info)


# ============================================================================
# Decorators for Automatic Instrumentation
# ============================================================================

def track_request_metrics(endpoint: str):
    """
    Decorator to automatically track HTTP request metrics.

    Usage:
        @track_request_metrics("/binary/analyze")
        async def analyze_binary(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                # Track success
                http_requests_total.labels(
                    method='POST',  # TODO: Get from request
                    endpoint=endpoint,
                    status='200'
                ).inc()

                return result

            except Exception as e:
                # Track error
                http_requests_total.labels(
                    method='POST',
                    endpoint=endpoint,
                    status='500'
                ).inc()

                errors_total.labels(
                    error_code=type(e).__name__,
                    severity='high'
                ).inc()

                raise

            finally:
                # Track duration
                duration = time.time() - start_time
                http_request_duration_seconds.labels(
                    method='POST',
                    endpoint=endpoint
                ).observe(duration)

        return wrapper
    return decorator


def track_analysis_metrics(analysis_type: str = 'standard'):
    """
    Decorator to track binary analysis metrics.

    Usage:
        @track_analysis_metrics('deep')
        async def deep_analysis(binary_path: str):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                # Track success
                binaries_analyzed_total.labels(status='success').inc()

                return result

            except Exception as e:
                # Track failure
                binaries_analyzed_total.labels(status='failed').inc()
                raise

            finally:
                # Track duration
                duration = time.time() - start_time
                binary_analysis_duration_seconds.labels(
                    analysis_type=analysis_type
                ).observe(duration)

        return wrapper
    return decorator


def track_ai_request(service: str):
    """
    Decorator to track AI service requests.

    Usage:
        @track_ai_request('gemini')
        async def call_gemini(prompt: str):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                # Track success
                ai_requests_total.labels(
                    service=service,
                    status='success'
                ).inc()

                return result

            except Exception as e:
                # Track failure
                ai_requests_total.labels(
                    service=service,
                    status='failed'
                ).inc()
                raise

            finally:
                # Track duration
                duration = time.time() - start_time
                ai_request_duration_seconds.labels(service=service).observe(duration)

        return wrapper
    return decorator


# ============================================================================
# Export Functions
# ============================================================================

def get_metrics() -> bytes:
    """
    Get metrics in Prometheus format.

    Returns:
        bytes: Metrics in Prometheus text format
    """
    # Update system metrics before export
    collect_system_metrics()
    collect_process_metrics()

    return generate_latest(registry)


def get_content_type() -> str:
    """
    Get the content type for Prometheus metrics.

    Returns:
        str: Content type header value
    """
    return CONTENT_TYPE_LATEST


# ============================================================================
# Metric Recording Helpers
# ============================================================================

def record_binary_analyzed(success: bool, size_bytes: int, duration_seconds: float, analysis_type: str = 'standard'):
    """Record binary analysis completion"""
    status = 'success' if success else 'failed'
    binaries_analyzed_total.labels(status=status).inc()
    binary_size_bytes.observe(size_bytes)
    binary_analysis_duration_seconds.labels(analysis_type=analysis_type).observe(duration_seconds)


def record_yara_match(rule_category: str):
    """Record YARA rule match"""
    yara_matches_total.labels(rule_category=rule_category).inc()


def record_crash_found(crash_type: str, exploitability: str):
    """Record fuzzing crash"""
    fuzzing_crashes_total.labels(
        crash_type=crash_type,
        exploitability=exploitability
    ).inc()


def record_cache_access(namespace: str, hit: bool):
    """Record cache hit/miss"""
    if hit:
        cache_hits_total.labels(namespace=namespace).inc()
    else:
        cache_misses_total.labels(namespace=namespace).inc()


def record_error(error_code: str, severity: str = 'medium'):
    """Record error occurrence"""
    errors_total.labels(error_code=error_code, severity=severity).inc()


def record_resource_limit_exceeded(resource: str):
    """Record resource limit violation"""
    resource_limit_exceeded_total.labels(resource=resource).inc()


def record_ai_tokens(service: str, input_tokens: int, output_tokens: int):
    """Record AI token usage"""
    ai_tokens_used_total.labels(service=service, type='input').inc(input_tokens)
    ai_tokens_used_total.labels(service=service, type='output').inc(output_tokens)
