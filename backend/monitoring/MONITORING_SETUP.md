# VRAgent Monitoring Setup Guide

## Overview

VRAgent includes comprehensive monitoring through **Prometheus** and **Grafana**, providing real-time visibility into:

- System resources (CPU, memory, disk)
- API performance (request rates, latency, errors)
- Analysis statistics (binaries, APKs, scans)
- Fuzzing campaigns (executions, coverage, crashes)
- Cache performance (hit rates, memory usage)
- Database performance (queries, connections, transactions)

---

## Quick Start

### 1. Start All Services

```bash
docker-compose up -d
```

This starts:
- Backend (port 8000)
- Prometheus (port 9090)
- Grafana (port 3001)
- All other VRAgent services

### 2. Access Grafana

Open your browser to: **http://localhost:3001**

**Default credentials:**
- Username: `admin`
- Password: `admin`

On first login, you'll be prompted to change the password.

### 3. View Dashboards

Grafana is pre-configured with 4 dashboards:

| Dashboard | Description | URL |
|-----------|-------------|-----|
| **VRAgent - System Overview** | High-level system health, API metrics, scan counts | http://localhost:3001/d/vragent-overview |
| **VRAgent - Fuzzing Campaigns** | Detailed fuzzing metrics, executions, coverage, crashes | http://localhost:3001/d/vragent-fuzzing |
| **VRAgent - Cache Performance** | Redis cache hit rates, memory usage, operations | http://localhost:3001/d/vragent-cache |
| **VRAgent - Database Performance** | PostgreSQL queries, connections, transactions | http://localhost:3001/d/vragent-database |

---

## Dashboard Details

### 1. System Overview Dashboard

**Key Metrics:**
- CPU, Memory, Disk usage gauges
- API request rates and response times (p95, p99)
- Total binaries analyzed, APKs processed
- Active fuzzing campaigns
- Total crashes found

**Use Cases:**
- Quick health check
- Identify resource bottlenecks
- Monitor API performance
- Track analysis progress

### 2. Fuzzing Campaigns Dashboard

**Key Metrics:**
- Active campaigns count
- Executions per minute
- Coverage (edges discovered)
- Crashes by severity
- Unique crashes per campaign
- Corpus size and file count

**Use Cases:**
- Monitor fuzzing campaign progress
- Identify campaigns finding crashes
- Track coverage growth
- Compare campaign effectiveness

### 3. Cache Performance Dashboard

**Key Metrics:**
- Cache hit rate gauge (target: >70%)
- Cache hits vs misses
- Cache operations (sets, deletes, pattern deletes)
- Redis memory usage
- Redis connections
- Key evictions/expirations

**Use Cases:**
- Optimize cache TTL policies
- Identify cache thrashing
- Monitor Redis resource usage
- Detect cache misconfigurations

### 4. Database Performance Dashboard

**Key Metrics:**
- Active database connections
- Queries per minute
- Query duration (p95, p99)
- Queries by operation type (SELECT, INSERT, UPDATE, DELETE)
- Transaction commits vs rollbacks
- Buffer cache hits vs disk reads
- Deadlocks and conflicts
- Table operations by table

**Use Cases:**
- Identify slow queries
- Monitor connection pool usage
- Detect database bottlenecks
- Track transaction rollbacks
- Optimize indexes

---

## Prometheus Metrics

### Accessing Raw Metrics

**Prometheus UI:** http://localhost:9090

**Metrics endpoint:** http://localhost:8000/health/metrics

### Available Metrics

**System Metrics:**
```
node_cpu_seconds_total - CPU time
node_memory_* - Memory statistics
node_filesystem_* - Disk statistics
node_network_* - Network statistics
```

**API Metrics:**
```
vragent_api_requests_total{method, endpoint, status} - Total API requests
vragent_api_request_duration_seconds{endpoint} - Request duration histogram
vragent_api_errors_total{endpoint, error_type} - API errors
```

**Analysis Metrics:**
```
vragent_scans_total{scan_type} - Total scans
vragent_binaries_analyzed_total - Binaries analyzed
vragent_apks_analyzed_total - APKs analyzed
```

**Fuzzing Metrics:**
```
vragent_fuzz_campaigns_active - Active campaigns
vragent_fuzz_executions_total{campaign_id} - Executions
vragent_fuzz_coverage_edges{campaign_id} - Coverage
vragent_fuzz_unique_crashes{campaign_id} - Unique crashes
vragent_crashes_total{severity} - Total crashes
vragent_fuzz_corpus_size_bytes{campaign_id} - Corpus size
vragent_fuzz_corpus_count{campaign_id} - Corpus file count
```

**Cache Metrics:**
```
vragent_cache_hits_total{cache_type} - Cache hits
vragent_cache_misses_total{cache_type} - Cache misses
vragent_cache_operations_total{operation} - Cache operations
redis_memory_used_bytes - Redis memory usage
redis_connected_clients - Redis connections
redis_evicted_keys_total - Evicted keys
redis_expired_keys_total - Expired keys
```

**Database Metrics:**
```
vragent_database_queries_total{operation} - Database queries
vragent_database_query_duration_seconds{operation} - Query duration histogram
pg_stat_activity_count - Active connections
pg_stat_database_xact_commit - Transactions committed
pg_stat_database_xact_rollback - Transactions rolled back
pg_stat_database_blks_hit - Buffer cache hits
pg_stat_database_blks_read - Disk reads
pg_stat_database_deadlocks - Deadlocks
```

---

## Custom Queries

### Prometheus PromQL Examples

**API Request Rate (last 5 minutes):**
```promql
rate(vragent_api_requests_total[5m])
```

**95th Percentile API Latency:**
```promql
histogram_quantile(0.95, sum(rate(vragent_api_request_duration_seconds_bucket[5m])) by (le, endpoint))
```

**Cache Hit Rate:**
```promql
(sum(rate(vragent_cache_hits_total[5m])) / (sum(rate(vragent_cache_hits_total[5m])) + sum(rate(vragent_cache_misses_total[5m])))) * 100
```

**Top 5 Slowest Endpoints:**
```promql
topk(5, histogram_quantile(0.99, sum(rate(vragent_api_request_duration_seconds_bucket[5m])) by (le, endpoint)))
```

**Fuzzing Campaigns with Most Crashes:**
```promql
topk(5, vragent_fuzz_unique_crashes)
```

**Database Query Rate by Type:**
```promql
sum by (operation) (rate(vragent_database_queries_total[5m]))
```

---

## Alerting

### Prometheus Alert Rules

Alert rules are defined in `backend/monitoring/prometheus/rules/alerts.yml`.

**Example alerts:**

**High Error Rate:**
```yaml
- alert: HighAPIErrorRate
  expr: rate(vragent_api_errors_total[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High API error rate detected"
    description: "API error rate is {{ $value }} errors/sec for endpoint {{ $labels.endpoint }}"
```

**Low Cache Hit Rate:**
```yaml
- alert: LowCacheHitRate
  expr: (sum(rate(vragent_cache_hits_total[5m])) / (sum(rate(vragent_cache_hits_total[5m])) + sum(rate(vragent_cache_misses_total[5m])))) * 100 < 50
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Cache hit rate below 50%"
    description: "Cache hit rate is {{ $value }}% - consider adjusting TTL policies"
```

**Database Connection Pool Exhaustion:**
```yaml
- alert: DatabaseConnectionPoolExhausted
  expr: pg_stat_activity_count > 80
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Database connection pool near exhaustion"
    description: "Active connections: {{ $value }} / 100 limit"
```

**Fuzzing Campaign Stuck:**
```yaml
- alert: FuzzingCampaignStuck
  expr: rate(vragent_fuzz_executions_total[5m]) == 0 and vragent_fuzz_campaigns_active > 0
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "Fuzzing campaign {{ $labels.campaign_id }} appears stuck"
    description: "No executions for 15 minutes"
```

### Configuring Alertmanager

1. **Create alertmanager.yml:**
```yaml
route:
  receiver: 'default-receiver'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h

receivers:
  - name: 'default-receiver'
    email_configs:
      - to: 'your-email@example.com'
        from: 'alertmanager@vragent.local'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'your-email@example.com'
        auth_password: 'your-password'
```

2. **Add to docker-compose.yml:**
```yaml
alertmanager:
  image: prom/alertmanager:latest
  container_name: vragent-alertmanager
  ports:
    - "9093:9093"
  volumes:
    - ./backend/monitoring/prometheus/alertmanager.yml:/etc/alertmanager/alertmanager.yml
  restart: unless-stopped
```

---

## Performance Tuning

### Prometheus Retention

**Default:** 30 days

**Change retention:**
Edit `docker-compose.yml`:
```yaml
prometheus:
  command:
    - '--storage.tsdb.retention.time=90d'  # Change to 90 days
```

### Grafana Performance

**For large installations:**

1. **Increase query timeout:**
```yaml
grafana:
  environment:
    - GF_DATAPROXY_TIMEOUT=300  # 5 minutes
```

2. **Enable query caching:**
```yaml
grafana:
  environment:
    - GF_CACHE_ENABLED=true
```

### Prometheus Scrape Interval

**Default:** 15 seconds

**Change scrape interval:**
Edit `backend/monitoring/prometheus/prometheus.yml`:
```yaml
global:
  scrape_interval: 30s  # Reduce load, less frequent updates
```

---

## Troubleshooting

### Prometheus Not Scraping Metrics

**Check Prometheus targets:**
1. Open http://localhost:9090/targets
2. Verify backend target is "UP"
3. If "DOWN", check backend is running: `docker-compose ps backend`

**Check metrics endpoint:**
```bash
curl http://localhost:8000/health/metrics
```

Should return Prometheus-formatted metrics.

### Grafana Dashboards Empty

**Verify Prometheus datasource:**
1. In Grafana, go to Configuration → Data Sources
2. Click on "Prometheus"
3. Verify URL is `http://prometheus:9090`
4. Click "Save & Test"

**Verify data is being collected:**
1. Open Prometheus UI: http://localhost:9090
2. Run query: `vragent_api_requests_total`
3. If no data, check backend is exporting metrics

### Redis Metrics Missing

**Install Redis exporter:**

Add to `docker-compose.yml`:
```yaml
redis-exporter:
  image: oliver006/redis_exporter:latest
  container_name: vragent-redis-exporter
  ports:
    - "9121:9121"
  environment:
    - REDIS_ADDR=redis://redis:6379
  depends_on:
    - redis
  restart: unless-stopped
```

Add scrape config to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### PostgreSQL Metrics Missing

**Install Postgres exporter:**

Add to `docker-compose.yml`:
```yaml
postgres-exporter:
  image: prometheuscommunity/postgres-exporter:latest
  container_name: vragent-postgres-exporter
  ports:
    - "9187:9187"
  environment:
    - DATA_SOURCE_NAME=postgresql://vragent:vragent_secret@db:5432/vragent?sslmode=disable
  depends_on:
    - db
  restart: unless-stopped
```

Add scrape config to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'postgresql'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

---

## Security

### Grafana Security

**Change default password:**
1. Login to Grafana
2. Go to Profile → Change Password

**Disable anonymous access:**
```yaml
grafana:
  environment:
    - GF_AUTH_ANONYMOUS_ENABLED=false
```

**Enable HTTPS:**
```yaml
grafana:
  environment:
    - GF_SERVER_PROTOCOL=https
    - GF_SERVER_CERT_FILE=/etc/grafana/cert.pem
    - GF_SERVER_CERT_KEY=/etc/grafana/key.pem
  volumes:
    - ./certs/cert.pem:/etc/grafana/cert.pem:ro
    - ./certs/key.pem:/etc/grafana/key.pem:ro
```

### Prometheus Security

**Basic authentication:**

1. **Generate password hash:**
```bash
htpasswd -nB admin
```

2. **Create web.yml:**
```yaml
basic_auth_users:
  admin: $2y$05$...hash...
```

3. **Update docker-compose.yml:**
```yaml
prometheus:
  command:
    - '--web.config.file=/etc/prometheus/web.yml'
  volumes:
    - ./backend/monitoring/prometheus/web.yml:/etc/prometheus/web.yml:ro
```

---

## Backup & Restore

### Prometheus Data

**Backup:**
```bash
docker run --rm -v vragent_prometheus_data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-backup.tar.gz /data
```

**Restore:**
```bash
docker run --rm -v vragent_prometheus_data:/data -v $(pwd):/backup alpine tar xzf /backup/prometheus-backup.tar.gz -C /
```

### Grafana Data

**Backup:**
```bash
docker run --rm -v vragent_grafana_data:/data -v $(pwd):/backup alpine tar czf /backup/grafana-backup.tar.gz /data
```

**Restore:**
```bash
docker run --rm -v vragent_grafana_data:/data -v $(pwd):/backup alpine tar xzf /backup/grafana-backup.tar.gz -C /
```

---

## Advanced Configuration

### Custom Dashboard

1. **In Grafana UI:**
   - Click "+" → "Dashboard"
   - Add panels with custom queries
   - Save dashboard

2. **Export as JSON:**
   - Click "Share" → "Export"
   - Save to `backend/monitoring/grafana/dashboards/`

3. **Reload dashboards:**
```bash
docker-compose restart grafana
```

### Custom Metrics

**Add custom metrics to backend:**

```python
from prometheus_client import Counter, Histogram

# Define custom metric
custom_operations = Counter(
    'vragent_custom_operations_total',
    'Total custom operations',
    ['operation_type']
)

# Use in code
custom_operations.labels(operation_type='decompilation').inc()
```

**Query in Grafana:**
```promql
rate(vragent_custom_operations_total[5m])
```

---

## Support

For issues with monitoring:

1. Check docker-compose logs: `docker-compose logs prometheus grafana`
2. Verify services are running: `docker-compose ps`
3. Check Prometheus targets: http://localhost:9090/targets
4. Check Grafana logs: `docker-compose logs grafana`
5. Open issue: https://github.com/your-org/vragent/issues

---

## Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Tutorial](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)
