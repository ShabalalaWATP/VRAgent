# VRAgent Monitoring

Complete monitoring solution for VRAgent using Prometheus and Grafana.

## Features

- **Real-time Metrics**: CPU, memory, disk, network
- **API Performance**: Request rates, latency, error rates
- **Analysis Tracking**: Binary/APK scans, findings, reports
- **Fuzzing Metrics**: Campaign progress, executions, coverage, crashes
- **Cache Performance**: Redis hit rates, memory usage
- **Database Performance**: Query times, connections, transactions
- **Pre-built Dashboards**: 4 comprehensive Grafana dashboards
- **Alert Rules**: 20+ alert rules for proactive monitoring

## Quick Start

### 1. Start All Services

```bash
# From VRAgent root directory
docker-compose up -d
```

This starts:
- Prometheus (metrics collection) on port **9090**
- Grafana (visualization) on port **3001**
- All VRAgent services

### 2. Access Dashboards

**Grafana:** http://localhost:3001
- Username: `admin`
- Password: `admin` (change on first login)

**Prometheus:** http://localhost:9090

### 3. View Pre-built Dashboards

Navigate to: Dashboards → Browse → VRAgent folder

- **System Overview** - High-level health metrics
- **Fuzzing Campaigns** - Detailed fuzzing progress
- **Cache Performance** - Redis metrics and hit rates
- **Database Performance** - PostgreSQL query performance

## Directory Structure

```
backend/monitoring/
├── README.md                           # This file
├── MONITORING_SETUP.md                 # Detailed setup guide
├── grafana/
│   ├── dashboards/
│   │   ├── vragent_overview.json      # System overview dashboard
│   │   ├── vragent_fuzzing.json       # Fuzzing metrics dashboard
│   │   ├── vragent_cache.json         # Cache performance dashboard
│   │   └── vragent_database.json      # Database performance dashboard
│   └── provisioning/
│       ├── dashboards/
│       │   └── dashboards.yml         # Dashboard provisioning config
│       └── datasources/
│           └── prometheus.yml         # Prometheus datasource config
└── prometheus/
    ├── prometheus.yml                 # Prometheus main config
    └── rules/
        └── alerts.yml                 # Alert rules
```

## Available Dashboards

### 1. VRAgent - System Overview
**URL:** http://localhost:3001/d/vragent-overview

High-level view of system health:
- CPU, Memory, Disk usage
- API request rates and latency
- Total scans, binaries analyzed, APKs processed
- Active fuzzing campaigns
- Total crashes discovered

### 2. VRAgent - Fuzzing Campaigns
**URL:** http://localhost:3001/d/vragent-fuzzing

Detailed fuzzing metrics:
- Active campaigns
- Executions per minute
- Coverage (edges) over time
- Crashes by severity
- Unique crashes per campaign
- Corpus size and file count

### 3. VRAgent - Cache Performance
**URL:** http://localhost:3001/d/vragent-cache

Redis cache metrics:
- Cache hit rate gauge
- Hits vs misses
- Cache operations (sets, deletes, patterns)
- Memory usage
- Connection count
- Key evictions/expirations

### 4. VRAgent - Database Performance
**URL:** http://localhost:3001/d/vragent-database

PostgreSQL performance:
- Active connections
- Queries per minute
- Query duration (p95, p99)
- Transaction commits vs rollbacks
- Buffer cache efficiency
- Deadlocks and conflicts
- Table operations

## Key Metrics

### API Performance
```promql
# Request rate
rate(vragent_api_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95, sum(rate(vragent_api_request_duration_seconds_bucket[5m])) by (le, endpoint))

# Error rate
rate(vragent_api_errors_total[5m])
```

### Fuzzing
```promql
# Executions per second
rate(vragent_fuzz_executions_total[5m])

# Coverage growth
rate(vragent_fuzz_coverage_edges[30m])

# Unique crashes
vragent_fuzz_unique_crashes
```

### Cache
```promql
# Hit rate
(sum(rate(vragent_cache_hits_total[5m])) / (sum(rate(vragent_cache_hits_total[5m])) + sum(rate(vragent_cache_misses_total[5m])))) * 100
```

### Database
```promql
# Query latency p99
histogram_quantile(0.99, sum(rate(vragent_database_query_duration_seconds_bucket[5m])) by (le))
```

## Alert Rules

20+ pre-configured alerts for:

**API Alerts:**
- High error rate (>0.1 errors/sec for 5min)
- High latency (p99 >5s for 5min)
- API down (>1min)

**Cache Alerts:**
- Low hit rate (<50% for 10min)
- High Redis memory (>90% for 5min)
- High connection count (>100 for 5min)

**Database Alerts:**
- High connection count (>80 for 5min)
- Slow queries (p95 >1s for 5min)
- High rollback rate (>10% for 5min)
- Deadlocks detected

**Fuzzing Alerts:**
- Campaign stuck (no executions for 15min)
- High crash rate (>10/sec - good news!)
- No coverage growth (30min)

**System Alerts:**
- High CPU (>90% for 10min)
- High memory (>90% for 5min)
- Low disk space (>85%)
- Critical disk space (>95%)

## Advanced Configuration

### Add Node Exporter (System Metrics)

Add to `docker-compose.yml`:
```yaml
node-exporter:
  image: prom/node-exporter:latest
  container_name: vragent-node-exporter
  ports:
    - "9100:9100"
  restart: unless-stopped
```

Uncomment in `prometheus/prometheus.yml`:
```yaml
- job_name: 'node-exporter'
  static_configs:
    - targets: ['node-exporter:9100']
```

### Add Redis Exporter

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

Uncomment in `prometheus/prometheus.yml`:
```yaml
- job_name: 'redis'
  static_configs:
    - targets: ['redis-exporter:9121']
```

### Add PostgreSQL Exporter

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

Uncomment in `prometheus/prometheus.yml`:
```yaml
- job_name: 'postgresql'
  static_configs:
    - targets: ['postgres-exporter:9187']
```

## Troubleshooting

### Prometheus Not Scraping

**Check targets status:**
```
http://localhost:9090/targets
```

If backend is "DOWN":
```bash
# Verify backend is running
docker-compose ps backend

# Check backend health endpoint
curl http://localhost:8000/health/metrics
```

### Grafana Dashboards Empty

**Verify Prometheus datasource:**
1. Go to Configuration → Data Sources
2. Click "Prometheus"
3. Verify URL: `http://prometheus:9090`
4. Click "Save & Test"

**Check Prometheus has data:**
```bash
# Query Prometheus directly
curl 'http://localhost:9090/api/v1/query?query=vragent_api_requests_total'
```

### View Logs

```bash
# Prometheus logs
docker-compose logs prometheus

# Grafana logs
docker-compose logs grafana

# Backend logs
docker-compose logs backend
```

## Backup & Restore

### Backup Prometheus Data
```bash
docker run --rm -v vragent_prometheus_data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-backup.tar.gz /data
```

### Restore Prometheus Data
```bash
docker run --rm -v vragent_prometheus_data:/data -v $(pwd):/backup alpine tar xzf /backup/prometheus-backup.tar.gz -C /
```

### Backup Grafana Data
```bash
docker run --rm -v vragent_grafana_data:/data -v $(pwd):/backup alpine tar czf /backup/grafana-backup.tar.gz /data
```

### Restore Grafana Data
```bash
docker run --rm -v vragent_grafana_data:/data -v $(pwd):/backup alpine tar xzf /backup/grafana-backup.tar.gz -C /
```

## Documentation

For detailed documentation, see:
- [Monitoring Setup Guide](./MONITORING_SETUP.md) - Complete setup and configuration guide
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

## Support

For issues:
1. Check logs: `docker-compose logs prometheus grafana`
2. Verify services: `docker-compose ps`
3. Check Prometheus targets: http://localhost:9090/targets
4. Open issue: https://github.com/your-org/vragent/issues
