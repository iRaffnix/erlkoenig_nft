# Observability

erlkoenig_nft exports metrics, traces, and structured logs via
[OpenTelemetry](https://opentelemetry.io/) (OTLP). This lets you feed
operational data into Grafana, Datadog, Honeycomb, Jaeger, or any
OTLP-compatible backend without vendor lock-in.

## Architecture

```
erlkoenig_nft                  OTel Collector            Backend
─────────────                  ──────────────            ───────
counter events ─┐
conntrack      ─┤  OTLP/HTTP
guard stats    ──┼────────────→  receive, batch,   ──→  Prometheus (metrics)
nflog drops    ──┤  :4318        transform, export      Tempo/Jaeger (traces)
ban/unban spans─┘                                       Loki (logs)
                                                            │
                                                            ▼
                                                        Grafana
```

The instrumentation module (`erlkoenig_nft_otel`) subscribes to internal
event streams and pushes data via OTLP. The application code depends only
on `opentelemetry_api` (zero transitive dependencies). The SDK and
exporter are included only in the production release.

When the SDK is not loaded (tests, library use), all telemetry calls are
no-ops with zero overhead.

## Quick Start

### 1. Run an OTel Collector

The simplest path is the
[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
with a Prometheus + Tempo backend. A minimal Docker Compose setup:

```yaml
# docker-compose.otel.yml
services:
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    ports:
      - "4318:4318"   # OTLP HTTP receiver
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol/config.yaml

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
```

Collector config:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  prometheus:
    endpoint: 0.0.0.0:8889
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true
  loki:
    endpoint: http://loki:3100/loki/api/v1/push

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
    traces:
      receivers: [otlp]
      exporters: [otlp/tempo]
    logs:
      receivers: [otlp]
      exporters: [loki]
```

Prometheus scrape config for the collector:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: otel-collector
    static_configs:
      - targets: ["otel-collector:8889"]
```

### 2. Configure erlkoenig_nft

The OTLP exporter is configured via environment variables (recommended)
or `sys.config`.

**Environment variables** (standard OTel):

```bash
export OTEL_SERVICE_NAME=erlkoenig_nft
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

**sys.config** (in `config/sys.config`):

```erlang
{opentelemetry, [
    {span_processor, batch},
    {resource, [
        {service, [
            {name, <<"erlkoenig_nft">>},
            {version, <<"0.7.0">>}
        ]}
    ]}
]},
{opentelemetry_exporter, [
    {otlp_protocol, http_protobuf},
    {otlp_endpoint, "http://localhost:4318"}
]}
```

### 3. Build and Run

```bash
make release           # or: rebar3 as prod release
_build/prod/rel/erlkoenig_nft/bin/erlkoenig_nft foreground
```

The OTel instrumentation starts automatically. You should see:

```
=INFO REPORT==== OTel instrumentation active
```

If the SDK is not present (dev build without prod profile), you'll see
no message — the module returns `ignore` silently.

### 4. Connect Grafana

1. Open Grafana at `http://localhost:3000`
2. Add data sources:
   - **Prometheus** at `http://prometheus:9090`
   - **Tempo** at `http://tempo:3200` (if running traces)
   - **Loki** at `http://loki:3100` (if running logs)
3. Create dashboards or use Explore to query metrics

## Metrics Reference

All metrics use the `erlkoenig.nft` namespace.

### Counter Traffic

Per named firewall counter (label: `name`).

| Metric | Type | Description |
|---|---|---|
| `erlkoenig.nft.counter.packets` | Counter | Total packets through counter |
| `erlkoenig.nft.counter.bytes` | Counter | Total bytes through counter |
| `erlkoenig.nft.counter.pps` | Gauge | Current packets per second |
| `erlkoenig.nft.counter.bps` | Gauge | Current bytes per second |

Example Prometheus query — packets per second for all counters:

```promql
erlkoenig_nft_counter_pps
```

Per-counter:

```promql
erlkoenig_nft_counter_pps{name="ssh"}
```

### Connection Tracking

| Metric | Type | Description |
|---|---|---|
| `erlkoenig.nft.ct.active` | Gauge | Active tracked connections |
| `erlkoenig.nft.ct.new` | Counter | Total new connections seen |
| `erlkoenig.nft.ct.destroy` | Counter | Total connections destroyed |

### Threat Detection

Polled every 10 seconds from `guard_stats/0`.

| Metric | Type | Description |
|---|---|---|
| `erlkoenig.nft.guard.floods` | Counter | Connection floods detected |
| `erlkoenig.nft.guard.scans` | Counter | Port scans detected |
| `erlkoenig.nft.guard.active_bans` | Gauge | Currently banned IPs |
| `erlkoenig.nft.guard.bans_issued` | Counter | Total bans issued |

### NFLOG

| Metric | Type | Description |
|---|---|---|
| `erlkoenig.nft.nflog.packets` | Counter | Dropped packets logged via NFLOG |

## Traces Reference

Spans are emitted for mutating operations. Each span includes the
operation duration, result (`ok` or `error`), and relevant attributes.

| Span Name | Trigger | Attributes |
|---|---|---|
| `nft.ban` | `erlkoenig_nft:ban/1` | `ip` |
| `nft.unban` | `erlkoenig_nft:unban/1` | `ip` |
| `nft.reload` | `erlkoenig_nft:reload/0` | — |
| `nft.add_element` | `erlkoenig_nft:add_element/2` | `set`, `value` |
| `nft.del_element` | `erlkoenig_nft:del_element/2` | `set`, `value` |

All spans set `result=ok` or `result=error` with `error.type` and
`error.message` attributes on failure.

## Structured Logs Reference

Log events are emitted via Erlang's `logger` with OTel-compatible
metadata. When the OTel log bridge is active, these are exported as
OTLP log records correlated with the active trace context.

| Event | Severity | Fields |
|---|---|---|
| `nft.ban` | WARN | `ip` |
| `nft.unban` | INFO | `ip` |
| `nft.reload` | INFO | — |
| `nft.ct.alert` | WARN | `alert` (mode switch details) |
| `nft.nflog.drop` | WARN | `src`, `dst`, `proto` |
| `nft.guard.flood_detected` | WARN | `total` |
| `nft.guard.scan_detected` | WARN | `total` |

## Grafana Dashboard Examples

### Firewall Overview Panel (Prometheus)

```promql
# Packets per second across all counters
sum(erlkoenig_nft_counter_pps) by (name)

# Active connections
erlkoenig_nft_ct_active

# Ban rate (bans per 5 minutes)
increase(erlkoenig_nft_guard_bans_issued[5m])
```

### Alert Rules

```yaml
# Grafana alerting rule: high ban rate
- alert: HighBanRate
  expr: increase(erlkoenig_nft_guard_bans_issued[5m]) > 10
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "erlkoenig_nft issued {{ $value }} bans in 5 minutes"

# Connection flood detection active
- alert: FloodDetected
  expr: increase(erlkoenig_nft_guard_floods[5m]) > 0
  labels:
    severity: critical
```

## Dependency Footprint

| Scope | Package | Transitive Deps |
|---|---|---|
| Application | `opentelemetry_api ~> 1.5` | 0 |
| Prod release | `opentelemetry ~> 1.7` | 1 (`opentelemetry_api`) |
| Prod release | `opentelemetry_exporter ~> 1.10` | 3 (`opentelemetry`, `opentelemetry_api`, `tls_certificate_check`) |

The API package is the only compile-time dependency. The SDK and
exporter are release-level only — they do not affect library consumers.

## Disabling Telemetry

To run without telemetry (tests, development, library use):

- **Don't include the SDK in your release** — all calls become no-ops
- Or set `OTEL_SDK_DISABLED=true` at runtime
- The `erlkoenig_nft_otel` gen_server returns `ignore` when the SDK
  module is not loaded — zero processes spawned, zero overhead

## Standalone vs. Integrated Mode

When erlkoenig_nft runs as a dependency of the main erlkoenig runtime,
the OTel config is shared. Set `OTEL_SERVICE_NAME=erlkoenig` at the
release level — spans and metrics from both applications appear under
one service in your backend.

When running standalone (own release), set
`OTEL_SERVICE_NAME=erlkoenig_nft`.
