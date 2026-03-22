# Tutorial: Grafana Observability for erlkoenig_nft

This is a hands-on, step-by-step guide to getting full observability
for erlkoenig_nft — metrics, traces, and structured logs — visible in
Grafana dashboards.

By the end of this tutorial you will have:

- An OpenTelemetry Collector receiving telemetry from erlkoenig_nft
- Prometheus storing firewall metrics (counter rates, conntrack, threat detection)
- Tempo storing operation traces (ban, unban, reload)
- Loki storing structured log events (bans, alerts, drops)
- Grafana dashboards showing all of it

## Prerequisites

- Docker and Docker Compose (v2)
- Erlang/OTP 28+ installed
- erlkoenig_nft source checked out
- `make` available
- About 1 GB of free RAM for the containers

## Overview

```
┌─────────────────────┐
│   erlkoenig_nft     │
│                     │
│  erlkoenig_nft_otel │──── OTLP/HTTP ────┐
│  (metrics, traces,  │     :4318         │
│   logs)             │                    ▼
└─────────────────────┘          ┌─────────────────┐
                                 │  OTel Collector  │
                                 │                  │
                                 │  metrics ──→ Prometheus :9090
                                 │  traces  ──→ Tempo      :3200
                                 │  logs    ──→ Loki       :3100
                                 └─────────────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │     Grafana      │
                                 │     :3000        │
                                 └─────────────────┘
```

## Step 1: Set Up the Observability Stack

All configuration files are provided in this tutorial directory.

Start the full stack:

```bash
cd tutorials/grafana-observability
docker compose up -d
```

Verify everything is running:

```bash
docker compose ps
```

You should see five healthy containers: `otel-collector`, `prometheus`,
`tempo`, `loki`, and `grafana`.

Check that the collector is accepting OTLP:

```bash
curl -s http://localhost:4318/v1/metrics -X POST \
  -H "Content-Type: application/json" -d '{}' | head -1
```

A non-connection-error response (even an error body) means the
collector is listening.

## Step 2: Build erlkoenig_nft with OTel

From the erlkoenig_nft root directory, build the production release:

```bash
cd /path/to/erlkoenig_nft
rebar3 as prod release
```

This pulls in `opentelemetry`, `opentelemetry_exporter`, and their
dependencies — they are only included in the `prod` profile.

Verify the release includes the OTel applications:

```bash
ls _build/prod/rel/erlkoenig_nft/lib/ | grep opentelemetry
```

You should see `opentelemetry-1.x.x`, `opentelemetry_api-1.x.x`, and
`opentelemetry_exporter-1.x.x`.

## Step 3: Configure and Start erlkoenig_nft

Set the environment variables for the OTLP exporter:

```bash
export OTEL_SERVICE_NAME=erlkoenig_nft
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

Start the release (needs root/CAP_NET_ADMIN for firewall operations):

```bash
sudo -E _build/prod/rel/erlkoenig_nft/bin/erlkoenig_nft foreground
```

You should see in the logs:

```
=INFO REPORT==== OTel instrumentation active
=INFO REPORT==== Firewall applied: table=webserver, chains=2, counters=5
```

The `-E` flag preserves the `OTEL_*` environment variables through sudo.

## Step 4: Generate Some Telemetry

Open a second terminal and attach to the running node:

```bash
sudo _build/prod/rel/erlkoenig_nft/bin/erlkoenig_nft remote_console
```

Now generate events from the Erlang shell:

```erlang
%% Ban an IP — creates a span + log event + updates guard metrics
erlkoenig_nft:ban("203.0.113.42").

%% Check guard stats
erlkoenig_nft:guard_stats().

%% Unban it
erlkoenig_nft:unban("203.0.113.42").

%% Reload config — creates a span
erlkoenig_nft:reload().

%% Add an element to a set — creates a span
erlkoenig_nft:add_element(<<"blocklist">>, "198.51.100.1").

%% Remove it
erlkoenig_nft:del_element(<<"blocklist">>, "198.51.100.1").

%% Check counter rates (these are reported as metrics automatically)
erlkoenig_nft:rates().

%% Check active connections
erlkoenig_nft:ct_count().
```

Each of these operations emits OTel signals. The counter metrics are
exported continuously as traffic flows.

Alternatively, use the JSON API socket:

```bash
echo '{"cmd":"ban","ip":"203.0.113.42"}' | \
  sudo socat - UNIX-CONNECT:/run/erlkoenig_nft/api.sock

echo '{"cmd":"unban","ip":"203.0.113.42"}' | \
  sudo socat - UNIX-CONNECT:/run/erlkoenig_nft/api.sock
```

## Step 5: Verify Data in Prometheus

Open Prometheus at http://localhost:9090 and run these queries:

```promql
# All exported metrics from erlkoenig_nft
{job="otel-collector"}

# Counter packets per second
erlkoenig_nft_counter_pps

# Active connections
erlkoenig_nft_ct_active

# Bans issued
erlkoenig_nft_guard_bans_issued
```

If you see results, the full pipeline is working:
erlkoenig_nft -> OTel Collector -> Prometheus.

## Step 6: Set Up Grafana Dashboards

Open Grafana at http://localhost:3000 (no login required — anonymous
admin is enabled in the tutorial compose file).

The data sources are auto-provisioned. Go to **Explore** and select:

- **Prometheus** for metrics
- **Tempo** for traces
- **Loki** for logs

### Import the Tutorial Dashboard

1. Go to **Dashboards** -> **Import**
2. Upload or paste the contents of `dashboard.json` from this directory
3. Select the Prometheus data source when prompted
4. Click **Import**

The dashboard includes:

- **Firewall Traffic** — packets/sec and bytes/sec per named counter
- **Connection Tracking** — active connections over time
- **Threat Detection** — floods detected, scans detected, active bans
- **NFLOG Drops** — dropped packets over time
- **Operations** — ban/unban/reload activity

### Build Your Own Panels

Here are useful queries for building custom panels:

**Traffic overview — stacked area chart:**

```promql
sum by (name) (erlkoenig_nft_counter_pps)
```

**Connection pressure — single stat:**

```promql
erlkoenig_nft_ct_active
```

**Ban rate — bar chart (per 5min):**

```promql
increase(erlkoenig_nft_guard_bans_issued[5m])
```

**Threat detection timeline — stacked bars:**

```promql
increase(erlkoenig_nft_guard_floods[5m])
increase(erlkoenig_nft_guard_scans[5m])
```

**Top SSH rate — gauge:**

```promql
erlkoenig_nft_counter_pps{name="ssh"}
```

## Step 7: Explore Traces

In Grafana, go to **Explore** -> select **Tempo**.

Search for traces by service name `erlkoenig_nft`. You should see
spans for each `ban`, `unban`, `reload`, `add_element`, and
`del_element` operation you triggered in Step 4.

Click a trace to see:

- **Duration** of the operation (how long the netlink transaction took)
- **Attributes**: `ip`, `set`, `value`, `result`
- **Error details** if the operation failed

Traces are especially useful for debugging slow bans (netlink socket
contention) or failed reloads (config parse errors).

## Step 8: Explore Logs

In Grafana, go to **Explore** -> select **Loki**.

Query structured log events:

```logql
{service_name="erlkoenig_nft"}
```

Filter by event type:

```logql
{service_name="erlkoenig_nft"} |= "nft.ban"
```

Filter for threat alerts only:

```logql
{service_name="erlkoenig_nft"} |= "guard"
```

Each log entry includes the OTel trace ID, so you can click through
from a log event to the corresponding trace in Tempo.

## Step 9: Set Up Alerts

In Grafana, go to **Alerting** -> **Alert Rules** -> **New Rule**.

### Example: High Ban Rate

- **Query**: `increase(erlkoenig_nft_guard_bans_issued[5m]) > 10`
- **Condition**: "Is above 10"
- **Evaluate every**: 1m
- **For**: 2m
- **Label**: severity = warning
- **Summary**: "erlkoenig_nft issued {{ $value }} bans in 5 minutes"

### Example: Flood Detected

- **Query**: `increase(erlkoenig_nft_guard_floods[5m]) > 0`
- **Condition**: "Is above 0"
- **Evaluate every**: 30s
- **For**: 0m (fire immediately)
- **Label**: severity = critical
- **Summary**: "Connection flood detected"

### Example: High Connection Count

- **Query**: `erlkoenig_nft_ct_active > 50000`
- **Condition**: "Is above 50000"
- **Evaluate every**: 1m
- **For**: 5m
- **Label**: severity = warning
- **Summary**: "Active connections at {{ $value }}, approaching mode switch threshold"

## Cleanup

Stop the observability stack:

```bash
cd tutorials/grafana-observability
docker compose down -v
```

The `-v` flag removes the data volumes. Omit it to keep historical data.

## Troubleshooting

### No metrics in Prometheus

1. Check the collector logs: `docker compose logs otel-collector`
2. Verify erlkoenig_nft OTel is active: look for "OTel instrumentation active" in logs
3. Verify the endpoint: `echo $OTEL_EXPORTER_OTLP_ENDPOINT` should be `http://localhost:4318`
4. Check Prometheus targets: http://localhost:9090/targets — the `otel-collector` job should be UP

### No traces in Tempo

1. Traces require mutating operations (ban, unban, reload). Read-only queries like `rates()` don't create spans.
2. Check Tempo is receiving: `docker compose logs tempo`
3. In Grafana Explore, make sure you're searching by `service.name = erlkoenig_nft`

### OTel instrumentation not active

If you don't see the "OTel instrumentation active" log:

1. Make sure you built with `rebar3 as prod release` (not `rebar3 release`)
2. Check the release includes OTel: `ls _build/prod/rel/erlkoenig_nft/lib/ | grep otel`
3. The `opentelemetry` application must be started before `erlkoenig_nft` — the relx config handles this

### erlkoenig_nft_otel returns ignore

This is normal when:
- Running a dev build (`rebar3 release` without `as prod`)
- Running tests (`make test`)
- Using erlkoenig_nft as a library dependency

The module checks `code:ensure_loaded(opentelemetry)` on init. If the
SDK is not in the code path, it returns `ignore` — no process, no overhead.

## Next Steps

- Add the other erlkoenig applications (erlkoenig, erlkoenig_fuse, erlkoenig_elf) to the same collector for unified observability
- Set up Grafana notification channels (Slack, PagerDuty, email) for the alert rules
- Deploy the OTel Collector as a sidecar or DaemonSet in production
- Explore the Grafana Tempo service graph for cross-service correlation when running the full erlkoenig cluster
