# Tutorial: Grafana Observability for erlkoenig_nft

End-to-end guide: erlkoenig_nft firewall metrics and traces in Grafana.

## What You Get

- Live firewall counters (SSH packets/sec, dropped packets/sec) in Grafana
- Traces for every ban, unban, and reload operation
- Alerts when thresholds are exceeded

## Prerequisites

- Docker and Docker Compose (v2)
- Erlang/OTP 28+
- erlkoenig_nft source checked out

## Step 1: Write the Firewall Config

The tutorial ships a ready-made config in `firewall.exs`. Here's what it does:

```elixir
defmodule Firewall.OtelTest do
  use ErlkoenigNft.Firewall

  firewall "erlkoenig" do
    counters [:ssh, :icmp, :dropped]

    chain "input", hook: :input, priority: 0, policy: :drop do
      accept :established          # allow replies to outgoing connections
      accept :loopback             # CRITICAL: OTLP exports to localhost:4318
      accept :icmp                 # allow ping
      accept_protocol :icmpv6      # allow IPv6 ping
      accept_tcp 22, counter: :ssh # allow SSH, count packets
      log_and_drop "DROP: ", counter: :dropped  # drop + count everything else
    end
  end
end
```

**Why `accept :loopback` matters:** erlkoenig_nft exports telemetry to the
OTel Collector on `localhost:4318`. Without the loopback rule, the firewall
blocks its own export traffic. This is the most common mistake.

The watch section defines which counters to monitor and at what thresholds:

```elixir
defmodule Watch.OtelTest do
  use ErlkoenigNft.Watch

  watch :otel_test do
    counter :ssh, :pps, threshold: 100      # alert if SSH > 100 pps
    counter :icmp, :pps, threshold: 50      # alert if ICMP > 50 pps
    counter :dropped, :pps, threshold: 200  # alert if drops > 200 pps
    interval 2000                           # poll every 2 seconds
    on_alert :log
  end
end
```

These counters become the metrics you see in Grafana. Every 2 seconds,
erlkoenig_nft reads the kernel counters, computes packets/sec and bytes/sec,
and pushes them via OTLP.

## Step 2: Start the Observability Stack

```bash
cd tutorials/grafana-observability
docker compose up -d
```

This starts:

| Container | Port | Role |
|---|---|---|
| OTel Collector | 4318 | Receives OTLP from erlkoenig_nft |
| Prometheus | 9090 | Stores metrics |
| Tempo | 3200 | Stores traces |
| Loki | 3100 | Stores logs |
| Grafana | 3000 | Dashboards |

Verify the collector is ready:

```bash
curl -s -X POST http://localhost:4318/v1/traces \
  -H "Content-Type: application/json" -d '{}'
```

Any response (even an error body) means it's listening.

## Step 3: Build and Install

Build the production release:

```bash
cd /path/to/erlkoenig_nft
rebar3 as prod tar
```

Install with OTel export enabled:

```bash
sudo sh install.sh --local _build/prod/rel/erlkoenig_nft \
  --otel-endpoint http://localhost:4318
```

The `--otel-endpoint` flag configures the OTLP export target directly
in the systemd service.

## Step 4: Deploy the Firewall Config

Compile the DSL config and apply it:

```bash
sudo erlkoenig-nft compile tutorials/grafana-observability/firewall.exs \
  -o /opt/erlkoenig_nft/etc/firewall.term
sudo systemctl restart erlkoenig_nft
```

Verify the rules are applied:

```bash
sudo nft list ruleset
```

You should see:

```
table inet erlkoenig {
    counter ssh { packets 0 bytes 0 }
    counter icmp { packets 0 bytes 0 }
    counter dropped { packets 0 bytes 0 }

    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname "lo" accept
        icmp type echo-request accept
        meta l4proto ipv6-icmp accept
        tcp dport 22 counter name "ssh" accept
        log prefix "DROP: " counter name "dropped" drop
    }
}
```

## Step 5: Generate Traces

Counter metrics flow automatically as traffic hits the firewall. But
traces only appear for mutating operations. Trigger some:

```bash
# Reload the config (creates a nft.reload span)
echo '{"cmd":"reload"}' | sudo nc -U -q1 /run/erlkoenig_nft/api.sock
```

Wait 10 seconds for the OTel batch exporter to flush, then check Grafana.

## Step 6: Open Grafana

Open http://localhost:3000 (no login needed).

The tutorial auto-provisions all data sources and a dashboard.
Go to **Dashboards** -> **erlkoenig** -> **erlkoenig_nft Firewall**.

You should see:

- **Packets per Second** — one line per counter (ssh, dropped)
- **Active Connections** — conntrack gauge
- **Threat Detection** — floods, scans, active bans

To explore traces: **Explore** -> **Tempo** -> search for
`service.name = erlkoenig_nft`. Click a span to see duration,
attributes (`ip`, `result`), and error details.

## Cleanup

```bash
docker compose down -v
```

## Troubleshooting

**No data in Grafana?**

1. Check `sudo nft list ruleset` — the `iifname "lo" accept` rule must
   be present, otherwise OTLP traffic to localhost:4318 is dropped.
2. Check `sudo systemctl status erlkoenig_nft` — service must be active.
3. Traces need a mutating operation (reload, ban, unban). Counter metrics
   need traffic hitting the firewall.

**Service won't start?**

1. `pgrep beam` — if an old BEAM is running, kill it first.
2. Check `journalctl -u erlkoenig_nft -n 20` for errors.

**No traces after ban/reload?**

The batch exporter flushes every ~5-10 seconds. Wait and refresh.
