# Tutorial: Grafana Observability for erlkoenig_nft

> erlkoenig_nft v0.8.0

End-to-end guide: erlkoenig_nft firewall metrics and traces in Grafana.

## What You Get

- Live firewall counter rates (packets/sec, bytes/sec) per counter in Grafana
- Active connections, bans, flood/scan detection as gauges
- Traces for every ban, unban, and reload operation
- A pre-built dashboard that lights up the moment traffic flows

## Prerequisites

- A Linux machine (Ubuntu 22.04+ or Debian 12+) with root access
- Docker and Docker Compose (v2)
- Erlang/OTP 28+ and rebar3 (for building from source)

## What is erlkoenig_nft?

erlkoenig_nft is a pure Erlang nftables firewall engine. It talks
directly to the Linux kernel via AF_NETLINK — no `nft` CLI, no C
bindings, no shell commands. It manages firewall rules, tracks
connections, detects threats (floods, port scans), and auto-bans
attackers.

This tutorial adds observability: you'll see all of that in Grafana.

## Overview

```
erlkoenig_nft ──OTLP──> OTel Collector ──> Prometheus (metrics)
                                       ──> Tempo      (traces)
                                       ──> Grafana    (dashboards)
```

## Step 1: Understand the Firewall Config

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
| Grafana | 3000 | Dashboards (no login needed) |

Verify all containers are running:

```bash
docker compose ps
```

All 5 should show "Up". Then verify the collector accepts connections:

```bash
curl -s -X POST http://localhost:4318/v1/traces \
  -H "Content-Type: application/json" -d '{}'
```

Any response means it's listening.

## Step 3: Install erlkoenig_nft

There are two ways to install erlkoenig_nft:

### Option A: From a GitHub Release (recommended)

```bash
# Download and install the latest release
curl -fsSL https://github.com/iRaffnix/erlkoenig_nft/releases/download/v0.8.0/install.sh -o install.sh
sudo sh install.sh --version v0.8.0 --otel-endpoint http://localhost:4318
```

### Option B: Build from Source

```bash
git clone https://github.com/iRaffnix/erlkoenig_nft.git
cd erlkoenig_nft
rebar3 as prod tar
sudo sh install.sh --local _build/prod/rel/erlkoenig_nft \
  --otel-endpoint http://localhost:4318
```

Both options install erlkoenig_nft to `/opt/erlkoenig_nft` with a systemd
service. The `--otel-endpoint` flag configures OTLP export — you should
see `[+] OTel export: http://localhost:4318` in the output.

The installer also creates a service user (`erlkoenig`), generates an
Erlang cookie, sets up the CLI (`erlkoenig-nft`), and configures
systemd capabilities (`CAP_NET_ADMIN`).

## Step 4: Deploy the Firewall Config

Compile the tutorial's DSL config:

```bash
sudo erlkoenig-nft compile tutorials/grafana-observability/firewall.exs \
  -o /opt/erlkoenig_nft/etc/firewall.term
```

Start (or restart) the service:

```bash
sudo systemctl restart erlkoenig_nft
```

Verify the rules are applied:

```bash
sudo nft list ruleset | grep -A20 "table inet erlkoenig"
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

Verify the API socket is up:

```bash
echo '{"cmd":"status"}' | sudo nc -U -q1 /run/erlkoenig_nft/api.sock
```

## Step 5: Generate Traffic

The dashboard needs actual traffic to show data. Counter metrics only
appear in Grafana when values are > 0.

Generate some dropped traffic (anything not SSH/ICMP gets dropped):

```bash
# These connections get dropped by the firewall and counted
for i in $(seq 1 30); do timeout 1 curl -s http://localhost:80 2>/dev/null & done
```

For traces, trigger a mutating operation:

```bash
echo '{"cmd":"reload"}' | sudo nc -U -q1 /run/erlkoenig_nft/api.sock
```

Wait 15 seconds for the OTel batch exporter to flush.

## Step 6: Open Grafana

Open http://localhost:3000 (no login needed).

### Dashboard

Go to **Dashboards** -> **erlkoenig** -> **erlkoenig_nft Firewall**.

Set the time range to **Last 5 minutes** (top right). You should see:

- **Packets per Second** — lines for `ssh`, `icmp`, `dropped`
- **Bytes per Second** — same counters, byte rate
- **Active Connections** — conntrack gauge
- **Threat Detection** — active bans, floods, scans

If the graphs are flat at zero, generate more traffic (Step 5).

### Traces

Go to **Explore** -> select **Tempo** -> click **Run query**.

You should see `nft.reload` spans with:
- `service.name = erlkoenig_nft`
- `result = ok`
- Duration in milliseconds

Click a trace to see the full span details.

## Already Have Your Own Stack?

Skip the Docker setup. Just install with the endpoint pointing to your
collector:

```bash
sudo sh install.sh --version v0.8.0 \
  --otel-endpoint http://your-collector:4318
```

erlkoenig_nft pushes standard OTLP/HTTP protobuf. Any OTLP-compatible
backend works: Grafana Cloud, Datadog, Honeycomb, SigNoz, etc.

## Cleanup

```bash
cd tutorials/grafana-observability
docker compose down -v
```

The `-v` removes data volumes. Omit it to keep historical data.

## Troubleshooting

**Dashboard shows "No data"**

The panels need traffic to display. Counter values at 0 show as empty
graphs. Generate traffic with `curl http://localhost:80` or similar
(anything that hits the firewall's drop rule).

**No metrics in Prometheus**

1. Check `sudo nft list ruleset` — the `iifname "lo" accept` rule must
   be present, otherwise OTLP traffic to localhost:4318 is dropped by
   your own firewall.
2. Check `sudo systemctl status erlkoenig_nft` — service must be active.
3. Wait 15-20 seconds — the metrics SDK exports in batches.

**No traces in Tempo**

Traces only appear for mutating operations: `reload`, `ban`, `unban`,
`add_element`, `del_element`. Read-only queries like `rates()` don't
create spans. Trigger a reload and wait 10 seconds.

**Service won't start**

1. `pgrep beam` — if an old BEAM is still running, kill it:
   `sudo pkill -9 beam && sudo pkill -9 epmd`
2. Then `sudo systemctl start erlkoenig_nft`
3. Check `journalctl -u erlkoenig_nft -n 20` for errors.

**Collector container keeps restarting**

Check `docker compose logs otel-collector`. Most likely a config issue.
The collector-config.yaml in this tutorial is tested and working.
