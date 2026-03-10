# Elixir DSL Reference

The Elixir DSL (`dsl/`) provides a compile-time macro layer that produces
Erlang term maps compatible with `erlkoenig_nft`. No Elixir runtime is
needed — the DSL outputs `.term` files that the Erlang application loads.

Located in `dsl/`, built with Mix (Elixir >= 1.18, zero dependencies).

```bash
cd dsl && mix test
```

## Firewall DSL

### Basic Usage

```elixir
defmodule MyFirewall do
  use ErlkoenigNft.Firewall

  firewall "production" do
    counters [:ssh, :http, :https, :banned, :dropped]

    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr
    set "wg_allow", :ipv4_addr, timeout: 300_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept :icmp
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp [80, 443]
      drop_if_in_set "blocklist", counter: :dropped
      log_and_drop "BLOCKED: ", counter: :dropped
    end
  end
end
```

### Generated Functions

| Function | Returns |
|----------|---------|
| `MyFirewall.config()` | Erlang term map (ready for `erlkoenig_nft`) |
| `MyFirewall.write!(path)` | Writes the `.term` file to disk |

### `firewall` Block

```elixir
firewall name :: String.t() do
  # sets, counters, chains
end
```

Top-level block. `name` is used as the table name.

### `set`

```elixir
set name, type
set name, type, timeout: milliseconds
```

| Param | Type | Description |
|-------|------|-------------|
| `name` | `String.t()` | Set name |
| `type` | `:ipv4_addr \| :ipv6_addr` | Element type |
| `timeout` | `integer()` | Auto-expire elements (ms) |

### `counters`

```elixir
counters [:ssh, :http, :dropped]
```

List of named counter atoms. Each creates a kernel counter object.

### `chain`

```elixir
chain name, hook: hook, policy: policy do
  # rules
end

chain name, hook: hook, type: type, priority: priority, policy: policy do
  # rules
end
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `hook` | atom | required | `:input`, `:output`, `:forward`, `:prerouting`, `:postrouting` |
| `policy` | atom | required | `:accept` or `:drop` |
| `type` | atom | `:filter` | `:filter`, `:nat`, `:route` |
| `priority` | integer | `0` | Lower = evaluated earlier |

## Rule Macros

### Connection Tracking

```elixir
accept :established    # conntrack established + related
```

### Interface

```elixir
accept :loopback       # accept on lo
```

### Protocol

```elixir
accept :icmp           # ICMP (IPv4)
accept_protocol :icmpv6  # explicit protocol
```

### TCP Rules

```elixir
accept_tcp 22                                      # basic port accept
accept_tcp 443, counter: :https                    # with counter
accept_tcp 22, counter: :ssh, limit: {25, burst: 5}  # rate-limited
accept_tcp [80, 443]                               # multiple ports
accept_tcp_range 8000, 8999                        # port range
reject_tcp 23                                      # TCP RST response
```

Rate-limited rules expand to two kernel rules (drop excess + accept rest).

### UDP Rules

```elixir
accept_udp 53                          # basic
accept_udp 51820, counter: :wg         # with counter
accept_udp_range 27000, 27015          # port range
```

### Set Operations

```elixir
drop_if_in_set "blocklist"                      # drop if source IP in set
drop_if_in_set "blocklist", counter: :banned    # with counter
```

### Source IP Filtering

```elixir
accept_from "10.0.0.0/24"    # accept from source IP/subnet
drop_from "192.168.1.100"    # drop from source IP
```

### Connection Limits

```elixir
connlimit_drop 10             # max 10 concurrent connections per source
connlimit_drop 10, 5          # with offset
```

### Logging

```elixir
log_and_drop "PREFIX: "                       # syslog + drop
log_and_drop "PREFIX: ", counter: :dropped    # syslog + counter + drop
log_and_reject "PREFIX: "                     # syslog + ICMP unreachable
```

### Accept All

```elixir
accept :all                    # unconditional accept
```

## Guard DSL

Threat detection configuration.

```elixir
defmodule MyGuard do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {10, 0, 0, 1}
    whitelist {192, 168, 1, 1}
    cleanup_interval 60_000
  end
end

MyGuard.guard_config()
# => %{conn_flood: {50, 10}, port_scan: {20, 60},
#      ban_duration: 3600, whitelist: [...], cleanup_interval: 60000}
```

### `detect`

```elixir
detect :conn_flood, threshold: max_conns, window: seconds
detect :port_scan, threshold: max_ports, window: seconds
```

| Detector | Triggers when |
|----------|---------------|
| `:conn_flood` | >threshold connections from one source in window |
| `:port_scan` | >threshold distinct destination ports from one source in window |

### `ban_duration`

```elixir
ban_duration seconds    # default: 3600 (1 hour)
```

How long banned IPs stay in the kernel blocklist.

### `whitelist`

```elixir
whitelist {127, 0, 0, 1}    # never ban localhost (included by default)
whitelist {10, 0, 0, 1}     # never ban admin IP
```

### `cleanup_interval`

```elixir
cleanup_interval 30_000    # ms between expired entry cleanup (default: 30s)
```

## Watch DSL

Counter-based monitoring with threshold alerts.

```elixir
defmodule MyMonitoring do
  use ErlkoenigNft.Watch

  watch :traffic do
    counter :ssh_pkts, :pps, threshold: 100
    counter :http_pkts, :pps, threshold: 5000
    counter :dropped, :packets, threshold: 1000
    interval 3000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/erlkoenig"}
  end
end

MyMonitoring.watches()    # => list of watch term maps
```

### `watch` Block

```elixir
watch name :: atom() do
  # counters, thresholds, actions
end
```

### `counter`

```elixir
counter name, metric, threshold: value
```

| Param | Values | Description |
|-------|--------|-------------|
| `name` | atom | Counter name |
| `metric` | `:pps`, `:bps`, `:packets`, `:bytes` | What to measure |
| `threshold` | number | Alert when exceeded |

### `interval`

```elixir
interval 2000    # poll every 2 seconds (default)
```

### `on_alert`

```elixir
on_alert :log                                        # logger.warning
on_alert {:webhook, "https://..."}                   # HTTP POST
on_alert {:exec, "/usr/local/bin/alert.sh"}          # execute command
on_alert :isolate                                    # isolate action
```

## Profiles

Built-in profiles for quick setup.

```elixir
ErlkoenigNft.Firewall.Profiles.get(:strict)
ErlkoenigNft.Firewall.Profiles.get(:strict, allow_tcp: [22, 443])
ErlkoenigNft.Firewall.Profiles.get(:standard, allow_udp: [51820])
ErlkoenigNft.Firewall.Profiles.get(:open)
ErlkoenigNft.Firewall.Profiles.list()    # => [:strict, :standard, :open]
```

| Profile | Description |
|---------|-------------|
| `:strict` | Established + ICMP only. All else dropped. |
| `:standard` | Established + ICMP + DNS. Outbound allowed. |
| `:open` | Everything accepted (monitoring only). |

All profiles accept `allow_tcp: [ports]` and `allow_udp: [ports]` options
to open additional ports.
