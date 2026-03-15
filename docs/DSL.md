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
  # sets, counters, quotas, flowtables, chains
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
| `type` | `:ipv4_addr \| :ipv6_addr \| :inet_service` | Element type |
| `timeout` | `integer()` | Auto-expire elements (ms) |

### `concat_set`

Concatenated sets allow composite keys for O(1) multi-field matching.

```elixir
concat_set "allowpairs", [:ipv4_addr, :inet_service]
concat_set "allowpairs", [:ipv4_addr, :inet_service], timeout: 60_000
```

| Param | Type | Description |
|-------|------|-------------|
| `name` | `String.t()` | Set name |
| `fields` | `[atom()]` | List of field types (e.g., `[:ipv4_addr, :inet_service]`) |
| `timeout` | `integer()` | Auto-expire elements (ms) |

### `vmap`

Verdict maps dispatch packets to different chains based on a key (e.g., port number).

```elixir
vmap "port_dispatch", :inet_service, id: 10
```

| Param | Type | Description |
|-------|------|-------------|
| `name` | `String.t()` | Map name |
| `type` | atom | Key type (e.g., `:inet_service` for ports) |
| `id` | `integer()` | Set ID for batch referencing |

### `counters`

```elixir
counters [:ssh, :http, :dropped]
```

List of named counter atoms. Each creates a kernel counter object.

### `quota`

Named quota objects track byte usage in the kernel.

```elixir
quota :bandwidth, 10_000_000_000, flags: 0    # 10 GB soft quota
```

| Param | Type | Description |
|-------|------|-------------|
| `name` | atom | Quota name |
| `bytes` | `integer()` | Byte limit |
| `flags` | `integer()` | 0 = soft (count only), 1 = hard (enforce) |

### `flowtable`

Hardware flow offloading tables for accelerating established connections.

```elixir
flowtable "fastpath", hook: :ingress, priority: -100, devices: ["eth0"]
```

| Option | Type | Description |
|--------|------|-------------|
| `hook` | atom | `:ingress` |
| `priority` | integer | Evaluation priority |
| `devices` | `[String.t()]` | Network interfaces to offload |

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

## Zones

Zones group interfaces and define inter-zone policies. At compile time,
zone macros expand into standard chains (`z_dispatch_input`, `z_input_<zone>`,
`z_dispatch_forward`, `z_fwd_<from>_<to>`, `z_nat_postrouting`) — the
Erlang runtime sees only normal chains and rules.

### Zone Definitions

```elixir
zone "wan", interfaces: ["eth0"]
zone "lan", interfaces: ["eth1", "br0"]
zone "vpn", interfaces: ["wg0"]
```

Each interface may only belong to one zone.

### Zone Input (traffic to this host)

```elixir
zone_input "wan", policy: :drop do
  accept :established
  accept :icmp
  accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
  log_and_drop "WAN-DROP: ", counter: :dropped
end

zone_input "lan", policy: :accept do
  accept :established
end
```

With `policy: :accept`, an implicit `accept` is appended. With `:drop`, the
chain ends after your rules (unmatched packets return to the dispatch chain
which has policy drop).

### Zone Forward (traffic between zones)

```elixir
zone_forward "lan", to: "wan", policy: :accept do
  accept :established
  accept :all
end

zone_forward "wan", to: "lan", policy: :drop do
  accept :established
end
```

For multi-interface zones, all interface combinations generate
`iifname`+`oifname` jump rules automatically.

### Zone Masquerade (NAT between zones)

```elixir
zone_masquerade "lan", to: "wan"
```

Generates a `z_nat_postrouting` chain (type nat, hook postrouting,
priority 100) with per-interface-pair masquerade rules.

### Coexistence with Manual Chains

Zone chains and manual `chain` blocks coexist — zone chains get a `z_` prefix
to avoid collisions. Zone chains are placed before manual chains in the output.

### Interface Macros

These macros can be used inside manual chains for direct interface matching:

```elixir
accept_on_interface "wg0"       # accept if iifname matches
accept_output_interface "eth0"  # accept if oifname matches
masquerade()                    # masquerade (dynamic SNAT)
masquerade_not_via "wg0"        # masquerade if oifname != name
accept_forward_established()    # accept established/related in forward
```

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
accept_udp_if_in_set "wg_allow", 51820 # only if source IP in set
```

### Set Operations

```elixir
drop_if_in_set "blocklist"                      # drop if source IP in set
drop_if_in_set "blocklist", counter: :banned    # with counter
```

### Concatenated Set Operations

Match composite keys (e.g., IP + port) in a single O(1) lookup.

```elixir
accept_if_in_concat_set "allowpairs", [:ipv4_addr, :inet_service]
drop_if_in_concat_set "denylist", [:ipv4_addr, :inet_service]
```

### Verdict Map Dispatch

Dispatch packets to per-service chains based on a key field.

```elixir
dispatch :tcp, "port_dispatch"     # TCP dport -> chain via vmap
```

### Source IP Filtering

```elixir
accept_from "10.0.0.0/24"    # accept from source IP/subnet
accept_from {10, 0, 1, 10}   # accept from specific IP
drop_from "192.168.1.100"    # drop from source IP
```

### Connection Limits

```elixir
connlimit_drop 10             # max 10 concurrent connections per source
connlimit_drop 10, 5          # with offset
```

### Conntrack Marks

Set and match connection tracking marks for cross-chain state.

```elixir
mark_connection 42             # set ct mark on matching packets
match_mark 42, verdict: :accept  # match packets with ct mark
```

### FIB Reverse Path Filter

Kernel FIB lookup to detect spoofed source addresses. Drops packets
whose source address has no valid return path through the incoming
interface.

```elixir
rpf_check                      # FIB saddr + iif -> drop if no route
```

### SYN Proxy

Kernel-level SYN cookie protection. The kernel handles the TCP handshake
and only forwards completed connections, protecting backend services
from SYN floods.

```elixir
synproxy [80, 443], mss: 1460, wscale: 7
```

| Option | Type | Description |
|--------|------|-------------|
| `mss` | integer | Maximum segment size |
| `wscale` | integer | Window scale factor |

### Notrack

Bypass connection tracking for high-throughput stateless services (e.g., DNS).

```elixir
notrack 53, :udp               # skip conntrack for UDP port 53
notrack 53, :tcp               # skip conntrack for TCP port 53
```

### Rate Metering

Per-source-IP rate limiting using kernel meters (dynamic sets with
attached limit expressions). More granular than global `limit` — each
source IP gets its own rate counter.

```elixir
meter_limit "ssh_meter", 22, :tcp, rate: 10, burst: 3, unit: :minute
```

| Param | Type | Description |
|-------|------|-------------|
| `name` | `String.t()` | Meter set name |
| `port` | integer | Destination port |
| `proto` | `:tcp \| :udp` | Protocol |
| `rate` | integer | Max packets per unit |
| `burst` | integer | Burst tolerance |
| `unit` | atom | `:second`, `:minute`, `:hour`, `:day` |

### NFQUEUE

Send matching packets to a userspace queue for inspection (e.g., IDS/IPS).

```elixir
queue_to 443, :tcp, queue: 0, fanout: true
```

| Option | Type | Description |
|--------|------|-------------|
| `queue` | integer | Queue number |
| `fanout` | boolean | Distribute across CPU cores |

### OS Fingerprinting

Match packets by the operating system detected via TCP SYN fingerprint
(uses the kernel `nft_osf` module).

```elixir
match_os "Linux", :accept
match_os "Windows", :drop
```

### Cgroup Matching

Filter traffic by cgroup ID — useful for container and systemd service
isolation.

```elixir
match_cgroup 1234, :accept     # accept from cgroup ID 1234
match_cgroup 5678, :drop       # drop from cgroup ID 5678
```

### Flow Offloading

Offload established connections to a flowtable for hardware-accelerated
forwarding (requires a `flowtable` definition in the firewall block).

```elixir
offload "fastpath"             # offload to named flowtable
```

### Logging

```elixir
log_and_drop "PREFIX: "                                 # syslog + drop
log_and_drop "PREFIX: ", counter: :dropped              # syslog + counter + drop
log_and_reject "PREFIX: "                               # syslog + ICMP unreachable
log_and_drop_nflog "PREFIX: ", group: 1, counter: :dropped  # NFLOG + counter + drop
```

`log_and_drop_nflog` sends to an NFLOG group where `erlkoenig_nft_nflog`
can process packets in Erlang — no syslog, no file I/O.

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
