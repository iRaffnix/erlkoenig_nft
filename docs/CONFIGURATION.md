# Configuration Reference

The firewall is defined in a single Erlang term file. Default search order:

1. `$ERLKOENIG_CONFIG_DIR/firewall.term` (default: `/etc/erlkoenig_nft`)
2. `etc/firewall.term` (development fallback)

The file contains a single Erlang map:

```erlang
#{
    table    => <<"erlkoenig">>,
    sets     => [...],
    counters => [...],
    chains   => [...],
    watch    => #{...},
    ct_guard => #{...}
}.
```

## Table

```erlang
table => <<"erlkoenig">>
```

The nf_tables table name. All chains, sets, and counters live under this table.
On termination, the entire table is deleted from the kernel.

## Sets

Named sets are kernel hash tables for O(1) IP lookup. Used for blocklists,
allowlists, and dynamic access control.

```erlang
sets => [
    {<<"blocklist">>, ipv4_addr},
    {<<"blocklist6">>, ipv6_addr},
    {<<"wg_allow">>, ipv4_addr, #{flags => [timeout], timeout => 300000}}
]
```

**Format:** `{Name, Type}` or `{Name, Type, Options}`

**Types:**

| Type | Description |
|------|-------------|
| `ipv4_addr` | IPv4 addresses (4 bytes) |
| `ipv6_addr` | IPv6 addresses (16 bytes) |
| `inet_service` | Port numbers (2 bytes) |

**Options map:**

| Key | Type | Description |
|-----|------|-------------|
| `flags` | `[atom()]` | Set flags: `timeout`, `constant`, `interval`, `map`, `eval` |
| `timeout` | `integer()` | Auto-expire elements after N milliseconds |

**Timeout sets** automatically remove elements after the configured duration.
Useful for temporary allowlists (e.g., WireGuard SPA authorization).

## Counters

Named counter objects track packet counts and byte counts in the kernel.

```erlang
counters => [ssh, http, https, banned, dropped]
```

Each atom creates a named nf_tables counter object. Reference them in rules
to count traffic per service. Counter values are polled by
`erlkoenig_nft_counter` workers for rate calculation.

## Chains

Chains attach to netfilter hooks and contain ordered rule lists.

```erlang
chains => [
    #{
        name     => <<"input">>,
        hook     => input,
        type     => filter,
        priority => 0,
        policy   => drop,
        rules    => [...]
    }
]
```

**Chain parameters:**

| Key | Type | Description |
|-----|------|-------------|
| `name` | `binary()` | Chain name (unique within table) |
| `hook` | `atom()` | Netfilter hook point |
| `type` | `atom()` | Chain type |
| `priority` | `integer()` | Evaluation order (lower = earlier) |
| `policy` | `atom()` | Default verdict if no rule matches |

**Hooks:** `prerouting`, `input`, `forward`, `output`, `postrouting`

**Types:** `filter`, `nat`, `route`

**Policies:** `accept`, `drop`

**Priority guide:**

| Priority | Typical use |
|----------|-------------|
| `-300` | Early prerouting (blocklist check before anything) |
| `-150` | Mangle/conntrack |
| `0` | Standard filter |
| `100` | Security |
| `300` | Late postrouting |

## Rules

Rules are specified as atoms or tuples in the `rules` list. They are evaluated
top-to-bottom; the first matching rule determines the verdict.

### Connection Tracking

```erlang
ct_established_accept
```

Accept packets belonging to established or related connections. Should be
the first rule in most chains — it fast-paths return traffic without
evaluating further rules.

### Loopback

```erlang
iif_accept
```

Accept all traffic on the loopback interface (`lo`). Required for local
service communication.

### Interface Match

```erlang
{iifname_accept, <<"br0">>}
```

Accept all traffic arriving on a specific interface.

### TCP Accept

```erlang
{tcp_accept, Port}
{tcp_accept, Port, CounterName}
```

Accept TCP traffic on the given port. Optionally increment a named counter.

```erlang
{tcp_accept, 80}           %% port only
{tcp_accept, 443, https}   %% port + counter
```

### TCP Accept with Rate Limit

```erlang
{tcp_accept_limited, Port, CounterName, #{rate => Rate, burst => Burst}}
```

Rate-limited TCP accept. Expands to **two** kernel rules:
1. Match port + rate exceeded -> drop (shed excess traffic)
2. Match port + counter -> accept (pass the rest)

```erlang
{tcp_accept_limited, 22, ssh, #{rate => 25, burst => 5}}
%% 25 new packets/sec, burst tolerance of 5
```

### TCP Reject

```erlang
{tcp_reject, Port}
```

Reject TCP traffic with a TCP RST response (instead of silently dropping).

### UDP Accept

```erlang
{udp_accept, Port}
{udp_accept, Port, CounterName}
```

Accept UDP traffic on the given port.

### Protocol Accept

```erlang
{protocol_accept, Protocol}
```

Accept an entire protocol.

| Protocol | Description |
|----------|-------------|
| `icmp` | ICMP (IPv4 ping, etc.) |
| `icmpv6` | ICMPv6 (IPv6 neighbor discovery, ping6) |

### Set Lookup Drop

```erlang
{set_lookup_drop, SetName}
{set_lookup_drop, SetName, CounterName}
```

Drop the packet if the source IP is found in the named set. This is how
blocklists work — one rule handles all banned IPs with O(1) hash lookup.

```erlang
{set_lookup_drop, <<"blocklist">>, banned}
```

### Set Lookup UDP Accept

```erlang
{set_lookup_udp_accept, SetName, Port}
```

Accept UDP traffic on a port only if the source IP is in the named set.
Used for conditional access (e.g., WireGuard behind SPA authorization).

```erlang
{set_lookup_udp_accept, <<"wg_allow">>, 51820}
```

### NFLOG Capture UDP

```erlang
{nflog_capture_udp, Port, Prefix, NflogGroup}
```

Capture UDP packets via NFLOG and drop them. Used for Single Packet
Authorization — the packet is logged to an NFLOG group where
`erlkoenig_nft_nflog` receives and processes it.

```erlang
{nflog_capture_udp, 61820, <<"SPA:">>, 3}
```

### Log and Drop

```erlang
{log_drop, Prefix}
```

Log the packet via kernel `printk` and drop it.

### Log, NFLOG, and Drop

```erlang
{log_drop_nflog, Prefix, NflogGroup, CounterName}
```

Log via both kernel syslog and NFLOG, increment a counter, then drop.
Typically the last rule in a drop-policy chain to count and trace all
rejected traffic.

```erlang
{log_drop_nflog, <<"ERLKOENIG: ">>, 1, dropped}
```

### Log and Reject

```erlang
{log_reject, Prefix}
```

Log the packet and reject with ICMP destination unreachable.

### Connection Limit

```erlang
{connlimit_drop, MaxConns, per_srcip}
```

Drop if the source IP has more than `MaxConns` concurrent connections.

### Source IP Accept

```erlang
{ip_saddr_accept, IP}
```

Accept traffic from a specific source IP address. Accepts tuples, strings,
or binary strings.

### Destination NAT

```erlang
{dnat, DestIP, DestPort}
```

Redirect traffic to a different destination IP and port. Use in `prerouting`
nat chains.

```erlang
{dnat, {10,0,0,5}, 8080}
```

### Masquerade

```erlang
masq
```

Dynamic source NAT (masquerade). Use in `postrouting` nat chains for
outbound traffic from private networks.

### Forward Established

```erlang
forward_established
```

Accept established/related traffic in a forward chain. Companion to
`ct_established_accept` for forwarding scenarios.

## Watch (Counter Monitoring)

Configure threshold-based alerting on counter rates.

```erlang
watch => #{
    interval => 2000,
    thresholds => [
        {AlertId, CounterName, Metric, Op, Value},
        ...
    ]
}
```

| Key | Type | Description |
|-----|------|-------------|
| `interval` | `integer()` | Counter poll interval in milliseconds |
| `thresholds` | `[tuple()]` | List of threshold definitions |

**Threshold format:** `{AlertId, CounterName, Metric, Op, Value}`

| Field | Type | Description |
|-------|------|-------------|
| `AlertId` | `atom()` | Unique identifier for this alert |
| `CounterName` | `atom()` | Which counter to monitor |
| `Metric` | `pps \| bps` | Packets per second or bytes per second |
| `Op` | `'>' \| '<' \| '>=' \| '<=' \| '=='` | Comparison operator |
| `Value` | `float()` | Threshold value |

**Examples:**

```erlang
thresholds => [
    {ssh_flood,    ssh,     pps, '>', 50.0},    %% SSH brute force?
    {http_flood,   http,    pps, '>', 1000.0},  %% HTTP DDoS?
    {ddos_alert,   dropped, pps, '>', 200.0},   %% mass scanning?
    {ban_activity, banned,  pps, '>', 0.0}      %% any banned traffic?
]
```

Events are broadcast via `pg` process groups. Subscribe to
`counter_events` in the `erlkoenig_nft` group to receive
`{counter_event, Name, #{pps, bps, packets, bytes, ...}}` messages.

## ct_guard (Threat Detection)

Automatic threat detection and temporary IP banning based on connection
patterns from conntrack events.

```erlang
ct_guard => #{
    conn_flood       => {MaxConns, WindowSecs},
    port_scan        => {MaxPorts, WindowSecs},
    ban_duration     => Seconds,
    whitelist        => [IP, ...],
    cleanup_interval => Milliseconds
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `conn_flood` | `{integer(), integer()}` | `{50, 10}` | Ban after N connections in T seconds |
| `port_scan` | `{integer(), integer()}` | `{20, 60}` | Ban after N distinct ports in T seconds |
| `ban_duration` | `integer()` | `3600` | Temporary ban duration in seconds |
| `whitelist` | `[tuple()]` | `[{127,0,0,1}]` | IPs that are never banned |
| `cleanup_interval` | `integer()` | `30000` | Expired entry cleanup interval (ms) |

**How it works:**

1. `erlkoenig_nft_ct` monitors kernel conntrack events via netlink multicast
2. `erlkoenig_nft_ct_guard` maintains sliding windows per source IP in ETS
3. When a threshold is exceeded, the source IP is added to the kernel blocklist set
4. A timer automatically removes the ban after `ban_duration` seconds

Whitelisted IPs are never banned regardless of behavior.

## wg_auth (WireGuard SPA)

Single Packet Authorization for WireGuard access control.

```erlang
wg_auth => #{
    secret           => <<"64_hex_chars">>,
    spa_port         => 61820,
    wg_port          => 51820,
    nflog_group      => 3,
    timeout          => 300,
    timestamp_window => 30,
    require_totp     => false
}
```

| Key | Type | Description |
|-----|------|-------------|
| `secret` | `binary()` | 32-byte hex-encoded shared secret |
| `spa_port` | `integer()` | UDP port for SPA knock packets |
| `wg_port` | `integer()` | WireGuard listen port to authorize |
| `nflog_group` | `integer()` | NFLOG group for packet capture |
| `timeout` | `integer()` | Authorization duration in seconds |
| `timestamp_window` | `integer()` | Acceptable clock skew in seconds |
| `require_totp` | `boolean()` | Require TOTP in addition to HMAC |

SPA packets are captured via NFLOG, validated by `erlkoenig_nft_nflog`,
and on success the source IP is added to the `wg_allow` timeout set.
The set entry auto-expires after `timeout` seconds.

## Complete Example

```erlang
#{
    table => <<"production">>,
    sets => [
        {<<"blocklist">>, ipv4_addr},
        {<<"blocklist6">>, ipv6_addr},
        {<<"wg_allow">>, ipv4_addr, #{flags => [timeout], timeout => 300000}}
    ],
    counters => [ssh, http, https, wg, banned, dropped],
    chains => [
        %% Early blocklist check
        #{name => <<"prerouting_ban">>, hook => prerouting, type => filter,
          priority => -300, policy => accept,
          rules => [
              {set_lookup_drop, <<"blocklist">>, banned},
              {set_lookup_drop, <<"blocklist6">>, banned}
          ]},
        %% Main input filter
        #{name => <<"input">>, hook => input, type => filter,
          priority => 0, policy => drop,
          rules => [
              ct_established_accept,
              iif_accept,
              {nflog_capture_udp, 61820, <<"SPA:">>, 3},
              {set_lookup_udp_accept, <<"wg_allow">>, 51820},
              {tcp_accept_limited, 22, ssh, #{rate => 25, burst => 5}},
              {tcp_accept, 80, http},
              {tcp_accept, 443, https},
              {protocol_accept, icmp},
              {protocol_accept, icmpv6},
              {log_drop_nflog, <<"DROP: ">>, 1, dropped}
          ]}
    ],
    watch => #{
        interval => 2000,
        thresholds => [
            {ssh_flood,    ssh,     pps, '>', 50.0},
            {http_flood,   http,    pps, '>', 500.0},
            {ddos_alert,   dropped, pps, '>', 100.0},
            {ban_activity, banned,  pps, '>', 0.0}
        ]
    },
    ct_guard => #{
        conn_flood => {50, 10},
        port_scan  => {20, 60},
        ban_duration => 3600,
        whitelist => [{127, 0, 0, 1}],
        cleanup_interval => 30000
    }
}.
```
