# API Reference

All public functions are in the `erlkoenig_nft` module. It delegates to
supervised gen_servers — all calls are safe to make from any process.

## Firewall Management

### status/0

```erlang
erlkoenig_nft:status() -> map().
```

Returns current firewall status including applied config, table name,
chain count, and rule count.

### reload/0

```erlang
erlkoenig_nft:reload() -> ok | {error, term()}.
```

Re-reads the config file and re-applies all rules as an atomic netlink
batch. No connections are dropped during reload — the kernel switches
rulesets atomically.

## IP Banning

### ban/1

```erlang
erlkoenig_nft:ban(IP) -> ok | {error, term()}.
```

Add an IP to the kernel blocklist set. Takes effect immediately with O(1)
lookup performance. Accepts:

- Strings: `"10.0.0.5"`, `"2001:db8::1"`
- Binaries: `<<"10.0.0.5">>`, `<<"2001:db8::1">>`
- Tuples: `{10,0,0,5}`, `{0,0,0,0,0,0,0,1}`
- Raw binaries: `<<10,0,0,5>>` (4 bytes IPv4), `<<...>>` (16 bytes IPv6)

Automatically selects the correct set (`blocklist` for IPv4, `blocklist6`
for IPv6) based on the address format.

```erlang
erlkoenig_nft:ban("203.0.113.42").
erlkoenig_nft:ban({10,0,0,5}).
erlkoenig_nft:ban(<<"2001:db8::1">>).
```

### unban/1

```erlang
erlkoenig_nft:unban(IP) -> ok | {error, term()}.
```

Remove an IP from the kernel blocklist set. Same input formats as `ban/1`.

```erlang
erlkoenig_nft:unban("203.0.113.42").
```

## Counter Monitoring

### rates/0

```erlang
erlkoenig_nft:rates() -> #{atom() => #{pps => float(), bps => float()}}.
```

Returns current packet and byte rates for all named counters. Rates are
calculated from the last poll interval.

```erlang
erlkoenig_nft:rates().
%% => #{ssh => #{pps => 12.5, bps => 8340.0},
%%       http => #{pps => 245.0, bps => 198400.0},
%%       dropped => #{pps => 0.5, bps => 320.0}}
```

## Connection Tracking

### ct_count/0

```erlang
erlkoenig_nft:ct_count() -> non_neg_integer().
```

Total number of tracked connections.

### ct_count/1

```erlang
erlkoenig_nft:ct_count(IP) -> non_neg_integer().
```

Number of active connections from a specific source IP.

### ct_top/1

```erlang
erlkoenig_nft:ct_top(N) -> [{IP, Count}].
```

Top N source IPs by active connection count.

```erlang
erlkoenig_nft:ct_top(5).
%% => [{{203,0,113,42}, 47}, {{198,51,100,1}, 23}, ...]
```

### ct_connections/0

```erlang
erlkoenig_nft:ct_connections() -> [map()].
```

Full list of tracked connections (only available in `full` tracking mode).
Each connection is a map with `proto`, `src`, `dst`, `sport`, `dport`.

### ct_mode/0

```erlang
erlkoenig_nft:ct_mode() -> full | aggregate.
```

Current tracking mode. `full` tracks individual connections. `aggregate`
tracks per-source-IP counts (activated automatically under DDoS load to
reduce memory 10x).

### ct_stats/0

```erlang
erlkoenig_nft:ct_stats() -> map().
```

Operational statistics for the conntrack monitor.

## Threat Detection (ct_guard)

### guard_stats/0

```erlang
erlkoenig_nft:guard_stats() -> map().
```

Detection statistics.

```erlang
erlkoenig_nft:guard_stats().
%% => #{floods_detected => 3, scans_detected => 1, active_bans => 2}
```

### guard_banned/0

```erlang
erlkoenig_nft:guard_banned() -> [map()].
```

List of currently banned IPs with reason and remaining duration.

```erlang
erlkoenig_nft:guard_banned().
%% => [#{ip => "203.0.113.42", reason => conn_flood, expires_in => 2847}]
```

## Rule Testing (nft_vm)

The kernel emulator runs rules in pure userspace. No CAP_NET_ADMIN needed.

### Building Packets

```erlang
nft_vm_pkt:tcp(Opts) -> packet().
nft_vm_pkt:udp(Opts) -> packet().
```

Build synthetic packets for testing. Options:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `saddr` | IP | `{192,168,1,100}` | Source IP |
| `daddr` | IP | `{10,0,0,1}` | Destination IP |
| `sport` | integer | `12345` | Source port |
| `dport` | integer | `80` | Destination port |

```erlang
Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,5}, dport => 22}).
Pkt = nft_vm_pkt:udp(#{saddr => "203.0.113.42", sport => 12345}).
```

#### Connection Tracking State

```erlang
nft_vm_pkt:with_ct_state(Pkt, State) -> packet().
```

Attach conntrack state to a packet: `new`, `established`, `related`.

```erlang
Pkt2 = nft_vm_pkt:with_ct_state(Pkt, established).
```

### Evaluating Rules

```erlang
nft_vm:eval(Exprs, Pkt) -> {Verdict, Trace}.
nft_vm:eval(Exprs, Pkt, DefaultPolicy) -> {Verdict, Trace}.
```

Evaluate a single rule (list of expressions) against a packet.

```erlang
Rules = nft_rules:tcp_accept(22, ssh),
Pkt = nft_vm_pkt:tcp(#{dport => 22}),
{accept, _Trace} = nft_vm:eval(Rules, Pkt, drop).
```

### Evaluating Chains

```erlang
nft_vm:eval_chain(RuleList, Pkt) -> {Verdict, Trace}.
nft_vm:eval_chain(RuleList, Pkt, DefaultPolicy) -> {Verdict, Trace}.
```

Evaluate multiple rules in chain order. Mirrors kernel `nft_do_chain()`:
try each rule in order; first terminal verdict wins; if no rule matches,
apply the default policy.

```erlang
Chain = [
    nft_rules:ct_established_accept(),
    nft_rules:tcp_accept(22, ssh),
    nft_rules:tcp_accept(80, http)
],
Pkt = nft_vm_pkt:tcp(#{dport => 443}),
{drop, _} = nft_vm:eval_chain(Chain, Pkt, drop).
```

### Trace Output

```erlang
nft_vm:print_trace(Trace) -> ok.
```

Print a human-readable trace showing every expression step, register
state transitions, and the final verdict. Useful for debugging why a
packet was accepted or dropped.

## Event Subscription

Counter events and conntrack events are broadcast via OTP `pg` process
groups under the `erlkoenig_nft` scope.

### Counter Events

```erlang
pg:join(erlkoenig_nft, counter_events, self()).

receive
    {counter_event, Name, #{pps := PPS, bps := BPS}} ->
        io:format("~p: ~.1f pps, ~.1f bps~n", [Name, PPS, BPS])
end.
```

### Conntrack Events

```erlang
pg:join(erlkoenig_nft, ct_events, self()).

receive
    {ct_new, #{proto := Proto, src := Src, dport := DPort}} ->
        io:format("New ~p connection from ~p to port ~p~n", [Proto, Src, DPort]);
    {ct_destroy, ConnInfo} ->
        io:format("Connection closed: ~p~n", [ConnInfo])
end.
```

## Rule Builders (nft_rules)

`nft_rules` provides functions that return expression IR lists. These can
be passed to `nft_vm` for testing or to `nft_encode` for kernel deployment.

| Function | Returns |
|----------|---------|
| `ct_established_accept()` | Accept established+related |
| `iif_accept()` | Accept on loopback |
| `tcp_accept(Port)` | TCP accept |
| `tcp_accept(Port, Counter)` | TCP accept with counter |
| `tcp_accept_limited(Port, Counter, Opts)` | Rate-limited TCP (2 rules) |
| `udp_accept(Port)` | UDP accept |
| `set_lookup_drop(Set)` | Drop if source IP in set |
| `set_lookup_drop(Set, Counter)` | Drop if in set, with counter |
| `set_lookup_udp_accept(Set, Port)` | Conditional UDP accept |
| `log_drop(Prefix)` | Log + drop |
| `log_drop_nflog(Prefix, Group, Counter)` | NFLOG + log + counter + drop |
| `masq_rule()` | Masquerade (dynamic SNAT) |
| `dnat_rule(IP, Port)` | Destination NAT |
| `ban_ip(Family, Table, IP)` | Add IP to blocklist (netlink msg) |
| `unban_ip(Family, Table, IP)` | Remove IP from blocklist |
