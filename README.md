# erlkoenig_nft

A firewall engine written in pure Erlang that talks directly to the Linux
kernel via `AF_NETLINK`. No C code. No NIFs. No `os:cmd("nft ...")`.
Zero external dependencies.

> **Early stage software.** erlkoenig_nft is under active development and has
> not been battle-tested in production yet. The userspace VM tests cover rule
> logic extensively (239 tests), but real-world kernel interaction has seen
> limited testing. Review your config carefully before deploying, and don't
> use this as your only line of defense on critical systems — yet.
>
> Since erlkoenig_nft uses standard nf_tables under the hood, you can always
> verify what's actually loaded in the kernel with `nft list ruleset`. This
> makes it easy to check that the rules, sets, and counters look correct
> before trusting them with real traffic.

```erlang
erlkoenig_nft:ban("203.0.113.42").
%% Blocked in microseconds — kernel hash set, O(1) lookup.
%% Automatic expiry. No rule changes. No restarts.
```

## Why

Every firewall tool shells out to `nft` or `iptables`. Every ban is a
subprocess. Every rule change is a string that might fail to parse.

erlkoenig_nft speaks the kernel's binary protocol directly. One Erlang
function call becomes one netlink message. Rules are data structures,
not strings. The compiler catches your typos, not the kernel.

```erlang
%% This is your entire firewall at runtime
erlkoenig_nft:status().
erlkoenig_nft:rates().
erlkoenig_nft:ct_top(10).
erlkoenig_nft:guard_stats().
erlkoenig_nft:reload().
```

## Quick Start

```bash
make                  # build Erlang core + Elixir DSL
make erl              # or just the Erlang core

# pick a config
cp priv/examples/01_hardened_webserver.term priv/firewall.term

rebar3 shell          # needs CAP_NET_ADMIN
```

## Elixir DSL

The optional DSL (`dsl/`) compiles to the same `.term` format the Erlang
runtime loads. Write firewall configs that read like firewall configs.

### Hardened Web Server

```elixir
defmodule Firewall.Web do
  use ErlkoenigNft.Firewall

  firewall "webserver" do
    counters [:ssh, :http, :https, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "WEB-DROP: ", counter: :dropped
    end
  end
end
```

### Mail Server with TLS Enforcement

```elixir
defmodule Firewall.Mail do
  use ErlkoenigNft.Firewall

  firewall "mailserver" do
    counters [:smtp, :submission, :imaps, :pop3s, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept_tcp 25, counter: :smtp, limit: {50, burst: 10}
      accept_tcp 587, counter: :submission, limit: {100, burst: 20}
      accept_tcp 993, counter: :imaps
      accept_tcp 995, counter: :pop3s
      reject_tcp 143                    # plaintext IMAP -> RST (use TLS!)
      reject_tcp 110                    # plaintext POP3 -> RST (use TLS!)
      accept :icmp
      log_and_drop "MAIL-DROP: ", counter: :dropped
    end
  end
end
```

### Database Server (Private Subnet Only)

```elixir
defmodule Firewall.Database do
  use ErlkoenigNft.Firewall

  firewall "dbserver" do
    counters [:ssh, :postgres, :dropped]

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept_from {10, 0, 1, 10}       # app-server-1
      accept_from {10, 0, 1, 11}       # app-server-2
      accept_from {10, 0, 1, 12}       # app-server-3
      connlimit_drop 100               # max 100 concurrent conns per source
      accept_tcp 5432, counter: :postgres
      log_and_drop "DB-DROP: ", counter: :dropped
    end
  end
end
```

### Game Server with Port Ranges

```elixir
defmodule Firewall.Game do
  use ErlkoenigNft.Firewall

  firewall "gameserver" do
    counters [:game, :voice, :dropped]

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, limit: {10, burst: 3}
      accept_udp_range 27015, 27030     # game traffic
      accept_udp 9987, counter: :voice  # voice chat
      accept_tcp_range 8080, 8089       # web admin panel
      accept :icmp
      log_and_drop "GAME-DROP: ", counter: :dropped
    end
  end
end
```

### Dev Server (Relaxed, Reject Instead of Drop)

```elixir
defmodule Firewall.Dev do
  use ErlkoenigNft.Firewall

  firewall "devserver" do
    counters [:ssh, :http, :phoenix, :epmd, :postgres]

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp [80, 443]              # HTTP/HTTPS
      accept_tcp [4000, 4001]           # Phoenix + LiveReload
      accept_tcp 4369, counter: :epmd   # Erlang EPMD
      accept_tcp_range 9100, 9155       # Erlang distribution
      accept_tcp 5432, counter: :postgres
      accept_tcp 3000                   # Grafana
      accept :icmp
      log_and_reject "DEV-REJECT: "     # ICMP unreachable, not silent drop
    end
  end
end
```

### Reverse Proxy with Connection Limits

```elixir
defmodule Firewall.Proxy do
  use ErlkoenigNft.Firewall

  firewall "proxy" do
    counters [:http_fwd, :https_fwd, :dropped]

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, limit: {10, burst: 3}
      connlimit_drop 200               # DDoS protection per source
      accept_tcp 80, counter: :http_fwd
      accept_tcp 443, counter: :https_fwd
      accept :icmp
      log_and_drop "PROXY-DROP: ", counter: :dropped
    end

    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      accept_from {10, 0, 1, 100}      # backend server
      log_and_drop "PROXY-FWD-DROP: "
    end
  end
end
```

### Threat Detection

```elixir
defmodule MyGuard do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10    # 50 conns in 10s -> ban
    detect :port_scan, threshold: 20, window: 60     # 20 ports in 60s -> ban
    ban_duration 3600                                 # 1 hour
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 0, 1}                          # admin workstation
    cleanup_interval 15_000
  end
end
```

### Counter Monitoring with Alerts

```elixir
defmodule MyMonitoring do
  use ErlkoenigNft.Watch

  watch :traffic do
    counter :ssh, :pps, threshold: 50                # brute force?
    counter :http, :pps, threshold: 5000             # DDoS?
    counter :dropped, :pps, threshold: 200           # mass scanning?
    interval 2000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/fw"}
  end
end
```

### Quick Profiles

```elixir
# One-liners for common setups
ErlkoenigNft.Firewall.Profiles.get(:strict, allow_tcp: [22, 443])
ErlkoenigNft.Firewall.Profiles.get(:standard, allow_udp: [51820])
ErlkoenigNft.Firewall.Profiles.get(:open)
```

## Examples

All 10 scenarios ship with both Erlang term configs and Elixir DSL versions:

| # | Scenario | Erlang | Elixir |
|---|----------|--------|--------|
| 1 | Hardened web server | [`priv/examples/01_hardened_webserver.term`](priv/examples/01_hardened_webserver.term) | [`examples/01_hardened_webserver.exs`](examples/01_hardened_webserver.exs) |
| 2 | Paranoid bastion (WireGuard SPA) | [`priv/examples/02_paranoid_bastion.term`](priv/examples/02_paranoid_bastion.term) | [`examples/02_paranoid_bastion.exs`](examples/02_paranoid_bastion.exs) |
| 3 | Mail server (TLS enforcement) | [`priv/examples/03_mail_server.term`](priv/examples/03_mail_server.term) | [`examples/03_mail_server.exs`](examples/03_mail_server.exs) |
| 4 | Database server (private subnet) | [`priv/examples/04_database_server.term`](priv/examples/04_database_server.term) | [`examples/04_database_server.exs`](examples/04_database_server.exs) |
| 5 | VPN gateway (NAT + forwarding) | [`priv/examples/05_vpn_gateway.term`](priv/examples/05_vpn_gateway.term) | [`examples/05_vpn_gateway.exs`](examples/05_vpn_gateway.exs) |
| 6 | DNS server (rate-limited) | [`priv/examples/06_dns_server.term`](priv/examples/06_dns_server.term) | [`examples/06_dns_server.exs`](examples/06_dns_server.exs) |
| 7 | Game server (UDP port ranges) | [`priv/examples/07_game_server.term`](priv/examples/07_game_server.term) | [`examples/07_game_server.exs`](examples/07_game_server.exs) |
| 8 | Reverse proxy (DNAT + connlimit) | [`priv/examples/08_reverse_proxy.term`](priv/examples/08_reverse_proxy.term) | [`examples/08_reverse_proxy.exs`](examples/08_reverse_proxy.exs) |
| 9 | Docker host (bridge + containers) | [`priv/examples/09_docker_host.term`](priv/examples/09_docker_host.term) | [`examples/09_docker_host.exs`](examples/09_docker_host.exs) |
| 10 | Dev server (relaxed, reject) | [`priv/examples/10_dev_server.term`](priv/examples/10_dev_server.term) | [`examples/10_dev_server.exs`](examples/10_dev_server.exs) |

## Erlang Term Config

The DSL compiles to the same format you can write by hand:

```erlang
#{
    table => <<"erlkoenig">>,
    sets => [
        {<<"blocklist">>, ipv4_addr},
        {<<"blocklist6">>, ipv6_addr}
    ],
    counters => [ssh, http, https, banned, dropped],
    chains => [
        #{name => <<"input">>, hook => input, type => filter,
          priority => 0, policy => drop,
          rules => [
              ct_established_accept,
              iif_accept,
              {tcp_accept_limited, 22, ssh, #{rate => 25, burst => 5}},
              {tcp_accept, 80, http},
              {tcp_accept, 443, https},
              {protocol_accept, icmp},
              {log_drop_nflog, <<"ERLKOENIG: ">>, 1, dropped}
          ]}
    ],
    watch => #{
        interval => 2000,
        thresholds => [
            {ssh_flood, ssh, pps, '>', 50.0},
            {http_flood, http, pps, '>', 500.0}
        ]
    },
    ct_guard => #{
        conn_flood => {50, 10},
        port_scan  => {20, 60},
        ban_duration => 3600
    }
}.
```

Some features are only available in the Erlang term format:

| Feature | Term syntax | Notes |
|---------|-------------|-------|
| NFLOG capture | `{nflog_capture_udp, Port, Prefix, Group}` | SPA packet capture |
| NFLOG drop | `{log_drop_nflog, Prefix, Group, Counter}` | Log to NFLOG group |
| Set-gated UDP | `{set_lookup_udp_accept, Set, Port}` | WireGuard SPA gate |
| Interface accept | `{iifname_accept, <<"wg0">>}` | Trust named interface |
| Masquerade | `masq` | Dynamic SNAT |
| DNAT | `{dnat, {10,0,0,5}, Port}` | Destination NAT |
| Forward established | `forward_established` | Forward chain conntrack |

## Runtime API

```erlang
%% Firewall
erlkoenig_nft:status().                     %% applied config overview
erlkoenig_nft:reload().                     %% hot-reload from config file

%% Banning — kernel hash set, O(1), automatic IPv4/IPv6 detection
erlkoenig_nft:ban("203.0.113.42").          %% string, binary, tuple, or raw bytes
erlkoenig_nft:unban("203.0.113.42").

%% Live counters — packets/sec and bytes/sec per named counter
erlkoenig_nft:rates().
%% => #{ssh => #{pps => 12.5, bps => 8340.0},
%%       http => #{pps => 245.0, bps => 198400.0},
%%       dropped => #{pps => 0.5, bps => 320.0}}

%% Connection tracking — real-time via netlink multicast
erlkoenig_nft:ct_count().                   %% total active connections
erlkoenig_nft:ct_count("10.0.0.5").         %% connections from one IP
erlkoenig_nft:ct_top(10).                   %% top 10 talkers
erlkoenig_nft:ct_connections().             %% full connection list
erlkoenig_nft:ct_mode().                    %% full | aggregate
erlkoenig_nft:ct_stats().                   %% operational metrics

%% Threat detection
erlkoenig_nft:guard_stats().
%% => #{floods_detected => 3, scans_detected => 1, active_bans => 2}
erlkoenig_nft:guard_banned().
%% => [#{ip => "203.0.113.42", reason => conn_flood, expires_in => 2847}]
```

## Testing Without Root

The built-in nf_tables virtual machine (`nft_vm`) executes rules in
pure Erlang. Same semantics as the kernel: 16 registers, left-to-right
evaluation, BREAK on mismatch. Build synthetic packets, verify verdicts,
inspect execution traces — all without CAP_NET_ADMIN.

```erlang
%% Does SSH get accepted?
Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,5}, dport => 22}),
Rules = nft_rules:tcp_accept(22),
{accept, _} = nft_vm:eval_chain([Rules], Pkt, drop).

%% Does port 3306 get dropped?
Pkt2 = nft_vm_pkt:tcp(#{saddr => {10,0,0,5}, dport => 3306}),
{drop, _} = nft_vm:eval_chain([Rules], Pkt2, drop).

%% Full chain with trace
Chain = [
    nft_rules:ct_established_accept(),
    nft_rules:iif_accept(),
    nft_rules:tcp_accept(22),
    nft_rules:tcp_accept(80)
],
Pkt3 = nft_vm_pkt:tcp(#{dport => 80}),
{accept, Trace} = nft_vm:eval_chain(Chain, Pkt3, drop),
nft_vm:print_trace(Trace).    %% step-by-step register state

%% UDP, ICMP, conntrack states
UdpPkt = nft_vm_pkt:udp(#{dport => 53}),
IcmpPkt = nft_vm_pkt:icmp(#{}, #{type => echo_request}),
EstPkt = nft_vm_pkt:tcp(#{dport => 22}, #{}, #{ct_state => established}).

%% Set membership testing
Sets = #{<<"blocklist">> => sets:from_list([<<203,0,113,42:32>>])},
BanPkt = nft_vm_pkt:with_sets(
    nft_vm_pkt:tcp(#{saddr => {203,0,113,42}, dport => 80}),
    Sets).
```

239 tests + 43 DSL tests, all without root:

```bash
make check            # ct + dialyzer + DSL tests
make test             # Erlang common test only
make test-dsl         # Elixir DSL tests only
make dialyzer         # static analysis
```

## Architecture

```
erlkoenig_nft_sup (rest_for_one)
|
+-- pg (erlkoenig_nft)           Event broadcast (counter_events, ct_events, nflog_events)
+-- nfnl_server                  Shared AF_NETLINK socket, sequence management, batch I/O
+-- erlkoenig_nft_nflog          NFLOG packet receiver (SPA capture, dropped packet forensics)
+-- erlkoenig_nft_ct             Conntrack monitor (full + aggregate dual-mode)
+-- erlkoenig_nft_ct_guard       Threat detection: flood + scan -> auto-ban
+-- erlkoenig_nft_watch_sup      Dynamic supervisor for counter workers
|   +-- erlkoenig_nft_counter    One gen_server per named counter (polls, computes rates)
+-- erlkoenig_nft_firewall       Config owner: reads .term, builds rules, applies via netlink
```

### Data Pipeline

```
Config (.term file or DSL output)
  |
  v
Rule builders (nft_rules)         High-level: tcp_accept, set_lookup_drop, ...
  |
  v
Expression IR (nft_expr_ir)       Semantic terms: {meta, #{key => l4proto, dreg => 1}}
  |                                |
  +---> nft_vm (testing)           +---> nft_encode (production)
        Pure Erlang emulator              IR -> netlink binary
                                          |
                                          v
                                   nft_batch                Atomic transaction wrapper
                                          |
                                          v
                                   nfnl_server              Send + collect ACKs
                                          |
                                          v
                                   Kernel                   Apply all-or-nothing
```

### Event System

All monitoring uses OTP `pg` process groups. Subscribe from any process:

```erlang
%% Counter rate events
pg:join(erlkoenig_nft, counter_events, self()),
receive {counter_event, ssh, #{pps := PPS}} -> PPS end.

%% Connection tracking events
pg:join(erlkoenig_nft, ct_events, self()),
receive {ct_new, #{src := Src, dport := 22}} -> Src end.

%% NFLOG packet events
pg:join(erlkoenig_nft, nflog_events, self()),
receive {nflog_event, #{prefix := <<"SPA:">>, src := Src}} -> Src end.
```

### How Banning Works

Ban doesn't add rules. It inserts an element into a kernel hash set:

```
erlkoenig_nft:ban("10.0.0.5")
  -> erlkoenig_nft_ip:normalize/1          Convert to 4-byte binary
  -> nft_set_elem:add_elem(...)            Netlink NEWSETELEM message
  -> nfnl_server:apply_msgs/2             Send in batch
  -> Kernel hash table insert              O(1)
```

One rule matches the entire set: `ip saddr @blocklist drop`. Ban 1 IP
or 100,000 — same rule, same O(1) performance. Under DDoS, the
conntrack monitor automatically switches from per-connection tracking
(~100 bytes/conn) to per-source aggregation (~10 bytes/src) — 10x
memory reduction.

### Code Generation

38 of 83 modules are generated from the kernel's `nf_tables.h` via
`codegen/nft_gen.escript`. One module per expression type (payload,
meta, cmp, counter, log, nat, ...). The generator handles TLV attribute
boilerplate; all semantic logic is hand-written.

~10,000 lines total. 45 hand-written modules (7,909 LOC), 38 generated
(2,088 LOC).

## Requirements

| Requirement | Minimum |
|-------------|---------|
| Linux | >= 5.0 (nf_tables) |
| Erlang/OTP | >= 27 |
| Elixir | >= 1.18 (DSL only, optional) |
| Capabilities | CAP_NET_ADMIN (not needed for tests) |

## Documentation

| Document | Contents |
|----------|----------|
| [Configuration Reference](docs/CONFIGURATION.md) | All rule types, sets, counters, guard, watch options |
| [API Reference](docs/API.md) | Complete `erlkoenig_nft` module API with examples |
| [Elixir DSL Reference](docs/DSL.md) | All macros: firewall, guard, watch, profiles |
| [Technical Deep-Dive](docs/FIREWALL.md) | Netlink protocol, expression IR, code generation, VM internals |

## License

Apache-2.0
