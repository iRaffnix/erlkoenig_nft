# erlkoenig_nft

A firewall engine written in pure Erlang that talks directly to the Linux
kernel via `AF_NETLINK`. No C code. No NIFs. No `os:cmd("nft ...")`.
Zero external dependencies.

> **Early stage software — use in a VM only.** erlkoenig_nft is under active
> development and we are working on getting it stable. It has not been
> battle-tested in production yet. The test suite covers rule logic
> extensively (356 unit tests + 48 kernel integration tests), but real-world
> production usage has seen limited testing.
>
> **Do not run this on a bare-metal host or outside of a virtual machine.**
> A misconfigured firewall can lock you out of your own machine. Always test
> in a disposable VM where you can recover access through the hypervisor
> console.
>
> **Do not run this if Docker is installed.** Docker manages its own
> nf_tables/iptables rules for container networking. erlkoenig_nft will
> overwrite those rules, breaking container connectivity and potentially
> leaving you with no network access at all.
>
> **Do not enable the systemd service by default.** A unit file is included
> (`erlkoenig_nft.service`), but do not enable it to start at boot until you
> have thoroughly tested your configuration. If the firewall applies broken
> rules on boot, it can lock you out permanently — you would need console
> access to recover.
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

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/iRaffnix/erlkoenig_nft/main/install.sh
# Review the script, then run:
sudo sh install.sh --version v0.5.0
```

Auto-detects architecture (x86_64/aarch64) and libc (glibc/musl), downloads
the matching release, installs the CLI to `/usr/local/bin/erlkoenig-nft`,
and optionally installs the systemd unit.

No Erlang or Elixir install required — the release bundles its own runtime.

| Archive | For |
|---------|-----|
| `erlkoenig_nft-v*-x86_64-linux.tar.gz` | Standard Linux (Debian, Ubuntu, Fedora, ...) |
| `erlkoenig_nft-v*-x86_64-musl.tar.gz` | Alpine / static linking |
| `erlkoenig_nft-v*-aarch64-linux.tar.gz` | ARM64 Linux (Raspberry Pi, AWS Graviton, ...) |

Options: `--prefix /path` (default `/opt/erlkoenig_nft`), `--version vX.Y.Z`,
`--no-systemd`.

After install:

```bash
sudo systemctl start erlkoenig_nft    # start the daemon
sudo systemctl status erlkoenig_nft   # check status
sudo nft list ruleset                  # verify kernel rules
erlkoenig-nft --help                   # CLI tool
```

## Build from Source

```bash
make                  # build Erlang core + Elixir DSL
make erl              # or just the Erlang core

# pick a config
cp examples/hardened_webserver.exs etc/firewall.exs

rebar3 shell          # needs CAP_NET_ADMIN
```

## Elixir DSL

The optional DSL (`dsl/`) compiles to the Erlang term format the runtime
loads. Write firewall configs that read like firewall configs.

### Production Edge Server

Shows sets, counters, quotas, verdict maps, flowtables, SYN proxy,
rate metering, OS fingerprinting, NFQUEUE, conntrack marks, RPF
checks, connection limits, and NFLOG — all in one config.

```elixir
defmodule Firewall.Edge do
  use ErlkoenigNft.Firewall

  firewall "edge" do
    counters [:ssh, :http, :https, :dns, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr
    quota :bandwidth, 10_000_000_000, flags: 0          # 10 GB soft quota

    # Concat set: match (ip, port) pairs in a single O(1) lookup
    concat_set "allowpairs", [:ipv4_addr, :inet_service]

    # Verdict map: dispatch TCP ports to per-service chains
    vmap "port_dispatch", :inet_service, id: 10

    # Hardware flow offloading for established connections
    flowtable "fastpath", hook: :ingress, priority: -100, devices: ["eth0"]

    chain "prerouting", hook: :prerouting, priority: -300, policy: :accept do
      rpf_check                                         # FIB reverse-path filter
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
      synproxy [80, 443], mss: 1460, wscale: 7         # SYN cookie protection
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      offload "fastpath"                                # offload established flows
      accept :loopback
      notrack 53, :udp                                  # skip conntrack for DNS

      # Per-source rate limiting via kernel meter
      meter_limit "ssh_meter", 22, :tcp, rate: 10, burst: 3, unit: :minute

      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp [80, 443], counter: :https
      accept_udp 53, counter: :dns
      accept_tcp_range 8000, 8099                       # app ports
      accept_udp_range 27000, 27015                     # game traffic
      accept_from {10, 0, 1, 0, 0, 0, 0, 0}            # private subnet
      connlimit_drop 200                                # DDoS protection

      # Conntrack marks: tag and match traffic
      mark_connection 42
      match_mark 42, verdict: :accept

      # Dispatch TCP by port to per-service chains via verdict map
      dispatch :tcp, "port_dispatch"

      # OS fingerprinting: only allow Linux clients on port 9090
      match_os "Linux", :accept

      # NFQUEUE: send suspicious traffic to userspace IDS
      queue_to 443, :tcp, queue: 0, fanout: true

      # Cgroup-based filtering (container/systemd isolation)
      match_cgroup 1234, :accept

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop_nflog "EDGE-DROP: ", group: 1, counter: :dropped
    end
  end
end
```

### Threat Detection + Counter Monitoring

```elixir
defmodule MyGuard do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 0, 1}
    cleanup_interval 15_000
  end
end

defmodule MyWatch do
  use ErlkoenigNft.Watch

  watch :traffic do
    counter :ssh, :pps, threshold: 50
    counter :http, :pps, threshold: 5000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/fw"}
  end
end

# Quick profiles for simple setups
ErlkoenigNft.Firewall.Profiles.get(:strict, allow_tcp: [22, 443])
ErlkoenigNft.Firewall.Profiles.get(:standard, allow_udp: [51820])
```

## Examples

All 17 scenarios ship as Elixir DSL configs in [`examples/`](examples/):

| Scenario | Config |
|----------|--------|
| **Default (installed on first run)** | [`examples/default.exs`](examples/default.exs) |
| Hardened web server | [`examples/hardened_webserver.exs`](examples/hardened_webserver.exs) |
| Mail server (TLS enforcement) | [`examples/mail_server.exs`](examples/mail_server.exs) |
| Database server (private subnet) | [`examples/database_server.exs`](examples/database_server.exs) |
| VPN gateway (NAT + forwarding) | [`examples/vpn_gateway.exs`](examples/vpn_gateway.exs) |
| DNS server (rate-limited) | [`examples/dns_server.exs`](examples/dns_server.exs) |
| Game server (UDP port ranges) | [`examples/game_server.exs`](examples/game_server.exs) |
| Reverse proxy (DNAT + connlimit) | [`examples/reverse_proxy.exs`](examples/reverse_proxy.exs) |
| Docker host (bridge + containers) | [`examples/docker_host.exs`](examples/docker_host.exs) |
| Dev server (relaxed, reject) | [`examples/dev_server.exs`](examples/dev_server.exs) |
| Per-source rate limiter (meters + quotas) | [`examples/rate_limiter.exs`](examples/rate_limiter.exs) |
| SYN proxy server (anti-DDoS) | [`examples/synproxy_server.exs`](examples/synproxy_server.exs) |
| IDS gateway (NFQUEUE + OS fingerprint) | [`examples/ids_gateway.exs`](examples/ids_gateway.exs) |
| Service mesh (cgroups + flowtables) | [`examples/service_mesh.exs`](examples/service_mesh.exs) |
| Anti-spoofing edge router (FIB + vmaps) | [`examples/anti_spoofing.exs`](examples/anti_spoofing.exs) |
| NAT router (DNAT + SNAT) | [`examples/nat_router.exs`](examples/nat_router.exs) |
| Zone router (multi-zone segmentation) | [`examples/zone_router.exs`](examples/zone_router.exs) |

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

## CLI

The `erlkoenig` command-line tool provides both daemon interaction and
local config operations. Built with the Elixir DSL (`dsl/`).

```bash
mix escript.build    # in dsl/
```

### Daemon Commands

Talk to a running erlkoenig_nft daemon via Unix socket:

```bash
erlkoenig status                    # firewall status overview
erlkoenig counters                  # live counter values
erlkoenig ban 203.0.113.42         # add IP to blocklist
erlkoenig unban 203.0.113.42       # remove IP from blocklist
erlkoenig reload                    # hot-reload config
erlkoenig apply config.exs         # compile and apply new config
erlkoenig guard stats              # threat detection statistics
erlkoenig guard banned             # list currently banned IPs
```

### Local Commands

Work with config files without a running daemon:

```bash
erlkoenig show config.exs          # pretty-print compiled config
erlkoenig compile config.exs       # compile to .term (stdout or -o file)
erlkoenig validate config.exs      # check config for errors
erlkoenig inspect config.exs       # show internal IR structure
erlkoenig diff a.exs b.exs         # diff two compiled configs
erlkoenig list                      # list .exs configs in current dir
erlkoenig version                   # print version
erlkoenig completions bash          # shell completions (bash/zsh/fish)
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

356 unit tests + 48 kernel integration tests + DSL tests:

```bash
make check            # lint + eunit + ct + DSL tests
make test             # Erlang common test (unit, kernel tests skipped without root)
sudo make test        # includes kernel integration tests (requires root)
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

38 of 87 modules are generated from the kernel's `nf_tables.h` via
`codegen/nft_gen.escript`. One module per expression type (payload,
meta, cmp, counter, log, nat, ...). The generator handles TLV attribute
boilerplate; all semantic logic is hand-written. Kernel constants are
consolidated in a single header (`include/nft_constants.hrl`).

~12,300 lines total. 49 hand-written modules (10,216 LOC), 38 generated
(2,088 LOC).

## Requirements

| Requirement | Minimum |
|-------------|---------|
| Linux | >= 5.0 (nf_tables) |
| Erlang/OTP | >= 28 |
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
