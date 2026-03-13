# Erlkoenig NFT — Feature Roadmap

Advanced nftables features to expose through the full stack:
IR (`nft_expr_ir`) -> rule builder (`nft_rules`) -> DSL macro (`ErlkoenigNft.Firewall`)
-> VM tests (`nft_vm_SUITE`) -> kernel tests (validate against `nft -j`).

Each work packet follows the same structure:

1. **Erlang IR + encoder** — add or verify `nft_expr_ir` helpers and `nft_encode` support
2. **Rule builder** — add `nft_rules:*` functions returning IR terms
3. **DSL macro** — add Elixir macro in `ErlkoenigNft.Firewall` + `Builder`
4. **VM tests** — test rule logic in `nft_vm_SUITE` with synthetic packets
5. **Kernel tests** — apply via netlink, verify with `nft -j`, clean up

---

## WP-1: Owner Tables

**Priority:** P0 — operational safety, small change

### What

Set the `NFT_TABLE_F_OWNER` flag (0x02) on tables created by erlkoenig.
When the owning process (nfnl_server) exits or crashes, the kernel
automatically removes the table. No more orphaned firewall rules after
a daemon crash.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| Encoder | `src/nft_table.erl` | Add `add/4` accepting `#{owner => true}`, encode `NFTA_TABLE_FLAGS = 0x02`, add `NFTA_TABLE_USERDATA` with PID/name |
| Config | `src/erlkoenig_nft_config.erl` | Default `owner => true` in prod profile |
| Firewall | `src/erlkoenig_nft_firewall.erl` | Pass `owner` flag through to `nft_table:add/4` |

### DSL Example

```elixir
defmodule MyFirewall do
  use ErlkoenigNft.Firewall

  # Owner is the default — table auto-removed on daemon exit.
  # Set owner: false to persist across restarts.
  firewall "web", owner: true do
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

No VM-level behavior change — owner is a table-level flag, not an
expression. Unit tests go in `nft_table_SUITE`:

```erlang
%% Unit: owner flag encoded correctly
owner_table_flag(_) ->
    Msg = nft_table:add(1, <<"fw">>, #{owner => true}, 1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    {2, <<Flags:32/big>>} = lists:keyfind(2, 1, Decoded),
    ?assert((Flags band 16#02) =/= 0).

%% Unit: default (no owner) still works
default_table_no_owner(_) ->
    Msg = nft_table:add(1, <<"fw">>, 1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    {2, <<0:32/big>>} = lists:keyfind(2, 1, Decoded).
```

### Kernel Tests (`nft_table_SUITE`)

```erlang
%% Kernel: owner table appears in nft -j output with owner flag
kernel_owner_table(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, #{owner => true}, Seq) end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Table] = [T || #{<<"table">> := T = #{<<"name">> := ?TABLE}} <- Items],
    %% nft -j shows "flags" : "owner" for owned tables (kernel 5.13+)
    ?assertMatch(#{<<"flags">> := _}, Table),
    nfnl_server:stop(Pid).

%% Kernel: owner table disappears when nfnl_server stops
kernel_owner_table_removed_on_exit(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, #{owner => true}, Seq) end
    ]),
    %% Table exists
    ?assertNotEqual([], nft_json("list table inet " ++ binary_to_list(?TABLE))),
    %% Kill the netlink socket owner
    nfnl_server:stop(Pid),
    timer:sleep(100),
    %% Table should be gone
    Output = os:cmd("nft list table inet " ++ binary_to_list(?TABLE) ++ " 2>&1"),
    ?assertNotEqual(nomatch, string:find(Output, "No such")).
```

---

## WP-2: SYN Proxy

**Priority:** P0 — DDoS protection, IR already exists

### What

Kernel-level SYN cookie proxy. Protects TCP services from SYN floods
without consuming conntrack entries for half-open connections. The kernel
responds to SYN with a SYN-ACK containing a cookie; only completed
handshakes reach conntrack.

Requires two chains:
1. A `raw` prerouting chain with `notrack` for the target ports
2. The filter chain with `synproxy` + `ct state invalid,untracked`

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `synproxy/3` already exists — verify params: `mss`, `wscale`, `flags` (timestamp, sack-perm) |
| IR | `src/nft_expr_ir.erl` | Add `notrack/0` → `{notrack, #{}}` |
| Encoder | `src/nft_encode.erl` | Add `notrack` encoding (empty expression, name only) |
| Rules | `src/nft_rules.erl` | Add `synproxy_rules/2` returning `[NotrackRule, SynproxyRule]` |
| Config | `src/erlkoenig_nft_config.erl` | Support `synproxy` key in chain rule specs |
| Firewall | `src/erlkoenig_nft_firewall.erl` | Generate both chains (raw + filter) for synproxy ports |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `synproxy` macro |

### DSL Example

```elixir
defmodule WebFirewall do
  use ErlkoenigNft.Firewall

  firewall "web" do
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SYN proxy for HTTP/HTTPS — kernel handles SYN floods
      synproxy [80, 443], mss: 1460, wscale: 7, timestamp: true, sack_perm: true

      accept_tcp [80, 443]
      log_and_drop "BLOCKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% synproxy expressions produce correct IR terms
test_synproxy_ir(_) ->
    Rules = nft_rules:synproxy_rules([80, 443],
        #{mss => 1460, wscale => 7, flags => [timestamp, sack_perm]}),
    ?assert(length(Rules) >= 2),
    %% First rule: notrack for target ports in raw chain
    [NotrackRule | _] = Rules,
    ?assert(lists:any(fun({notrack, _}) -> true; (_) -> false end, NotrackRule)).

%% notrack rule does not produce a verdict (it's a side-effect)
test_notrack_ir(_) ->
    Expr = nft_expr_ir:notrack(),
    ?assertMatch({notrack, #{}}, Expr).

%% synproxy rule matches untracked TCP SYN
test_synproxy_untracked_syn(_) ->
    %% Build a TCP SYN packet with ct state = untracked
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80, flags => syn},
                          #{ct_state => untracked}),
    Rule = nft_rules:synproxy_filter_rule(80,
        #{mss => 1460, wscale => 7, flags => [timestamp, sack_perm]}),
    %% synproxy is a terminal action in the VM (like accept)
    {synproxy, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_synproxy_SUITE`)

```erlang
%% Kernel: synproxy rules applied and visible in nft -j
kernel_synproxy_rules(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        %% Raw chain for notrack
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"raw_prerouting">>,
            hook => prerouting, type => filter,
            priority => -300, policy => accept
        }, Seq) end,
        %% Filter chain with synproxy
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => drop
        }, Seq) end
        | synproxy_rule_funs(?TABLE, 80, #{mss => 1460, wscale => 7})
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Verify notrack rule exists in raw chain
    RawRules = rules_for_chain(Items, <<"raw_prerouting">>),
    ?assert(lists:any(fun has_notrack_expr/1, RawRules)),
    %% Verify synproxy rule exists in input chain
    InputRules = rules_for_chain(Items, <<"input">>),
    ?assert(lists:any(fun has_synproxy_expr/1, InputRules)),
    nfnl_server:stop(Pid).
```

---

## WP-3: Meters (Dynamic Per-Element Rate Limiting)

**Priority:** P0 — natural extension of ct_guard

### What

Kernel-side per-source-IP rate limiting using dynamic sets with
per-element `limit` expressions. Unlike static `limit` (global rate),
meters track rates **per key** (e.g., per source IP). This replaces
iptables `hashlimit`.

Combined with Erlang's `ct_guard`, enables a two-tier defense:
1. Kernel meters enforce per-IP rate limits at wire speed
2. Erlang ct_guard detects patterns and auto-bans persistent offenders

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `dynset/3` exists — add `meter/4` convenience: `meter(SetName, KeyExprs, LimitExpr, Verdict)` |
| Rules | `src/nft_rules.erl` | Add `meter_limit/4` — per-IP rate limit using dynamic set |
| Config | `src/erlkoenig_nft_config.erl` | Support `meter` rule type in chain specs |
| Firewall | `src/erlkoenig_nft_firewall.erl` | Create meter sets + rules |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `meter_limit` macro |

### DSL Example

```elixir
defmodule RateLimitedServer do
  use ErlkoenigNft.Firewall

  firewall "api" do
    counters [:ssh, :http, :dropped]

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Per-source-IP rate limits (kernel-enforced, no Erlang overhead)
      meter_limit :ssh_meter, 22, :tcp, rate: {10, :second}, burst: 5
      meter_limit :http_meter, 80, :tcp, rate: {200, :second}, burst: 50

      accept_tcp 22, counter: :ssh
      accept_tcp [80, 443], counter: :http
      log_and_drop "FLOOD: ", counter: :dropped
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Meter rule produces correct IR with dynset + limit
test_meter_limit_ir(_) ->
    Rule = nft_rules:meter_limit(<<"ssh_meter">>, 22, tcp,
        #{rate => 10, burst => 5, unit => second}),
    %% Should contain: meta l4proto, cmp tcp, tcp dport, cmp 22,
    %%                 dynset with limit expression
    ?assert(lists:any(fun({dynset, _}) -> true; (_) -> false end, Rule)).

%% Meter with under-limit traffic passes
test_meter_under_limit(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    Rule = nft_rules:meter_limit(<<"m">>, 22, tcp,
        #{rate => 100, burst => 10, unit => second}),
    %% Under limit -> rule does NOT match (traffic passes through)
    {break, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% Meter with over-limit traffic drops
test_meter_over_limit(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    Rule = nft_rules:meter_limit(<<"m">>, 22, tcp,
        #{rate => 0, burst => 0, unit => second}),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_meter_SUITE`)

```erlang
%% Kernel: meter set created with correct type and flags
kernel_meter_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = apply_meter_rules(Pid, ?TABLE, <<"ssh_meter">>, 22, tcp,
        #{rate => 10, burst => 5, unit => second}),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Verify meter set exists with dynamic flag
    [Set] = [S || #{<<"set">> := S = #{<<"name">> := <<"ssh_meter">>}} <- Items],
    Flags = maps:get(<<"flags">>, Set, []),
    ?assert(lists:member(<<"dynamic">>, Flags)),
    nfnl_server:stop(Pid).

%% Kernel: meter rule references the dynamic set
kernel_meter_rule_refs_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = apply_meter_rules(Pid, ?TABLE, <<"http_meter">>, 80, tcp,
        #{rate => 200, burst => 50, unit => second}),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"input">>),
    %% At least one rule should reference the meter set name
    ?assert(lists:any(fun(R) -> has_dynset_ref(R, <<"http_meter">>) end, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-4: NFQUEUE (Userspace Packet Processing)

**Priority:** P0 — unique differentiator for Erlang

### What

Send matched packets to an Erlang gen_server via NFQUEUE. Each packet
is delivered as a binary via netlink, processed by a lightweight Erlang
process, and verdicted (accept/drop/modify). This enables:

- Custom protocol validation (e.g., validate DNS query structure)
- Application-layer inspection without tproxy overhead
- Programmable packet decisions in Erlang

Requires a new `erlkoenig_nft_queue` gen_server that opens an
`AF_NETLINK/NETLINK_NETFILTER` socket for the NFQUEUE subsystem.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `queue/1` exists — add `queue/2` with `#{num, flags}` |
| Rules | `src/nft_rules.erl` | Add `queue_rule/3` — match port + queue to num |
| Queue | `src/erlkoenig_nft_queue.erl` | **New** — gen_server: open NFQUEUE socket, receive packets, dispatch to callback, send verdict |
| Sup | `src/erlkoenig_nft_sup.erl` | Add queue worker to supervision tree |
| Config | `src/erlkoenig_nft_config.erl` | Support `queue` rule type with callback module |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `queue_to` macro |

### DSL Example

```elixir
defmodule InspectionFirewall do
  use ErlkoenigNft.Firewall

  firewall "inspect" do
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Send DNS queries to Erlang for deep inspection
      # Queue 100, bypass=true (accept if no listener)
      queue_to 53, :udp, queue: 100, bypass: true

      # Send unknown TCP to Erlang for protocol detection
      queue_to {1024, 65535}, :tcp, queue: {200, 203}, fanout: true

      accept_tcp [22, 80, 443]
      log_and_drop "BLOCKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Queue expression produces correct IR
test_queue_ir(_) ->
    Rule = nft_rules:queue_rule(53, udp, #{num => 100, flags => [bypass]}),
    ?assert(lists:any(fun({queue, _}) -> true; (_) -> false end, Rule)).

%% Queue rule matches target port and protocol
test_queue_matches_port(_) ->
    Pkt = nft_vm_pkt:udp(#{saddr => {10,0,0,1}}, #{dport => 53}),
    Rule = nft_rules:queue_rule(53, udp, #{num => 100}),
    {queue, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% Queue rule does not match wrong protocol
test_queue_wrong_proto(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 53}),
    Rule = nft_rules:queue_rule(53, udp, #{num => 100}),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% Queue with port range
test_queue_port_range(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 8080}),
    Rule = nft_rules:queue_range_rule({1024, 65535}, tcp,
        #{num => {200, 203}, flags => [fanout]}),
    {queue, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_queue_SUITE`)

```erlang
%% Kernel: queue rule applied and visible in nft -j
kernel_queue_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, Seq) end
        | queue_rule_funs(?TABLE, 53, udp, #{num => 100, flags => [bypass]})
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"input">>),
    %% Verify queue expression with correct queue number
    [QRule] = [R || R <- Rules, has_queue_expr(R)],
    QExpr = find_expr(QRule, <<"queue">>),
    ?assertEqual(100, maps:get(<<"num">>, QExpr)),
    nfnl_server:stop(Pid).

%% Kernel: queue range + fanout flags
kernel_queue_fanout(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, Seq) end
        | queue_rule_funs(?TABLE, {1024, 65535}, tcp,
            #{num => {200, 203}, flags => [fanout]})
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"input">>),
    [QRule] = [R || R <- Rules, has_queue_expr(R)],
    QExpr = find_expr(QRule, <<"queue">>),
    %% nft -j shows "num" and "flags" for queue ranges
    ?assert(maps:is_key(<<"num">>, QExpr)),
    ?assertNotEqual(nomatch, string:find(
        json:encode(QExpr), <<"fanout">>)),
    nfnl_server:stop(Pid).
```

---

## WP-5: cgroupv2 Socket Matching

**Priority:** P1 — per-service firewall policies

### What

Match packets by the cgroupv2 hierarchy of the originating socket.
This allows per-systemd-service firewall rules without knowing PIDs
or port numbers. Example: restrict `postgresql.service` to only
accept connections on port 5432 from the local subnet.

Uses `socket cgroupv2 level N` to match at a specific cgroup ancestor
level. Level 0 = root, level 1 = first child (typically the systemd
slice), level 2 = the service unit.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `socket/2` exists — add `socket_cgroup/1` convenience for `{socket, #{key => cgroupv2, level => N, dreg => R}}` |
| Rules | `src/nft_rules.erl` | Add `cgroup_accept/1`, `cgroup_drop/1`, `cgroup_match/2` |
| Config | `src/erlkoenig_nft_config.erl` | Support `cgroup` rule type |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `match_cgroup` macro |

### DSL Example

```elixir
defmodule ServiceFirewall do
  use ErlkoenigNft.Firewall

  firewall "services" do
    chain "output", hook: :output, policy: :accept do
      # Only allow postgres to reach its own port
      match_cgroup "system.slice/postgresql.service", allow: [5432], proto: :tcp

      # Block all outbound from untrusted services
      match_cgroup "system.slice/untrusted.service", action: :drop
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established

      # Only accept nginx traffic on web ports
      match_cgroup "system.slice/nginx.service", allow: [80, 443], proto: :tcp

      log_and_drop "DENIED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Socket cgroup expression loads cgroup ID into register
test_socket_cgroup_ir(_) ->
    Expr = nft_expr_ir:socket_cgroup(2),
    ?assertMatch({socket, #{key := cgroupv2, level := 2, dreg := _}}, Expr).

%% cgroup match rule accepts packet from matching cgroup
test_cgroup_accept(_) ->
    CgroupId = 42,
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 5432},
                          #{socket_cgroup => CgroupId}),
    Rule = nft_rules:cgroup_accept(CgroupId),
    {accept, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% cgroup match rule rejects packet from different cgroup
test_cgroup_mismatch(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 5432},
                          #{socket_cgroup => 99}),
    Rule = nft_rules:cgroup_accept(42),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_cgroup_SUITE`)

```erlang
%% Kernel: cgroup rule applied with socket expression
kernel_cgroup_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"output">>,
            hook => output, type => filter,
            priority => 0, policy => accept
        }, Seq) end
        | cgroup_rule_funs(?TABLE, <<"output">>, 42, accept)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"output">>),
    %% Verify socket expression with cgroupv2 key
    ?assert(lists:any(fun has_socket_cgroup_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-6: Verdict Maps

**Priority:** P1 — performance + DSL expressiveness

### What

Single-rule port dispatch using verdict maps (vmap). Instead of N
separate rules for N ports, a single rule does an O(1) lookup:

    tcp dport vmap { 22: jump ssh, 80: jump http, 443: jump https }

This enables per-service chain isolation with zero performance cost.
Each service gets its own chain with independent counters and limits.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | Add `vmap_lookup/2` — lookup in a verdict map, verdict from map value |
| Sets | `src/nft_set.erl` | Support `NFT_SET_MAP` + `NFT_SET_OBJECT` flags for verdict maps |
| Rules | `src/nft_rules.erl` | Add `vmap_dispatch/2` — `(KeyExpr, #{Port => ChainName})` |
| Config | `src/erlkoenig_nft_config.erl` | Support `vmap` and service chains |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `dispatch` macro for port->chain routing |

### DSL Example

```elixir
defmodule ServiceIsolation do
  use ErlkoenigNft.Firewall

  firewall "isolated" do
    counters [:ssh, :http, :https, :dropped]

    # Per-service chains (no hook — called via jump)
    chain "ssh_svc" do
      accept_tcp 22, counter: :ssh, limit: {10, burst: 5}
      log_and_drop "SSH-FLOOD: "
    end

    chain "http_svc" do
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept :icmp

      # Single-rule dispatch — O(1) port lookup, jump to service chain
      dispatch :tcp, 22 => "ssh_svc", 80 => "http_svc", 443 => "http_svc"

      log_and_drop "BLOCKED: ", counter: :dropped
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Verdict map dispatches to correct chain
test_vmap_dispatch_ssh(_) ->
    SshChain = [nft_rules:tcp_accept(22)],
    HttpChain = [nft_rules:tcp_accept(80)],
    VmapRule = nft_rules:vmap_dispatch(tcp, #{22 => <<"ssh">>, 80 => <<"http">>}),
    Chains = #{<<"ssh">> => SshChain, <<"http">> => HttpChain},
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {accept, _} = nft_vm:eval_chain_with_jumps([VmapRule], Pkt, drop, Chains).

%% Verdict map falls through on unmatched port
test_vmap_dispatch_miss(_) ->
    VmapRule = nft_rules:vmap_dispatch(tcp, #{22 => <<"ssh">>, 80 => <<"http">>}),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 8080}),
    {drop, _} = nft_vm:eval_chain([VmapRule], Pkt, drop).
```

### Kernel Tests (`nft_vmap_SUITE`)

```erlang
%% Kernel: verdict map created and rule references it
kernel_vmap_dispatch(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, vmap_setup_msgs(?TABLE,
        #{22 => <<"ssh_svc">>, 80 => <<"http_svc">>})),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Verify map exists with verdict type
    Maps = [M || #{<<"map">> := M} <- Items],
    ?assert(length(Maps) > 0),
    %% Verify dispatch rule references the map via lookup
    Rules = rules_for_chain(Items, <<"input">>),
    ?assert(lists:any(fun has_lookup_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-7: Flowtables (Connection Fast-Path)

**Priority:** P1 — throughput for forwarding/NAT

### What

Offload established connections to a kernel fast-path that bypasses
the full netfilter stack. For forwarding workloads (VPN gateway,
reverse proxy), this provides 3-10x throughput improvement.

Flowtables are declared at table level with a list of devices and
the ingress hook. Connections are offloaded from the forward chain
via `flow add @ft`.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| Netlink | `src/nft_flowtable.erl` | **New** — NEWFLOWTABLE message builder (name, hook, priority, devices) |
| IR | `src/nft_expr_ir.erl` | `offload/1` exists — verify encoding |
| Rules | `src/nft_rules.erl` | Add `flow_offload/1` — `ct state established flow add @FlowtableName` |
| Config | `src/erlkoenig_nft_config.erl` | Support `flowtable` key: `#{name, devices, priority}` |
| Firewall | `src/erlkoenig_nft_firewall.erl` | Create flowtable + offload rule in forward chain |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `flowtable` and `offload` macros |

### DSL Example

```elixir
defmodule VpnGateway do
  use ErlkoenigNft.Firewall

  firewall "gateway" do
    # Declare fast-path for established connections between interfaces
    flowtable "fastpath", devices: ["eth0", "wg0"], priority: 0

    chain "forward", hook: :forward, policy: :drop do
      # Offload established connections — bypass netfilter stack
      offload "fastpath"

      accept :established
      accept_from "10.0.0.0/24"  # VPN clients
      log_and_drop "FWD-DENY: "
    end

    chain "postrouting", hook: :postrouting, type: :nat do
      masquerade oif: "eth0"
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Offload expression produces correct IR
test_flow_offload_ir(_) ->
    Rule = nft_rules:flow_offload(<<"fastpath">>),
    %% Should match ct state established, then offload
    ?assert(lists:any(fun({ct, #{key := state}}) -> true; (_) -> false end, Rule)),
    ?assert(lists:any(fun({offload, _}) -> true; (_) -> false end, Rule)).

%% Offload rule matches established connections
test_flow_offload_established(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80},
                          #{ct_state => established}),
    Rule = nft_rules:flow_offload(<<"ft">>),
    %% offload is a side-effect; the rule should not produce drop
    Result = nft_vm:eval_chain([Rule], Pkt, accept),
    ?assertNotMatch({drop, _}, Result).
```

### Kernel Tests (`nft_flowtable_SUITE`)

```erlang
%% Kernel: flowtable created with correct devices
kernel_flowtable(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_flowtable:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"ft">>,
            hook => ingress, priority => 0,
            devices => [<<"lo">>]  % lo for testing
        }, Seq) end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Ft] = [F || #{<<"flowtable">> := F = #{<<"name">> := <<"ft">>}} <- Items],
    ?assertEqual(<<"ingress">>, maps:get(<<"hook">>, Ft)),
    ?assert(lists:member(<<"lo">>, maps:get(<<"devs">>, Ft, []))),
    nfnl_server:stop(Pid).

%% Kernel: offload rule references flowtable
kernel_offload_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, flowtable_setup_msgs(?TABLE, <<"ft">>, [<<"lo">>])),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"forward">>),
    ?assert(lists:any(fun has_flow_offload_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-8: ct mark (Cross-Chain Connection Tagging)

**Priority:** P1 — stateful cross-chain logic

### What

Set a mark on a conntrack entry in one chain, match it in another.
This enables patterns like:

1. Mark SPA-authenticated connections in prerouting
2. Allow their outbound replies in output based on the mark
3. Tag VPN traffic for QoS classification in postrouting

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | Add `ct_mark_set/2` — set ct mark from register; `ct_mark/1` — load ct mark into register |
| Rules | `src/nft_rules.erl` | Add `ct_mark_set/1`, `ct_mark_match/2` |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `mark_connection` and `match_mark` macros |

### DSL Example

```elixir
defmodule MarkedFirewall do
  use ErlkoenigNft.Firewall

  firewall "marked" do
    chain "prerouting", hook: :prerouting, priority: -150 do
      # Tag SPA-authenticated WireGuard clients
      mark_connection 0x1, if_in_set: "wg_authorized"

      # Tag traffic from trusted subnet
      mark_connection 0x2, from: "10.0.0.0/24"
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      # Accept marked traffic
      match_mark 0x1, action: :accept
      match_mark 0x2, action: :accept
      log_and_drop "UNMARKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% ct mark set produces correct IR
test_ct_mark_set_ir(_) ->
    Exprs = nft_rules:ct_mark_set(16#01),
    ?assert(lists:any(fun({immediate, #{data := <<1:32/big>>}}) -> true;
                         (_) -> false end, Exprs)),
    ?assert(lists:any(fun({ct, #{key := mark}}) -> true; (_) -> false end, Exprs)).

%% ct mark match accepts tagged connections
test_ct_mark_match(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80},
                          #{ct_mark => 16#01}),
    Rule = nft_rules:ct_mark_match(16#01, accept),
    {accept, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% ct mark match rejects untagged connections
test_ct_mark_mismatch(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80},
                          #{ct_mark => 16#00}),
    Rule = nft_rules:ct_mark_match(16#01, accept),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_ct_mark_SUITE`)

```erlang
%% Kernel: ct mark set rule visible in nft -j
kernel_ct_mark_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, ct_mark_setup_msgs(?TABLE, 16#01)),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"prerouting">>),
    %% Verify ct expression with mark key and sreg (set mode)
    ?assert(lists:any(fun has_ct_mark_set_expr/1, Rules)),
    nfnl_server:stop(Pid).

%% Kernel: ct mark match rule visible
kernel_ct_mark_match(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, ct_mark_match_msgs(?TABLE, 16#01)),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"input">>),
    %% Verify ct expression with mark key and dreg (read mode)
    ?assert(lists:any(fun has_ct_mark_read_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-9: Quotas (Byte-Based Thresholds)

**Priority:** P1 — bandwidth management

### What

Named quota objects that enforce byte-count thresholds. Two modes:
- `over` — match when quota is exceeded (for dropping/logging)
- `until` — match while under quota (for allowing)

Combined with Erlang monitoring: dynamically adjust or reset quotas
based on time-of-day or billing cycles.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `quota/2` exists — verify `#{bytes, flags}` (flags: 0=until, 1=over) |
| Objects | `src/nft_quota.erl` | **New** — NEWOBJ message builder for named quota objects |
| Rules | `src/nft_rules.erl` | Add `quota_drop/2`, `quota_accept/2` |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `quota` macro |

### DSL Example

```elixir
defmodule BandwidthFirewall do
  use ErlkoenigNft.Firewall

  firewall "metered" do
    # Named quota objects (can be reset via API)
    quota :daily_http, bytes: 10_000_000_000  # 10 GB
    quota :daily_ssh, bytes: 1_000_000_000    # 1 GB

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Accept HTTP until 10 GB daily quota exhausted
      accept_tcp [80, 443], quota: :daily_http
      # Drop HTTP after quota exceeded
      reject_tcp [80, 443]

      accept_tcp 22, quota: :daily_ssh
      log_and_drop "OVER-QUOTA: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Quota under limit accepts
test_quota_under(_) ->
    Rule = nft_rules:quota_accept(80, tcp, #{bytes => 1_000_000, mode => until}),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {accept, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% Quota over limit drops
test_quota_over(_) ->
    Rule = nft_rules:quota_drop(80, tcp, #{bytes => 0, mode => over}),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_quota_SUITE`)

```erlang
%% Kernel: named quota object created
kernel_quota_object(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_quota:add(?NFPROTO_INET, ?TABLE, <<"daily">>,
            #{bytes => 10_000_000_000}, Seq) end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Quotas = [Q || #{<<"quota">> := Q = #{<<"name">> := <<"daily">>}} <- Items],
    ?assertEqual(1, length(Quotas)),
    [Q] = Quotas,
    ?assertEqual(10_000_000_000, maps:get(<<"bytes">>, Q)),
    nfnl_server:stop(Pid).
```

---

## WP-10: Notrack (Conntrack Bypass)

**Priority:** P2 — performance under DDoS

### What

Skip connection tracking for high-volume stateless traffic. Reduces
conntrack table pressure for services like DNS, NTP, health checks.
Applied in a `raw` prerouting chain at priority -300.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | Add `notrack/0` (shared with WP-2) |
| Rules | `src/nft_rules.erl` | Add `notrack_rule/2` — match port + notrack |
| Config | `src/erlkoenig_nft_config.erl` | Support `notrack` in chain specs |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `notrack` macro |

### DSL Example

```elixir
defmodule DnsServer do
  use ErlkoenigNft.Firewall

  firewall "dns" do
    chain "raw", hook: :prerouting, type: :filter, priority: -300 do
      # Skip conntrack for DNS — saves memory under query floods
      notrack 53, :udp
      notrack 53, :tcp
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      # Notracked DNS still needs explicit accept
      accept_udp 53
      accept_tcp 53
      log_and_drop "BLOCKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% notrack IR term
test_notrack_expr(_) ->
    Expr = nft_expr_ir:notrack(),
    ?assertMatch({notrack, #{}}, Expr).

%% notrack rule matches target port
test_notrack_matches(_) ->
    Pkt = nft_vm_pkt:udp(#{saddr => {10,0,0,1}}, #{dport => 53}),
    Rule = nft_rules:notrack_rule(53, udp),
    %% notrack is a side-effect, not a verdict
    {notrack, _} = nft_vm:eval_chain([Rule], Pkt, accept).
```

### Kernel Tests (`nft_notrack_SUITE`)

```erlang
%% Kernel: notrack rule in raw chain
kernel_notrack_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"raw">>,
            hook => prerouting, type => filter,
            priority => -300, policy => accept
        }, Seq) end
        | notrack_rule_funs(?TABLE, 53, udp)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"raw">>),
    ?assert(lists:any(fun has_notrack_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-11: FIB Lookups (Reverse-Path Filtering)

**Priority:** P2 — anti-spoofing

### What

Query the kernel routing table from within nftables rules. Primary use:
reverse-path filtering — verify that the source address of an incoming
packet would be routed back via the same interface. Detects spoofed IPs
at kernel speed, better than `rp_filter` sysctl because it's per-chain
and auditable.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `fib/3` exists — add `fib_rpf/0` convenience (saddr+iif->oif check) |
| Rules | `src/nft_rules.erl` | Add `fib_rpf_drop/0` — drop if reverse path check fails |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `rpf_check` macro |

### DSL Example

```elixir
defmodule HardenedServer do
  use ErlkoenigNft.Firewall

  firewall "hardened" do
    chain "prerouting", hook: :prerouting, priority: -150 do
      # Reverse-path filtering — drop spoofed source IPs
      rpf_check action: :drop
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      log_and_drop "BLOCKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% FIB RPF produces correct IR
test_fib_rpf_ir(_) ->
    Rule = nft_rules:fib_rpf_drop(),
    ?assert(lists:any(fun({fib, _}) -> true; (_) -> false end, Rule)).

%% FIB RPF with valid reverse path (simulated)
test_fib_rpf_valid(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80},
                          #{fib_result => valid}),
    Rule = nft_rules:fib_rpf_drop(),
    {break, _} = nft_vm:eval_chain([Rule], Pkt, accept).

%% FIB RPF with invalid reverse path (simulated)
test_fib_rpf_invalid(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80},
                          #{fib_result => invalid}),
    Rule = nft_rules:fib_rpf_drop(),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, accept).
```

### Kernel Tests (`nft_fib_SUITE`)

```erlang
%% Kernel: FIB rule applied with fib expression
kernel_fib_rpf(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"prerouting">>,
            hook => prerouting, type => filter,
            priority => -150, policy => accept
        }, Seq) end
        | fib_rpf_rule_funs(?TABLE)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"prerouting">>),
    ?assert(lists:any(fun has_fib_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-12: OS Fingerprinting

**Priority:** P2 — IoT/network segmentation

### What

Passive TCP SYN fingerprinting using the kernel's `osf` module.
Identifies the operating system from TCP options without active probing.
Uses the `pf.os` fingerprint database.

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `osf/1` exists — verify `#{ttl, flags}` params |
| Rules | `src/nft_rules.erl` | Add `osf_match/2` — match OS name and apply verdict |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `match_os` macro |

### DSL Example

```elixir
defmodule IoTFirewall do
  use ErlkoenigNft.Firewall

  firewall "iot_segment" do
    chain "inbound", hook: :input, policy: :drop do
      accept :established

      # Only allow Linux devices (IoT fleet) to access MQTT
      match_os "Linux", allow: [1883, 8883], proto: :tcp

      # Log and drop Windows devices trying to reach IoT services
      match_os "Windows", action: :log_and_drop, prefix: "WINDOWS-IOT: "

      log_and_drop "UNKNOWN-OS: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% OSF expression produces correct IR
test_osf_ir(_) ->
    Expr = nft_expr_ir:osf(0),
    ?assertMatch({osf, #{ttl := 0, dreg := _}}, Expr).

%% OSF match rule with simulated OS detection
test_osf_match_linux(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 1883, flags => syn},
                          #{osf_name => <<"Linux">>}),
    Rule = nft_rules:osf_match(<<"Linux">>, accept),
    {accept, _} = nft_vm:eval_chain([Rule], Pkt, drop).

test_osf_match_mismatch(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 1883, flags => syn},
                          #{osf_name => <<"Windows">>}),
    Rule = nft_rules:osf_match(<<"Linux">>, accept),
    {drop, _} = nft_vm:eval_chain([Rule], Pkt, drop).
```

### Kernel Tests (`nft_osf_SUITE`)

```erlang
%% Kernel: OSF rule applied with osf expression
kernel_osf_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => drop
        }, Seq) end
        | osf_rule_funs(?TABLE, <<"Linux">>, accept)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"input">>),
    ?assert(lists:any(fun has_osf_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-13: Packet Duplication (TEE)

**Priority:** P2 — traffic mirroring

### What

Clone packets and send copies to a monitoring host/interface. Enables
Erlang-driven traffic tapping: "mirror all SSH traffic to the SIEM",
"copy DNS queries to an analysis server".

### Implementation

| Layer | File | Change |
|-------|------|--------|
| IR | `src/nft_expr_ir.erl` | `dup/2` exists — verify `#{addr_reg, dev_reg}` |
| Rules | `src/nft_rules.erl` | Add `dup_to/2` — `(Addr, Device)` |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `mirror_to` macro |

### DSL Example

```elixir
defmodule MonitoredServer do
  use ErlkoenigNft.Firewall

  firewall "monitored" do
    chain "prerouting", hook: :prerouting, priority: -150 do
      # Mirror SSH traffic to SIEM at 10.0.0.200 via eth0
      mirror_to "10.0.0.200", device: "eth0", match: {22, :tcp}

      # Mirror all DNS queries to analysis host
      mirror_to "10.0.0.201", device: "eth0", match: {53, :udp}
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      accept_udp 53
      log_and_drop "BLOCKED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Dup expression produces correct IR
test_dup_ir(_) ->
    Rule = nft_rules:dup_to({10,0,0,200}, <<"eth0">>, 22, tcp),
    ?assert(lists:any(fun({dup, _}) -> true; (_) -> false end, Rule)).

%% Dup rule matches target port (dup is a side-effect, not a verdict)
test_dup_matches_port(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    Rule = nft_rules:dup_to({10,0,0,200}, <<"eth0">>, 22, tcp),
    %% dup does not consume the packet — chain continues
    Result = nft_vm:eval_chain([Rule], Pkt, accept),
    ?assertNotMatch({drop, _}, Result).
```

### Kernel Tests (`nft_dup_SUITE`)

```erlang
%% Kernel: dup rule applied with dup expression
kernel_dup_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => <<"prerouting">>,
            hook => prerouting, type => filter,
            priority => -150, policy => accept
        }, Seq) end
        | dup_rule_funs(?TABLE, {10,0,0,200}, <<"lo">>, 22, tcp)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = rules_for_chain(Items, <<"prerouting">>),
    ?assert(lists:any(fun has_dup_expr/1, Rules)),
    nfnl_server:stop(Pid).
```

---

## WP-14: Concatenated Sets

**Priority:** P2 — multi-dimensional matching

### What

Composite set keys combining multiple fields (e.g., IP + port) in a
single O(1) lookup. Enables fine-grained allowlists without rule
explosion:

    ip saddr . tcp dport { 10.0.0.1 . 22, 10.0.0.2 . 80 }

### Implementation

| Layer | File | Change |
|-------|------|--------|
| Sets | `src/nft_set.erl` | Support concatenated key types in set creation |
| IR | `src/nft_expr_ir.erl` | Add `concat/2` — concatenate multiple register values |
| Rules | `src/nft_rules.erl` | Add `concat_set_lookup/3` — `(SetName, [KeyExpr], Verdict)` |
| DSL | `dsl/lib/erlkoenig_nft/firewall.ex` | Add `set` with `:concat` type, `match_set` with multi-field keys |

### DSL Example

```elixir
defmodule GranularFirewall do
  use ErlkoenigNft.Firewall

  firewall "granular" do
    # Concatenated set: IP + port pairs
    set "allowed_services", {:concat, [:ipv4_addr, :inet_service]}

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Single O(1) lookup for IP+port combos
      accept_if_in_set "allowed_services", match: [:saddr, :tcp_dport]

      log_and_drop "DENIED: "
    end
  end
end
```

### VM Tests (`nft_vm_SUITE`)

```erlang
%% Concat expression produces correct IR
test_concat_ir(_) ->
    Exprs = nft_rules:concat_set_lookup(<<"allowed">>,
        [ip_saddr, tcp_dport], accept),
    ?assert(lists:any(fun({lookup, _}) -> true; (_) -> false end, Exprs)).

%% Concat set matches IP+port pair
test_concat_set_match(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    Sets = #{<<"allowed">> => [{<<10,0,0,1, 0,22>>}]},
    PktWithSets = nft_vm_pkt:with_sets(Pkt, Sets),
    Rule = nft_rules:concat_set_lookup(<<"allowed">>,
        [ip_saddr, tcp_dport], accept),
    {accept, _} = nft_vm:eval_chain([Rule], PktWithSets, drop).

%% Concat set misses wrong pair
test_concat_set_miss(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,2}}, #{dport => 22}),
    Sets = #{<<"allowed">> => [{<<10,0,0,1, 0,22>>}]},
    PktWithSets = nft_vm_pkt:with_sets(Pkt, Sets),
    Rule = nft_rules:concat_set_lookup(<<"allowed">>,
        [ip_saddr, tcp_dport], accept),
    {drop, _} = nft_vm:eval_chain([Rule], PktWithSets, drop).
```

### Kernel Tests (`nft_concat_SUITE`)

```erlang
%% Kernel: concatenated set created with correct key length
kernel_concat_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, concat_set_setup_msgs(?TABLE)),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Set] = [S || #{<<"set">> := S = #{<<"name">> := <<"allowed">>}} <- Items],
    %% Concatenated sets have "type" as a list in nft -j
    Type = maps:get(<<"type">>, Set),
    ?assert(is_list(Type) orelse Type =:= <<"concat">>),
    nfnl_server:stop(Pid).
```

---

## Summary

| WP | Feature | Priority | New files | Key dependency |
|----|---------|----------|-----------|----------------|
| 1 | Owner tables | P0 | — | Kernel 5.12+ |
| 2 | SYN proxy | P0 | `nft_synproxy_SUITE` | Kernel 5.3+, notrack |
| 3 | Meters | P0 | `nft_meter_SUITE` | dynset encoder |
| 4 | NFQUEUE | P0 | `nft_queue.erl`, `nft_queue_SUITE` | AF_NETLINK NFQUEUE |
| 5 | cgroupv2 | P1 | `nft_cgroup_SUITE` | Kernel 5.8+ |
| 6 | Verdict maps | P1 | `nft_vmap_SUITE` | Set MAP flag |
| 7 | Flowtables | P1 | `nft_flowtable.erl`, `nft_flowtable_SUITE` | Kernel 4.16+ |
| 8 | ct mark | P1 | `nft_ct_mark_SUITE` | ct encoder |
| 9 | Quotas | P1 | `nft_quota.erl`, `nft_quota_SUITE` | — |
| 10 | Notrack | P2 | `nft_notrack_SUITE` | Shared with WP-2 |
| 11 | FIB / RPF | P2 | `nft_fib_SUITE` | fib encoder |
| 12 | OS fingerprint | P2 | `nft_osf_SUITE` | pf.os database |
| 13 | Packet dup | P2 | `nft_dup_SUITE` | dup encoder |
| 14 | Concat sets | P2 | `nft_concat_SUITE` | Set concat flag |

### Dependency Graph

```
WP-10 (notrack) ──> WP-2 (synproxy)    [notrack is prerequisite]
WP-3  (meters)  ──> WP-5 (cgroupv2)    [meters + cgroups = per-service rate limits]
WP-6  (vmap)    ──> WP-8 (ct mark)     [vmap dispatch + mark tagging]
WP-7  (flowtable) standalone
WP-4  (nfqueue)    standalone           [most complex, start early]
WP-1  (owner)      standalone           [smallest, do first]
WP-9  (quotas)     standalone
WP-11 (fib)        standalone
WP-12 (osf)        standalone
WP-13 (dup)        standalone
WP-14 (concat)     standalone
```

### Recommended execution order

1. WP-1 (owner) — quick win, immediate operational benefit
2. WP-10 (notrack) + WP-2 (synproxy) — notrack first, synproxy builds on it
3. WP-3 (meters) — extends existing ct_guard naturally
4. WP-4 (nfqueue) — biggest differentiator, start early
5. WP-6 (vmap) — DSL expressiveness
6. WP-8 (ct mark) — cross-chain state
7. WP-7 (flowtable) — performance
8. WP-5 (cgroupv2) — per-service policies
9. WP-9 (quotas) — bandwidth management
10. WP-11..14 — as needed per use case
