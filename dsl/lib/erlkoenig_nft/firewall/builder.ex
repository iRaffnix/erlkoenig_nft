#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule ErlkoenigNft.Firewall.Builder do
  @moduledoc """
  Pure functional builder for firewall configurations.

  Accumulates DSL calls into a map that can be serialized to an
  Erlang term compatible with `erlkoenig_nft`.
  """

  # --- Constructor ---

  def new(name \\ "default", opts \\ [])

  def new(name, opts) when is_binary(name) and is_list(opts) do
    owner = Keyword.get(opts, :owner, false)
    %{name: name, owner: owner, sets: [], vmaps: [], counters: [], quotas: [],
      chains: [], flowtables: [], rules_acc: []}
  end

  # --- Sets ---

  def add_set(state, name, type) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    update_in(state, [:sets], &(&1 ++ [{name, type}]))
  end

  def add_set(state, name, type, opts) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    timeout = Keyword.get(opts, :timeout)
    elements = Keyword.get(opts, :elements)

    meta =
      %{}
      |> then(fn m -> if timeout, do: Map.merge(m, %{flags: [:timeout], timeout: timeout}), else: m end)
      |> then(fn m -> if elements, do: Map.put(m, :elements, elements), else: m end)

    case meta do
      m when m == %{} -> update_in(state, [:sets], &(&1 ++ [{name, type}]))
      m -> update_in(state, [:sets], &(&1 ++ [{name, type, m}]))
    end
  end

  @doc """
  Add a concatenated set. Fields is a list of type atoms.

  Example:
      add_concat_set(state, "allowpairs", [:ipv4_addr, :inet_service])
  """
  def add_concat_set(state, name, fields) when is_binary(name) and is_list(fields) do
    update_in(state, [:sets], &(&1 ++ [{name, :concat, %{fields: fields}}]))
  end

  def add_concat_set(state, name, fields, opts) when is_binary(name) and is_list(fields) do
    timeout = Keyword.get(opts, :timeout)
    base = %{fields: fields}
    meta = if timeout, do: Map.merge(base, %{flags: [:timeout], timeout: timeout}), else: base
    update_in(state, [:sets], &(&1 ++ [{name, :concat, meta}]))
  end

  # --- Verdict Maps ---

  @doc """
  Add a verdict map with initial entries.

  Entries is a list of {key, verdict} tuples where verdict is
  :accept, :drop, {:jump, chain}, or {:goto, chain}.

  In the DSL, keyword syntax is used: {80, jump: "http_chain"}
  """
  def add_vmap(state, name, type, opts) when is_binary(name) and is_list(opts) do
    entries = Keyword.fetch!(opts, :entries)
    normalized = Enum.map(entries, &normalize_vmap_entry/1)
    vmap = %{name: name, type: type, entries: normalized}
    update_in(state, [:vmaps], &(&1 ++ [vmap]))
  end

  defp normalize_vmap_entry({key, [jump: chain]}), do: {key, {:jump, chain}}
  defp normalize_vmap_entry({key, [goto: chain]}), do: {key, {:goto, chain}}
  defp normalize_vmap_entry({key, :accept}), do: {key, :accept}
  defp normalize_vmap_entry({key, :drop}), do: {key, :drop}
  defp normalize_vmap_entry({key, verdict}), do: {key, verdict}

  # --- Counters ---

  def add_counters(state, names) when is_list(names) do
    %{state | counters: state.counters ++ Enum.map(names, &to_string/1)}
  end

  # --- Quotas ---

  def add_quota(state, name, bytes, opts \\ []) when is_binary(name) and is_integer(bytes) do
    mode = Keyword.get(opts, :mode, :until)
    flags = if mode == :over, do: 1, else: 0
    quota = %{name: name, bytes: bytes, flags: flags}
    update_in(state, [:quotas], &(&1 ++ [quota]))
  end

  # --- Chains ---

  def add_chain(state, name, opts, rules) when is_binary(name) and is_list(rules) do
    chain = %{
      name: name,
      hook: Keyword.fetch!(opts, :hook),
      type: Keyword.get(opts, :type, :filter),
      priority: Keyword.get(opts, :priority, 0),
      policy: Keyword.fetch!(opts, :policy),
      rules: rules
    }

    update_in(state, [:chains], &(&1 ++ [chain]))
  end

  # --- Rule constructors ---

  def ct_established_accept, do: :ct_established_accept
  def icmp_accept, do: :icmp_accept
  def accept, do: :accept

  def tcp_accept(port) when is_integer(port), do: {:tcp_accept, port}

  def tcp_accept(port, opts) when is_integer(port) and is_list(opts) do
    counter = Keyword.get(opts, :counter)
    limit = Keyword.get(opts, :limit)
    build_tcp_accept(port, counter, limit)
  end

  defp build_tcp_accept(port, nil, nil), do: {:tcp_accept, port}
  defp build_tcp_accept(port, counter, nil), do: {:tcp_accept, port, to_string(counter)}

  defp build_tcp_accept(port, counter, {rate, burst_opts}) do
    burst = if is_list(burst_opts), do: Keyword.fetch!(burst_opts, :burst), else: burst_opts
    c = if counter, do: to_string(counter), else: "tcp_#{port}"
    {:tcp_accept_limited, port, c, %{rate: rate, burst: burst}}
  end

  def tcp_port_range_accept(from, to_port), do: {:tcp_port_range_accept, from, to_port}
  def tcp_reject(port), do: {:tcp_reject, port}

  def udp_accept(port) when is_integer(port), do: {:udp_accept, port}

  def udp_accept(port, opts) when is_integer(port) and is_list(opts) do
    case Keyword.get(opts, :counter) do
      nil -> {:udp_accept, port}
      counter -> {:udp_accept, port, to_string(counter)}
    end
  end

  def udp_port_range_accept(from, to_port), do: {:udp_port_range_accept, from, to_port}

  def protocol_accept(proto), do: {:protocol_accept, proto}

  def ip_saddr_accept(ip), do: {:ip_saddr_accept, ip}
  def ip_saddr_drop(ip), do: {:ip_saddr_drop, ip}

  def iifname_accept(name), do: {:iifname_accept, name}

  def set_lookup_drop(set_name), do: {:set_lookup_drop, set_name}
  def set_lookup_drop(set_name, counter), do: {:set_lookup_drop, set_name, to_string(counter)}

  def connlimit_drop(max), do: {:connlimit_drop, max, 0}
  def connlimit_drop(max, offset), do: {:connlimit_drop, max, offset}

  def log_drop(prefix), do: {:log_drop, prefix}
  def log_drop(prefix, counter), do: {:log_drop, prefix, to_string(counter)}

  def log_reject(prefix), do: {:log_reject, prefix}

  def fib_rpf_drop, do: :fib_rpf_drop

  def synproxy_filter(port, opts) when is_integer(port) and is_list(opts) do
    mss = Keyword.get(opts, :mss, 1460)
    wscale = Keyword.get(opts, :wscale, 7)
    ts = if Keyword.get(opts, :timestamp, false), do: 1, else: 0
    sack = if Keyword.get(opts, :sack_perm, false), do: 2, else: 0
    {:synproxy, port, mss, wscale, Bitwise.bor(ts, sack)}
  end

  def nflog_capture_udp(port, prefix, group), do: {:nflog_capture_udp, port, prefix, group}
  def set_lookup_udp_accept(set_name, port), do: {:set_lookup_udp_accept, set_name, port}
  def log_drop_nflog(prefix, group, counter), do: {:log_drop_nflog, prefix, group, to_string(counter)}

  def notrack_rule(port, proto), do: {:notrack, port, proto}

  def meter_limit(name, port, proto, opts) when is_binary(name) and is_integer(port) do
    {:meter_limit, name, port, proto, opts}
  end

  def queue_rule(port, proto, opts), do: {:queue_rule, port, proto, opts}

  def cgroup_accept(cgroup_id), do: {:cgroup_accept, cgroup_id}
  def cgroup_drop(cgroup_id), do: {:cgroup_drop, cgroup_id}
  def ct_mark_set(value) when is_integer(value), do: {:ct_mark_set, value}
  def ct_mark_match(value, verdict) when is_integer(value), do: {:ct_mark_match, value, verdict}
  def osf_match(os_name, verdict), do: {:osf_match, os_name, verdict}

  def dnat(ip, port), do: {:dnat, ip, port}

  def vmap_dispatch(proto, vmap_name) when proto in [:tcp, :udp] and is_binary(vmap_name) do
    {:vmap_dispatch, proto, vmap_name}
  end

  # --- Flowtables ---

  def add_flowtable(state, name, opts) when is_binary(name) and is_list(opts) do
    ft = %{
      name: name,
      hook: Keyword.get(opts, :hook, :ingress),
      priority: Keyword.get(opts, :priority, 0),
      devices: Keyword.get(opts, :devices, []),
      flags: Keyword.get(opts, :flags, 0)
    }

    update_in(state, [:flowtables], &(&1 ++ [ft]))
  end

  def flow_offload(flowtable_name) when is_binary(flowtable_name) do
    {:flow_offload, flowtable_name}
  end
  def concat_set_lookup(set_name, fields, verdict),
    do: {:concat_set_lookup, set_name, fields, verdict}

  def accept_if_in_concat_set(set_name, fields),
    do: {:concat_set_lookup, set_name, fields, :accept}

  def drop_if_in_concat_set(set_name, fields),
    do: {:concat_set_lookup, set_name, fields, :drop}

  # --- Rule accumulator (used by chain macro) ---

  def push_rule(state, rule) do
    update_in(state, [:rules_acc], &(&1 ++ [rule]))
  end

  def take_rules(state) do
    {state.rules_acc, %{state | rules_acc: []}}
  end

  # --- Serialization ---

  def to_term(state) do
    base = %{
      table: state.name,
      chains: Enum.map(state.chains, &chain_to_term/1)
    }

    base = if state.owner, do: Map.put(base, :owner, true), else: base
    base = if state.sets != [], do: Map.put(base, :sets, state.sets), else: base
    base = if state.vmaps != [], do: Map.put(base, :vmaps, state.vmaps), else: base
    base = if state.counters != [], do: Map.put(base, :counters, state.counters), else: base
    base = if state.flowtables != [], do: Map.put(base, :flowtables, state.flowtables), else: base
    base = if state.quotas != [], do: Map.put(base, :quotas, state.quotas), else: base
    base
  end

  def write!(state, path) do
    term = to_term(state)
    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(path, formatted)
  end

  defp chain_to_term(chain) do
    %{
      name: chain.name,
      hook: chain.hook,
      type: chain.type,
      priority: chain.priority,
      policy: chain.policy,
      rules: chain.rules
    }
  end
end
