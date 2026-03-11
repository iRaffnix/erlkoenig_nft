defmodule ErlkoenigNft.FirewallDslTest do
  use ExUnit.Case, async: true

  defmodule WebFirewall do
    use ErlkoenigNft.Firewall

    firewall "web" do
      counters [:ssh, :dropped]
      set "blocklist", :ipv4_addr, timeout: 3600

      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :icmp
        accept_tcp 22, counter: :ssh, limit: {5, burst: 2}
        accept_tcp [80, 443]
        drop_if_in_set "blocklist", counter: :dropped
        log_and_drop "BLOCKED: "
      end
    end
  end

  defmodule MinimalFirewall do
    use ErlkoenigNft.Firewall

    firewall "minimal" do
      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :loopback
      end
    end
  end

  defmodule WorkerFirewall do
    use ErlkoenigNft.Firewall

    firewall "worker" do
      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :icmp
        accept_udp 53
        accept :all
      end
    end
  end

  defmodule NflogFirewall do
    use ErlkoenigNft.Firewall

    firewall "nflog" do
      counters [:ssh, :banned, :dropped]
      set "blocklist", :ipv4_addr
      set "allowlist", :ipv4_addr, timeout: 300_000

      chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
        drop_if_in_set "blocklist", counter: :banned
      end

      chain "input", hook: :input, policy: :drop do
        accept :established
        accept :loopback
        accept_udp_if_in_set "allowlist", 51820
        accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
        accept :icmp
        log_and_drop_nflog "DROP: ", group: 0, counter: :dropped
      end
    end
  end

  describe "DSL compilation" do
    test "WebFirewall compiles with all features" do
      term = WebFirewall.config()
      assert is_map(term)
      assert length(term.chains) == 1
      assert term.counters == ["ssh", "dropped"]
      assert length(term.sets) == 1
    end

    test "WebFirewall chain has correct rules" do
      term = WebFirewall.config()
      [chain] = term.chains
      assert chain.name == "inbound"
      assert chain.hook == :input
      assert chain.policy == :drop

      rules = chain.rules
      assert hd(rules) == :ct_established_accept
      assert Enum.at(rules, 1) == :icmp_accept
      assert {:tcp_accept_limited, 22, "ssh", %{rate: 5, burst: 2}} in rules
      assert {:tcp_accept, 80} in rules
      assert {:tcp_accept, 443} in rules
    end

    test "WebFirewall has set with timeout" do
      term = WebFirewall.config()
      [set] = term.sets
      assert elem(set, 0) == "blocklist"
      assert elem(set, 1) == :ipv4_addr
    end

    test "MinimalFirewall has only established + loopback" do
      term = MinimalFirewall.config()
      [chain] = term.chains
      assert chain.rules == [:ct_established_accept, {:iifname_accept, "lo"}]
    end

    test "WorkerFirewall matches old hardcoded default" do
      term = WorkerFirewall.config()
      [chain] = term.chains

      assert chain.rules == [
               :ct_established_accept,
               :icmp_accept,
               {:udp_accept, 53},
               :accept
             ]
    end

    test "NflogFirewall has accept_udp_if_in_set rule" do
      term = NflogFirewall.config()
      input = Enum.find(term.chains, &(&1.name == "input"))
      assert {:set_lookup_udp_accept, "allowlist", 51820} in input.rules
    end

    test "NflogFirewall has log_drop_nflog rule" do
      term = NflogFirewall.config()
      input = Enum.find(term.chains, &(&1.name == "input"))
      assert {:log_drop_nflog, "DROP: ", 0, "dropped"} in input.rules
    end

    test "NflogFirewall rule order is preserved" do
      term = NflogFirewall.config()
      input = Enum.find(term.chains, &(&1.name == "input"))
      rules = input.rules
      udp_idx = Enum.find_index(rules, &match?({:set_lookup_udp_accept, _, _}, &1))
      tcp_idx = Enum.find_index(rules, &match?({:tcp_accept_limited, 22, _, _}, &1))
      nflog_idx = Enum.find_index(rules, &match?({:log_drop_nflog, _, _, _}, &1))
      assert udp_idx < tcp_idx
      assert tcp_idx < nflog_idx
    end

    test "NflogFirewall has set with timeout" do
      term = NflogFirewall.config()
      allow_set = Enum.find(term.sets, fn
        {"allowlist", _, _} -> true
        _ -> false
      end)
      assert {"allowlist", :ipv4_addr, %{flags: [:timeout], timeout: 300_000}} = allow_set
    end

    test "write! produces file" do
      path = Path.join(System.tmp_dir!(), "nft_dsl_test_#{:rand.uniform(100000)}.term")
      WebFirewall.write!(path)
      assert File.exists?(path)
      content = File.read!(path)
      assert content =~ "inbound"
      File.rm!(path)
    end
  end
end
