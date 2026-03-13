#!/usr/bin/env elixir
#
# VPN Gateway / NAT Router
#
# WireGuard VPN gateway with NAT.
# Routes traffic between WireGuard clients and the internet.
# Masquerade (SNAT) for outgoing NAT. Multi-chain setup.

defmodule Firewall.VPNGateway do
  use ErlkoenigNft.Firewall

  firewall "vpngw" do
    counters [:ssh, :wg, :forwarded, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr

    # Drop banned before any processing
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    # Protect the gateway itself
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept_udp 51820, counter: :wg
      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "GW-DROP: ", counter: :dropped
    end

    # Route traffic for VPN clients
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      # Trust WireGuard interface (iifname_accept requires term-level)
      log_and_drop "GW-FWD-DROP: "
    end

    # Masquerade outgoing traffic
    chain "masq", hook: :postrouting, type: :nat, policy: :accept do
      # masq rule requires term-level config
    end
  end
end

defmodule Guard.VPNGateway do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 15, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.VPNGateway do
  use ErlkoenigNft.Watch

  watch :vpn do
    counter :ssh, :pps, threshold: 10
    counter :dropped, :pps, threshold: 100
    interval 2000
    on_alert :log
  end
end
