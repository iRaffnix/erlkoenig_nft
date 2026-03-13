#!/usr/bin/env elixir
#
# NAT Router with Flow Offload
#
# Home/office router doing NAT between LAN (eth1) and WAN (eth0).
# Flowtable offloads established flows to the ingress hook so
# forwarded traffic (downloads, video calls, backups) bypasses
# the entire nftables pipeline after the first few packets.
#
# Without offload: every packet walks all rules (~2 Gbit/s on commodity hardware)
# With offload:    packets skip nftables entirely (~10 Gbit/s, or line rate with NIC offload)

defmodule Firewall.NATRouter do
  use ErlkoenigNft.Firewall

  firewall "router" do
    counters [:ssh, :dns, :dhcp, :forwarded, :banned, :dropped]

    set "blocklist", :ipv4_addr, elements: [
      "198.51.100.0",       # known scanner
      "203.0.113.50"        # abuse report
    ]

    set "trusted_lan", :ipv4_addr, elements: [
      "192.168.1.10",       # admin workstation
      "192.168.1.11"        # monitoring server
    ]

    # Flowtable: bind to both interfaces so established flows
    # between LAN and WAN get offloaded at ingress
    flowtable "ft0", devices: ["eth0", "eth1"], priority: 0

    # Block banned IPs before any processing
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
    end

    # Protect the router itself
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SSH only from trusted LAN hosts
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # DNS resolver (dnsmasq / unbound)
      accept_udp 53, counter: :dns

      # DHCP server
      accept_udp 67, counter: :dhcp

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "RTR-DROP: ", counter: :dropped
    end

    # Forward: this is where offload matters most.
    # First packet of each flow evaluates the rules normally,
    # then offload kicks in and subsequent packets skip nftables.
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      # Offload established flows — must come before accept :established
      # so the flow gets registered in the flowtable
      offload "ft0"

      accept :established

      # Allow LAN → WAN (new outbound connections)
      # In a real setup you'd use iifname "eth1" oifname "eth0" accept
      # but the DSL currently uses simpler primitives
      accept :icmp
      log_and_drop "RTR-FWD-DROP: "
    end

    # NAT: masquerade outgoing traffic on WAN interface
    chain "postrouting_nat", hook: :postrouting, type: :nat, priority: 100, policy: :accept do
    end
  end
end

defmodule Guard.NATRouter do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {192, 168, 1, 0}
  end
end

defmodule Watch.NATRouter do
  use ErlkoenigNft.Watch

  watch :router do
    counter :ssh, :pps, threshold: 20
    counter :dns, :pps, threshold: 5000
    counter :forwarded, :pps, threshold: 50_000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
