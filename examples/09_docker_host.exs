#!/usr/bin/env elixir
#
# 9. Docker / Container Host
#
# Host running containers with published port ranges.
# Bridge network traffic trusted. Container ports exposed.
# Multi-chain: input + forward + postrouting NAT.

defmodule Firewall.DockerHost do
  use ErlkoenigNft.Firewall

  firewall "dockerhost" do
    counters [:ssh, :containers, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      # Trust docker bridge (iifname_accept requires term-level for named ifaces)
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # Container exposed ports
      accept_tcp_range 3000, 3010                       # web apps
      accept_tcp_range 5432, 5439                       # databases
      accept_tcp_range 6379, 6380                       # Redis

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "DOCKER-DROP: ", counter: :dropped
    end

    # Container routing
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      # Trust docker bridge (requires term-level iifname_accept)
      log_and_drop "DOCKER-FWD-DROP: "
    end

    # NAT for container outbound
    chain "masq", hook: :postrouting, type: :nat, policy: :accept do
      # masq rule requires term-level config
    end
  end
end

defmodule Guard.DockerHost do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 100, window: 10
    detect :port_scan, threshold: 25, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {172, 17, 0, 0}                           # docker network
  end
end

defmodule Watch.DockerHost do
  use ErlkoenigNft.Watch

  watch :docker do
    counter :ssh, :pps, threshold: 10
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
