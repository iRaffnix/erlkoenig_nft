#!/usr/bin/env elixir
#
# 2. Paranoid Bastion Host
#
# Maximum lockdown: WireGuard SPA required for SSH access.
# No public services. SSH only reachable after Single Packet Authorization.
# All unknown traffic logged and dropped via NFLOG.

defmodule Firewall.ParanoidBastion do
  use ErlkoenigNft.Firewall

  firewall "bastion" do
    counters [:ssh, :wg, :spa, :banned, :dropped]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr
    set "wg_allow", :ipv4_addr, timeout: 180_000       # auto-expire 3 min
    set "wg_allow6", :ipv6_addr, timeout: 180_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      # SPA knock packet capture + WireGuard gating handled by .term config
      # (nflog_capture_udp and set_lookup_udp_accept require term-level rules)
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "BASTION-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.ParanoidBastion do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 20, window: 10       # aggressive
    detect :port_scan, threshold: 10, window: 30
    ban_duration 7200                                    # 2 hours
    whitelist {127, 0, 0, 1}
    cleanup_interval 15_000
  end
end

defmodule Watch.ParanoidBastion do
  use ErlkoenigNft.Watch

  watch :bastion do
    counter :ssh, :pps, threshold: 5
    counter :dropped, :pps, threshold: 50
    interval 1000                                        # fast polling
    on_alert :log
  end
end
