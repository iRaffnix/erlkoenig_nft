#!/usr/bin/env elixir
#
# Default Firewall
#
# Empty accept-all table with counters and blocklist sets.
# Like a fresh nft ruleset — all traffic passes, but ban/unban
# works immediately via the prerouting blocklist lookup.
#
# Use this as a starting point, then switch to a real config
# with: erlkoenig apply <your_config.exs>

defmodule Firewall.Default do
  use ErlkoenigNft.Firewall

  firewall "erlkoenig" do
    counters [:input, :forward, :output, :dropped, :banned]
    set "blocklist", :ipv4_addr
    set "blocklist6", :ipv6_addr

    # Drop banned IPs before they hit any chain
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "input", hook: :input, policy: :accept do
    end

    chain "forward", hook: :forward, policy: :accept do
    end

    chain "output", hook: :output, policy: :accept do
    end
  end
end
