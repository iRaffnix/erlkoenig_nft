defmodule Firewall.SetsAndBans do
  use ErlkoenigNft.Firewall

  firewall "test_sets" do
    set "blocklist", :ipv4_addr, elements: [
      "198.51.100.1",
      "203.0.113.5"
    ]
    set "allowlist", :ipv4_addr, elements: [
      "10.0.0.1",
      "10.0.0.2"
    ]
    set "blocklist6", :ipv6_addr
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist"
      drop_if_in_set "blocklist6"
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept :icmp
    end
  end
end
