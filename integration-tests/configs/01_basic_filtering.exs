defmodule Firewall.BasicFiltering do
  use ErlkoenigNft.Firewall

  firewall "test_basic" do

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 80
      accept_tcp 443
      accept_udp 53
      accept_tcp_range 8000, 8100
      reject_tcp 23
      accept :icmp
      accept_protocol :icmpv6
    end
  end
end
