defmodule Firewall.Conntrack do
  use ErlkoenigNft.Firewall

  firewall "test_conntrack" do
    counters [:ssh_counted, :dns, :dropped]
    # Raw prerouting: bypass conntrack for DNS/NTP
    chain "raw_prerouting", hook: :prerouting, priority: -300, policy: :accept do
      notrack 53, :udp
      notrack 123, :udp
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 2222, counter: :ssh_counted
      accept_udp 53, counter: :dns
      accept_udp 123
      accept :icmp
      log_and_drop "CT-DROP: ", counter: :dropped
    end
  end
end
