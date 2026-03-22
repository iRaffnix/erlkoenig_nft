defmodule Firewall.Counters do
  use ErlkoenigNft.Firewall

  firewall "test_counters" do
    counters [:ssh_counted, :http, :https, :dns, :dropped]
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 2222, counter: :ssh_counted
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
      accept_udp 53, counter: :dns
      accept :icmp
      log_and_drop "DROP: ", counter: :dropped
    end
  end
end
