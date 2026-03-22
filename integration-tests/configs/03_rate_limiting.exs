defmodule Firewall.RateLimiting do
  use ErlkoenigNft.Firewall

  firewall "test_ratelimit" do
    counters [:ssh_counted, :api, :dropped]
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 2222, counter: :ssh_counted, limit: {10, burst: 3}
      accept_tcp 80, counter: :api
      accept :icmp
      log_and_drop "RATE-DROP: ", counter: :dropped
    end
  end
end
