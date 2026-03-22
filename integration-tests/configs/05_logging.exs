defmodule Firewall.Logging do
  use ErlkoenigNft.Firewall

  firewall "test_logging" do
    counters [:ssh_counted, :dropped]
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 80
      log_and_reject "REJECT: "
      log_and_drop_nflog "NFLOG-DROP: ", group: 1, counter: :dropped
    end
  end
end
