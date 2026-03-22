defmodule Firewall.Advanced do
  use ErlkoenigNft.Firewall

  firewall "test_advanced" do
    counters [:ssh_counted, :http, :https, :dropped]

    # Verdict map: dispatch ports to verdicts
    vmap "port_vmap", :inet_service, entries: [
      {80, :accept},
      {443, :accept},
      {53, :accept}
    ]
    chain "prerouting_filter", hook: :prerouting, priority: -200, policy: :accept do
      rpf_check()
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 2222, counter: :ssh_counted
      dispatch :tcp, "port_vmap"
      accept :icmp
      log_and_drop_nflog "ADV-DROP: ", group: 1, counter: :dropped
    end
  end
end
