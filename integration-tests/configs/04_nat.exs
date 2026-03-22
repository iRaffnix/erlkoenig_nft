defmodule Firewall.NAT do
  use ErlkoenigNft.Firewall

  firewall "test_nat" do

    # Masquerade outbound traffic
    chain "postrouting_nat", hook: :postrouting, type: :nat, priority: 100, policy: :accept do
      masquerade()
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept :icmp
    end
  end
end
