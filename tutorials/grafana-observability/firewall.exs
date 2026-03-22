#!/usr/bin/env elixir
#
# OTel Integration Test Firewall
#
# Counters: ssh, icmp, dropped
# Loopback open (for OTLP on localhost:4318)
# SSH open, ICMP open+counted, rest dropped+counted

defmodule Firewall.OtelTest do
  use ErlkoenigNft.Firewall

  firewall "erlkoenig" do
    counters [:ssh, :icmp, :dropped]

    chain "input", hook: :input, priority: 0, policy: :drop do
      accept :established
      accept :loopback
      accept :icmp
      accept_protocol :icmpv6
      accept_tcp 22, counter: :ssh
      log_and_drop "DROP: ", counter: :dropped
    end
  end
end

defmodule Watch.OtelTest do
  use ErlkoenigNft.Watch

  watch :otel_test do
    counter :ssh, :pps, threshold: 100
    counter :icmp, :pps, threshold: 50
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
