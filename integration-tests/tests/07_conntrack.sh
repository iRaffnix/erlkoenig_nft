#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_conntrack"
assert_chain "test_conntrack" "raw_prerouting" "prerouting"
assert_chain "test_conntrack" "inbound" "input"
assert_rule_expr "test_conntrack" "raw_prerouting" "notrack"
assert_raw_contains '": 53' "DNS port 53"
assert_raw_contains '": 123' "NTP port 123"
assert_counter "test_conntrack" "ssh_counted"
assert_counter "test_conntrack" "dns"
assert_counter "test_conntrack" "dropped"
assert_raw_contains '"ct"' "conntrack expression present"
assert_raw_contains '": 22' "SSH port 22 present"
report "07 Conntrack"
