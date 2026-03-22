#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_nat"
assert_chain "test_nat" "postrouting_nat" "postrouting"
assert_chain "test_nat" "inbound" "input"
assert_rule_expr "test_nat" "postrouting_nat" "masq"
assert_raw_contains '": 22' "SSH port 22 present"
report "04 NAT"
