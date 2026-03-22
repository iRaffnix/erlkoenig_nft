#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_logging"
assert_chain "test_logging" "inbound" "input"
assert_counter "test_logging" "dropped"
assert_rule_expr "test_logging" "inbound" "log"
assert_raw_contains '"reject"' "reject expression present"
assert_raw_contains 'REJECT' "REJECT prefix in log"
assert_raw_contains '": 22' "SSH port 22 present"
report "05 Logging"
