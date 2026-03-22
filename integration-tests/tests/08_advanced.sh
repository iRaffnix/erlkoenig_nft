#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_advanced"
assert_chain "test_advanced" "prerouting_filter" "prerouting"
assert_chain "test_advanced" "inbound" "input"
assert_counter "test_advanced" "ssh_counted"
assert_counter "test_advanced" "dropped"
assert_raw_contains '"fib"' "FIB expression present"
assert_raw_contains 'port_vmap' "verdict map referenced"
assert_raw_contains '": 22' "SSH port 22 present"
report "08 Advanced"
