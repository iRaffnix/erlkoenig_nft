#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_counters"
assert_chain "test_counters" "inbound" "input"
assert_counter "test_counters" "ssh_counted"
assert_counter "test_counters" "http"
assert_counter "test_counters" "https"
assert_counter "test_counters" "dns"
assert_counter "test_counters" "dropped"
assert_raw_contains '"counter"' "counter references in rules"
assert_raw_contains '": 22' "SSH port 22"
assert_raw_contains '": 80' "HTTP port 80"
assert_raw_contains '": 443' "HTTPS port 443"
assert_raw_contains '": 53' "DNS port 53"
assert_rule_expr "test_counters" "inbound" "log"
report "06 Counters"
