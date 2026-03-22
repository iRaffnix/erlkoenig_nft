#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_ratelimit"
assert_chain "test_ratelimit" "inbound" "input"
assert_counter "test_ratelimit" "ssh_counted"
assert_counter "test_ratelimit" "api"
assert_counter "test_ratelimit" "dropped"
assert_rule_expr "test_ratelimit" "inbound" "limit"
assert_rule_expr "test_ratelimit" "inbound" "log"
assert_raw_contains '": 22' "SSH port 22 present"
report "03 Rate Limiting"
