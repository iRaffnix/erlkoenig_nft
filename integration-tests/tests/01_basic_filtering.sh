#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)

assert_table "test_basic"
assert_chain "test_basic" "inbound" "input"
assert_chain_policy "test_basic" "inbound" "drop"
assert_raw_contains '": 22'   "SSH port 22 accept"
assert_raw_contains '": 80'   "HTTP port 80 accept"
assert_raw_contains '": 443'  "HTTPS port 443 accept"
assert_raw_contains '": 53'   "DNS port 53 UDP accept"
assert_raw_contains '"range"' "port range expression present"
assert_raw_contains '"reject"' "reject expression present"
assert_raw_contains '"icmp"'  "ICMP accept rule present"

report "01 Basic Filtering"
