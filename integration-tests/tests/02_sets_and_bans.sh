#!/usr/bin/env bash
source "$(dirname "$0")/../lib/verify.sh"
reset_counters
RULESET=$(get_ruleset_json)
assert_table "test_sets"
assert_set "test_sets" "blocklist"
assert_set "test_sets" "allowlist"
assert_set "test_sets" "blocklist6"
assert_set_element "test_sets" "blocklist" "198.51.100.1"
assert_set_element "test_sets" "blocklist" "203.0.113.5"
assert_set_element "test_sets" "allowlist" "10.0.0.1"
assert_set_element "test_sets" "allowlist" "10.0.0.2"
assert_chain "test_sets" "prerouting_ban" "prerouting"
assert_chain "test_sets" "inbound" "input"
assert_raw_contains '@blocklist' "set lookup in prerouting"
assert_raw_contains '": 22' "SSH port 22 present"
report "02 Sets and Bans"
