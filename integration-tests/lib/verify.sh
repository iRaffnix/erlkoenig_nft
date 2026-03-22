#!/usr/bin/env bash
# Verify module: nft -j list ruleset → structured assertions.
# Source this file, don't execute it.

set -euo pipefail

REMOTE="${REMOTE:-erlkoenig-2__root}"
PASS=0
FAIL=0
ERRORS=""

# ── Core: Get Ruleset ───────────────────────────────────────────────

get_ruleset_json() {
    ssh "$REMOTE" "nft -j list ruleset" 2>/dev/null
}

# ── Assertions ──────────────────────────────────────────────────────
# All assertions take the ruleset JSON as first argument (or use global $RULESET).

# Check that a table with given name exists
assert_table() {
    local name="$1"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
tables = [o.get('table',{}).get('name','') for o in rs.get('nftables',[]) if 'table' in o]
sys.exit(0 if '$name' in tables else 1)
" 2>/dev/null; then
        pass "table '$name' exists"
    else
        fail "table '$name' NOT found"
    fi
}

# Check that a chain with given name and hook exists
assert_chain() {
    local table="$1" chain="$2" hook="$3"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    c = o.get('chain', {})
    if c.get('table') == '$table' and c.get('name') == '$chain' and c.get('hook') == '$hook':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "chain '$chain' (hook=$hook) in table '$table'"
    else
        fail "chain '$chain' (hook=$hook) NOT found in table '$table'"
    fi
}

# Check that a chain has a specific policy
assert_chain_policy() {
    local table="$1" chain="$2" policy="$3"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    c = o.get('chain', {})
    if c.get('table') == '$table' and c.get('name') == '$chain' and c.get('policy') == '$policy':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "chain '$chain' policy=$policy"
    else
        fail "chain '$chain' policy expected '$policy'"
    fi
}

# Check that a named set exists with given type
assert_set() {
    local table="$1" name="$2"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    s = o.get('set', {})
    if s.get('table') == '$table' and s.get('name') == '$name':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "set '$name' in table '$table'"
    else
        fail "set '$name' NOT found in table '$table'"
    fi
}

# Check that a set contains a specific element
assert_set_element() {
    local table="$1" name="$2" element="$3"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    s = o.get('set', {})
    if s.get('table') == '$table' and s.get('name') == '$name':
        elems = s.get('elem', [])
        for e in elems:
            val = e.get('elem',{}).get('val','') if isinstance(e, dict) else e
            if str(val) == '$element':
                sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "set '$name' contains '$element'"
    else
        fail "set '$name' does NOT contain '$element'"
    fi
}

# Check that a named counter object exists
assert_counter() {
    local table="$1" name="$2"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    c = o.get('counter', {})
    if c.get('table') == '$table' and c.get('name') == '$name':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "counter '$name' in table '$table'"
    else
        fail "counter '$name' NOT found in table '$table'"
    fi
}

# Check that a rule contains a specific expression type (e.g., "limit", "log", "counter")
assert_rule_expr() {
    local table="$1" chain="$2" expr_type="$3"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    r = o.get('rule', {})
    if r.get('table') == '$table' and r.get('chain') == '$chain':
        for e in r.get('expr', []):
            if '$expr_type' in e:
                sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "rule in '$chain' has expression '$expr_type'"
    else
        fail "no rule in '$chain' with expression '$expr_type'"
    fi
}

# Check total number of rules in a chain
assert_rule_count() {
    local table="$1" chain="$2" expected="$3"
    local actual
    actual=$(echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
count = sum(1 for o in rs.get('nftables', [])
            if 'rule' in o and o['rule'].get('table') == '$table'
            and o['rule'].get('chain') == '$chain')
print(count)
" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        pass "chain '$chain' has $expected rules"
    else
        fail "chain '$chain' has $actual rules, expected $expected"
    fi
}

# Check that a quota object exists
assert_quota() {
    local table="$1" name="$2"
    if echo "$RULESET" | python3 -c "
import json, sys
rs = json.load(sys.stdin)
for o in rs.get('nftables', []):
    q = o.get('quota', {})
    if q.get('table') == '$table' and q.get('name') == '$name':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "quota '$name' in table '$table'"
    else
        fail "quota '$name' NOT found in table '$table'"
    fi
}

# Check that nft -j output contains a specific string (raw grep)
assert_raw_contains() {
    local pattern="$1" desc="$2"
    if echo "$RULESET" | grep -q "$pattern"; then
        pass "$desc"
    else
        fail "$desc (pattern '$pattern' not found)"
    fi
}

# ── Reporting ───────────────────────────────────────────────────────

pass() {
    PASS=$((PASS + 1))
    echo "    PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    ERRORS="${ERRORS}\n    FAIL: $1"
    echo "    FAIL: $1" >&2
}

report() {
    local test_name="$1"
    echo ""
    echo "  ── $test_name: $PASS passed, $FAIL failed ──"
    if [ "$FAIL" -gt 0 ]; then
        echo -e "$ERRORS" >&2
        return 1
    fi
}

reset_counters() {
    PASS=0
    FAIL=0
    ERRORS=""
}
