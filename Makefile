.PHONY: all erl dsl test test-dsl dialyzer check clean clean-erl clean-dsl

all: erl dsl

## Build ---------------------------------------------------------------

erl:
	rebar3 compile

dsl:
	cd dsl && mix compile

## Test ----------------------------------------------------------------

test:
	rebar3 ct

test-dsl:
	cd dsl && mix test

dialyzer:
	rebar3 dialyzer

check: test dialyzer test-dsl

## Clean ---------------------------------------------------------------

clean: clean-erl clean-dsl

clean-erl:
	rebar3 clean
	rm -rf _build

clean-dsl:
	cd dsl && mix clean
	rm -rf dsl/_build
