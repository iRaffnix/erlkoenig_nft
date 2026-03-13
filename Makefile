.PHONY: all erl dsl test test-dsl dialyzer check clean clean-erl clean-dsl \
       release install uninstall fetch-artifacts

PREFIX ?= /opt/erlkoenig_nft
RELEASE_DIR = _build/prod/rel/erlkoenig_nft

all: erl dsl

## Build ---------------------------------------------------------------

erl:
	rebar3 compile

dsl:
	cd dsl && mix compile

release: erl dsl
	cd dsl && mix escript.build
	rebar3 as prod release

## Test ----------------------------------------------------------------

test:
	rebar3 ct

test-dsl:
	cd dsl && mix test

dialyzer:
	rebar3 dialyzer

check: test dialyzer test-dsl

## Install / Uninstall -------------------------------------------------
##
## All owned files live under $(PREFIX).  System integration points
## (/etc/systemd, /etc/erlkoenig_nft) are symlinks back into $(PREFIX).

install: release
	@echo "Installing erlkoenig_nft to $(PREFIX) ..."
	install -d $(PREFIX)
	cp -rT $(RELEASE_DIR) $(PREFIX)
	chmod +x $(PREFIX)/bin/erlkoenig_nft_run
	## Config directory inside PREFIX (default search path for firewall.term)
	install -d $(PREFIX)/etc
	@if [ ! -e /etc/erlkoenig_nft ]; then \
		ln -s $(PREFIX)/etc /etc/erlkoenig_nft; \
		echo "Symlinked /etc/erlkoenig_nft -> $(PREFIX)/etc"; \
	else \
		echo "/etc/erlkoenig_nft already exists, skipping symlink."; \
	fi
	## Systemd unit — rendered from template, installed as symlink
	sed 's|@@PREFIX@@|$(PREFIX)|g' dist/erlkoenig_nft.service \
		> $(PREFIX)/dist/erlkoenig_nft.service
	@if [ ! -e /etc/systemd/system/erlkoenig_nft.service ]; then \
		ln -s $(PREFIX)/dist/erlkoenig_nft.service /etc/systemd/system/erlkoenig_nft.service; \
		systemctl daemon-reload; \
		echo "Symlinked systemd unit. Enable with: systemctl enable erlkoenig_nft"; \
	else \
		echo "Systemd unit already exists, skipping symlink."; \
	fi
	@echo ""
	@echo "All files are in $(PREFIX).  External paths are symlinks:"
	@echo "  /etc/erlkoenig_nft              -> $(PREFIX)/etc"
	@echo "  /etc/systemd/system/erlkoenig_nft.service -> $(PREFIX)/dist/erlkoenig_nft.service"
	@echo ""
	@echo "Start with: systemctl start erlkoenig_nft"

uninstall:
	@echo "Uninstalling erlkoenig_nft from $(PREFIX) ..."
	-systemctl stop erlkoenig_nft 2>/dev/null || true
	-systemctl disable erlkoenig_nft 2>/dev/null || true
	## Remove symlinks (only if they point into PREFIX)
	@if [ -L /etc/systemd/system/erlkoenig_nft.service ]; then \
		rm -f /etc/systemd/system/erlkoenig_nft.service; \
	fi
	@if [ -L /etc/erlkoenig_nft ]; then \
		rm -f /etc/erlkoenig_nft; \
	fi
	-systemctl daemon-reload 2>/dev/null || true
	rm -rf $(PREFIX)
	@echo "Uninstalled."

## Artifacts -----------------------------------------------------------
##
## Download release artifacts from the latest GitHub Actions run.
## Requires: gh CLI authenticated.
## Usage:  make fetch-artifacts
##         make fetch-artifacts RUN_ID=123456789

REPO ?= iRaffnix/erlkoenig_nft
ARTIFACT_DIR ?= out

fetch-artifacts:
	@mkdir -p $(ARTIFACT_DIR)
ifdef RUN_ID
	gh run download $(RUN_ID) -R $(REPO) -D $(ARTIFACT_DIR) --pattern 'release-*'
else
	gh run download -R $(REPO) -D $(ARTIFACT_DIR) --pattern 'release-*'
endif
	@echo "Artifacts downloaded to $(ARTIFACT_DIR)/"
	@ls -1 $(ARTIFACT_DIR)/*.tar.gz 2>/dev/null || echo "(no tarballs found — check run status)"

## Clean ---------------------------------------------------------------

clean: clean-erl clean-dsl

clean-erl:
	rebar3 clean
	rm -rf _build

clean-dsl:
	cd dsl && mix clean
	rm -rf dsl/_build
