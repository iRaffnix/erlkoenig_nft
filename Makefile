.PHONY: all erl dsl test test-dsl dialyzer check clean clean-erl clean-dsl \
       release install uninstall fetch-artifacts tag

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

## Release tagging -----------------------------------------------------
##
## Bump version in all files, commit, tag, and push.
## Usage:  make tag VERSION=0.6.0
##         make tag VERSION=0.6.0 MSG="Release notes here"

CURRENT_VERSION = $(shell grep -oP '(?<=\{release, \{erlkoenig_nft, ")[^"]+' rebar.config)
VERSION_FILES = rebar.config src/erlkoenig_nft.app.src dsl/mix.exs install.sh

tag:
ifndef VERSION
	$(error Usage: make tag VERSION=X.Y.Z)
endif
	@if ! echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "Error: VERSION must be semver (e.g., 0.6.0)" >&2; exit 1; \
	fi
	@BRANCH=$$(git branch --show-current); \
	if [ "$$BRANCH" != "main" ]; then \
		echo "Error: tags are only allowed from main (currently on $$BRANCH)" >&2; \
		echo "  git checkout main && git merge $$BRANCH && make tag VERSION=$(VERSION)" >&2; \
		exit 1; \
	fi
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working tree is dirty — commit or stash first" >&2; exit 1; \
	fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Error: tag v$(VERSION) already exists" >&2; exit 1; \
	fi
	@echo "Bumping version: $(CURRENT_VERSION) -> $(VERSION)"
	sed -i 's/{release, {erlkoenig_nft, "[^"]*"}/{release, {erlkoenig_nft, "$(VERSION)"}/' rebar.config
	sed -i 's/{vsn, "[^"]*"}/{vsn, "$(VERSION)"}/' src/erlkoenig_nft.app.src
	sed -i 's/version: "[^"]*"/version: "$(VERSION)"/' dsl/mix.exs
	sed -i 's/--version v[0-9]*\.[0-9]*\.[0-9]*/--version v$(VERSION)/' install.sh
	git add $(VERSION_FILES)
	git commit -m "chore: bump version to $(VERSION)"
	git tag -a "v$(VERSION)" -m "$(if $(MSG),$(MSG),v$(VERSION))"
	@echo ""
	@echo "Tagged v$(VERSION). Push with:"
	@echo "  git push origin main v$(VERSION)"

## Clean ---------------------------------------------------------------

clean: clean-erl clean-dsl

clean-erl:
	rebar3 clean
	rm -rf _build

clean-dsl:
	cd dsl && mix clean
	rm -rf dsl/_build
