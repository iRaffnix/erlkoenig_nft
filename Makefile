.PHONY: all erl dsl test test-dsl dialyzer check clean clean-erl clean-dsl \
       release install uninstall fetch-artifacts tag \
       fmt fmt-check xref lint eunit

PREFIX ?= /opt/erlkoenig_nft
SERVICE_USER ?= erlkoenig
RELEASE_DIR = _build/prod/rel/erlkoenig_nft

all: erl dsl

## Build ---------------------------------------------------------------

erl:
	rebar3 compile

dsl:
	cd dsl && mix compile

release: erl dsl
	cd dsl && mix escript.build
	rebar3 as prod tar

## Quality -------------------------------------------------------------

fmt:
	rebar3 fmt

fmt-check:
	rebar3 fmt --check

xref:
	rebar3 xref

dialyzer:
	rebar3 dialyzer

lint: fmt-check xref dialyzer

## Test ----------------------------------------------------------------

eunit:
	rebar3 eunit

test:
	rebar3 ct

test-dsl:
	cd dsl && mix test

check: lint eunit test test-dsl

## Install / Uninstall -------------------------------------------------
##
## All owned files live under $(PREFIX).  System integration points
## (/etc/systemd, /etc/erlkoenig_nft) are symlinks back into $(PREFIX).

install: release
	@echo "Installing to $(PREFIX) ..."
	@# Service user (idempotent)
	id -u $(SERVICE_USER) >/dev/null 2>&1 || \
		useradd --system --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER)
	@# Extract release
	mkdir -p $(PREFIX)
	tar xzf $(RELEASE_DIR)/erlkoenig_nft-*.tar.gz -C $(PREFIX)
	@# Ownership: root owns files, service user can read
	chown -R root:$(SERVICE_USER) $(PREFIX)
	chmod 750 $(PREFIX)
	@# Install cookie-aware wrapper (rename relx script to _release)
	mv $(PREFIX)/bin/erlkoenig_nft $(PREFIX)/bin/_release
	cp bin/erlkoenig_nft_wrapper.sh $(PREFIX)/bin/erlkoenig_nft
	chmod 755 $(PREFIX)/bin/erlkoenig_nft
	chmod 755 $(PREFIX)/bin/_release
	@[ -f $(PREFIX)/bin/erlkoenig ] && chmod 755 $(PREFIX)/bin/erlkoenig || true
	chmod 644 $(PREFIX)/dist/erlkoenig_nft.service
	@# Security: strict file ownership in releases/<vsn>/
	@# vm.args.src = root-owned template (read-only for service user)
	@# vm.args     = service-user-owned (relx rewrites at every start)
	@# directory   = service-user-writable (vm.args creation target)
	@REL_VSN_DIR=$$(ls -d $(PREFIX)/releases/*/start.boot 2>/dev/null | head -1 | xargs dirname 2>/dev/null); \
	if [ -n "$$REL_VSN_DIR" ]; then \
		chown $(SERVICE_USER):$(SERVICE_USER) "$$REL_VSN_DIR"; \
		chmod 750 "$$REL_VSN_DIR"; \
		[ -f "$$REL_VSN_DIR/vm.args.src" ] && chown root:$(SERVICE_USER) "$$REL_VSN_DIR/vm.args.src" && chmod 440 "$$REL_VSN_DIR/vm.args.src"; \
		touch "$$REL_VSN_DIR/vm.args" && chown $(SERVICE_USER):$(SERVICE_USER) "$$REL_VSN_DIR/vm.args" && chmod 640 "$$REL_VSN_DIR/vm.args"; \
		[ -f "$$REL_VSN_DIR/sys.config" ] && chown root:$(SERVICE_USER) "$$REL_VSN_DIR/sys.config" && chmod 440 "$$REL_VSN_DIR/sys.config"; \
	fi
	@# Config directory (firewall.term search path)
	mkdir -p $(PREFIX)/etc
	chown $(SERVICE_USER):$(SERVICE_USER) $(PREFIX)/etc
	@if [ ! -e /etc/erlkoenig_nft ]; then \
		ln -s $(PREFIX)/etc /etc/erlkoenig_nft; \
		echo "  Symlinked /etc/erlkoenig_nft -> $(PREFIX)/etc"; \
	fi
	@# Cookie (first install only)
	@if [ ! -f $(PREFIX)/cookie ]; then \
		head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > $(PREFIX)/cookie; \
		echo "  Cookie generated"; \
	fi
	chown root:$(SERVICE_USER) $(PREFIX)/cookie
	chmod 440 $(PREFIX)/cookie
	@# Fix escript shebang to use bundled ERTS
	@ERTS_BIN=$$(ls -d $(PREFIX)/erts-*/bin 2>/dev/null | head -1); \
	if [ -n "$$ERTS_BIN" ] && [ -f $(PREFIX)/bin/erlkoenig ]; then \
		sed -i "1s|.*|#!$$ERTS_BIN/escript|" $(PREFIX)/bin/erlkoenig; \
		echo "  CLI shebang: $$ERTS_BIN/escript"; \
	fi
	@# Systemd symlink
	@if [ -d /etc/systemd/system ]; then \
		ln -sf $(PREFIX)/dist/erlkoenig_nft.service /etc/systemd/system/erlkoenig_nft.service; \
		systemctl daemon-reload; \
		echo "  Systemd unit symlinked"; \
	fi
	@# Hostname check
	@if ! getent hosts "$$(hostname -s)" >/dev/null 2>&1; then \
		echo ""; \
		echo "  WARNING: hostname '$$(hostname -s)' not resolvable."; \
		echo "  Add to /etc/hosts: 127.0.0.1 $$(hostname -s)"; \
		echo "  Distribution will not work without this."; \
		echo ""; \
	fi
	@echo ""
	@echo "Done. Next steps:"
	@echo "  1. Verify hostname:  getent hosts $$(hostname -s)"
	@echo "  2. Test foreground:  $(PREFIX)/bin/erlkoenig_nft foreground"
	@echo "  3. Start service:    sudo systemctl start erlkoenig_nft"
	@echo "  4. Check status:     $(PREFIX)/bin/erlkoenig_nft eval 'erlkoenig_nft:status()'"

uninstall:
	@echo "Uninstalling erlkoenig_nft ..."
	-systemctl stop erlkoenig_nft 2>/dev/null || true
	-systemctl disable erlkoenig_nft 2>/dev/null || true
	rm -f /etc/systemd/system/erlkoenig_nft.service
	@if [ -L /etc/erlkoenig_nft ]; then \
		rm -f /etc/erlkoenig_nft; \
	fi
	-systemctl daemon-reload 2>/dev/null || true
	rm -rf $(PREFIX)
	@echo "Done. Note: User '$(SERVICE_USER)' not removed. Run: userdel $(SERVICE_USER)"

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
