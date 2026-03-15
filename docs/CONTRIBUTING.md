# Contributing to erlkoenig_nft

## Branch Model

| Branch | Purpose | Who pushes |
|--------|---------|------------|
| `main` | Stable, always releasable | Only via PR |
| `dev-*` | Working branches | Anyone, freely |
| `v*` tags | Releases | Only from `main` |

## Development Workflow

### 1. Work on a dev branch

```bash
git checkout -b dev-yourname
# ... hack, commit, push ...
git push origin dev-yourname
```

Every push triggers CI (`.github/workflows/ci.yml`):
- Erlang compile, common test, dialyzer
- Kernel tests (nftables, requires root in CI)
- Elixir DSL tests
- Release artifact build (x86_64-glibc, x86_64-musl)

### 2. Test CI artifacts before merging

```bash
# Find the latest CI run
gh run list --branch dev-yourname

# Download artifacts
gh run download <run-id> -D /tmp/artifacts

# Install from local artifacts
sudo sh install.sh --local /tmp/artifacts
```

### 3. Create a Pull Request

```bash
gh pr create --base main --title "Short description"
```

### 4. Tag a release

```bash
git checkout main
git pull origin main

# Bumps rebar.config, app.src, mix.exs, install.sh
make tag VERSION=0.6.0

# Push (triggers release.yml → GitHub Release)
git push origin main v0.6.0
```

## Install Script

```bash
# From GitHub Releases (production)
sudo sh install.sh --version v0.6.0

# From local CI artifacts (testing)
sudo sh install.sh --local /tmp/artifacts
```

**Never** instruct users to pipe curl into sh. The correct pattern is:

```bash
curl -fsSL -o install.sh https://github.com/iRaffnix/erlkoenig_nft/releases/latest/download/install.sh
less install.sh        # review first
sudo sh install.sh --version v0.6.0
```

## Setting up `gh` CLI

```bash
gh auth login
```

For private repos, the token needs `repo` and `actions:read` scopes.
For public repos, no special scopes are required.
