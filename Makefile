# emberpool developer tasks. Run on the Linux host (or the dev VM), from the repo root.
# `make` with no target lists them.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# --- Paths and versions (override on the command line: make vm-test FC_DIR=/opt/fc) ---
FC_VERSION ?= v1.18.0
ARCH       := $(shell uname -m)
FC_DIR     ?= $(HOME)/fc
KERNEL     ?= $(FC_DIR)/Image
ROOTFS     ?= $(FC_DIR)/ep-exec-rootfs.ext4
JAIL_BASE  ?= /srv/jailer
PREFIX     ?= ep
TEST_PREFIX ?= ep-test

# A private venv per checkout, so tests never import another checkout's code.
VENV ?= $(or $(UV_PROJECT_ENVIRONMENT),$(CURDIR)/.venv)
UV   := UV_PROJECT_ENVIRONMENT=$(VENV) uv
# Root runs reuse the user's venv, never sync and never write bytecode as root.
SUDO_UV := sudo env PATH="$$PATH" UV_PROJECT_ENVIRONMENT=$(VENV) PYTHONDONTWRITEBYTECODE=1 uv run --no-sync

# Settings for the library (see docs/20-api.md).
EP_ENV := EMBERPOOL_FIRECRACKER=$(FC_DIR)/firecracker EMBERPOOL_JAILER=$(FC_DIR)/jailer \
          EMBERPOOL_KERNEL=$(KERNEL) EMBERPOOL_ROOTFS=$(ROOTFS) \
          EMBERPOOL_JAIL_BASE=$(JAIL_BASE) EMBERPOOL_PREFIX=$(PREFIX)
# Inputs for the vm-marked tests.
TEST_ENV := EMBERPOOL_TEST_PREFIX=$(TEST_PREFIX) EMBERPOOL_FC_DIR=$(FC_DIR) EMBERPOOL_TEST_ROOTFS=$(ROOTFS)

PYTEST_ARGS ?=
CODE    ?= print(1 + 1)
NETWORK ?= deny
TIMEOUT ?= 30

.PHONY: help setup check install firecracker rootfs test vm-test test-all run \
        firewall-show firewall-allow leftovers clean distclean

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'
	@echo
	@echo "  Variables: FC_DIR=$(FC_DIR) ROOTFS=$(ROOTFS) PREFIX=$(PREFIX) TEST_PREFIX=$(TEST_PREFIX) VENV=$(VENV)"

# --- Setup -------------------------------------------------------------------

setup: install firecracker check ## Install deps, fetch Firecracker, check the host
	@echo "Next: put the guest kernel at $(KERNEL), then 'make rootfs'."

check: ## Check the host has what emberpool needs (read-only)
	@ok=1; \
	[ "$$(uname -s)" = Linux ] || { echo "missing: Linux host"; ok=0; }; \
	[ -e /dev/kvm ] || { echo "missing: /dev/kvm"; ok=0; }; \
	for t in uv ip nft e2fsck debugfs dumpe2fs setpriv cp mkfs.ext4; do \
	  command -v $$t >/dev/null || { echo "missing tool: $$t"; ok=0; }; done; \
	for f in $(FC_DIR)/firecracker $(FC_DIR)/jailer; do \
	  [ -x $$f ] || { echo "missing: $$f (make firecracker)"; ok=0; }; done; \
	[ -f $(KERNEL) ] || { echo "missing: $(KERNEL) (6.1 guest kernel, see docs/10-setup.md)"; ok=0; }; \
	[ -f $(ROOTFS) ] || { echo "missing: $(ROOTFS) (make rootfs)"; ok=0; }; \
	if [ $$ok = 1 ]; then echo "host OK"; else exit 1; fi

install: ## Create the venv and install emberpool with dev dependencies
	$(UV) sync

firecracker: ## Put Firecracker and the jailer in FC_DIR (downloads only if needed; never overwrites)
	@set -euo pipefail; mkdir -p $(FC_DIR); \
	rel=$(FC_DIR)/release-$(FC_VERSION)-$(ARCH); tmp=""; \
	if [ ! -d $$rel ] && { [ ! -x $(FC_DIR)/firecracker ] || [ ! -x $(FC_DIR)/jailer ]; }; then \
	  tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	  curl -fsSL -o $$tmp/fc.tgz https://github.com/firecracker-microvm/firecracker/releases/download/$(FC_VERSION)/firecracker-$(FC_VERSION)-$(ARCH).tgz; \
	  tar -xzf $$tmp/fc.tgz -C $$tmp; rel=$$tmp/release-$(FC_VERSION)-$(ARCH); fi; \
	for b in firecracker jailer; do \
	  if [ -x $(FC_DIR)/$$b ]; then echo "keep:    $(FC_DIR)/$$b"; \
	  else install -m 0755 $$rel/$$b-$(FC_VERSION)-$(ARCH) $(FC_DIR)/$$b; echo "install: $(FC_DIR)/$$b"; fi; done; \
	$(FC_DIR)/firecracker --version | head -1

rootfs: ## Build the guest image with the agent (needs root and docker)
	sudo scripts/build-rootfs.sh $(ROOTFS)

# --- Tests -------------------------------------------------------------------

test: ## Unit tests (no root; vm tests skip)
	EMBERPOOL_TEST_PREFIX=$(TEST_PREFIX) $(UV) run pytest -q $(PYTEST_ARGS)

vm-test: ## Only the vm-marked tests, as root (boots real VMs)
	$(SUDO_UV) env $(TEST_ENV) pytest -q -p no:cacheprovider -m vm $(PYTEST_ARGS)
	@$(MAKE) --no-print-directory leftovers

test-all: ## Every test, as root
	$(SUDO_UV) env $(TEST_ENV) pytest -q -p no:cacheprovider $(PYTEST_ARGS)
	@$(MAKE) --no-print-directory leftovers

# --- Run ---------------------------------------------------------------------

run: ## Run CODE in a fresh sandbox, as root: make run CODE='print(2)' NETWORK=allow:pypi.org
	$(SUDO_UV) env $(EP_ENV) python scripts/run.py '$(CODE)' '$(NETWORK)' '$(TIMEOUT)'

# --- Host firewall (Docker hosts) --------------------------------------------

firewall-show: ## Show the DOCKER-USER chain
	sudo iptables -S DOCKER-USER

firewall-allow: ## Let PREFIX's sandbox uplinks through Docker's firewall (changes the host)
	@for d in -i -o; do \
	  sudo iptables -C DOCKER-USER $$d $(PREFIX)-h+ -j ACCEPT 2>/dev/null || \
	  sudo iptables -I DOCKER-USER $$d $(PREFIX)-h+ -j ACCEPT; done
	sudo iptables -S DOCKER-USER

# --- Cleanup -----------------------------------------------------------------

leftovers: ## List resources a run may have left behind (read-only)
	@ls /tmp/fc-*.sock 2>/dev/null || true
	@ip netns list 2>/dev/null | grep -E '^ep' || true
	@ip -br link 2>/dev/null | grep -E '^ep' || true
	@sudo nft list tables 2>/dev/null | grep -E ' (ep|emberpool)' || true
	@pgrep -a firecracker || true
	@echo "leftover check done (nothing listed above = clean)"

clean: ## Remove caches and build artifacts in the repo
	find . -path ./.git -prune -o -type d \( -name __pycache__ -o -name .pytest_cache \
	  -o -name .mypy_cache -o -name .ruff_cache -o -name '*.egg-info' \) -prune -exec rm -rf {} +
	rm -rf build dist

distclean: clean ## Also remove the venv
	rm -rf $(VENV)
