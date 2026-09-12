# wolfTrust CI

Three tiers, modeled on wolfProvider's CI: a fast per-PR lane, a heavy
nightly M33MU lane, and label-selected opt-in for pulling M33MU coverage
onto a PR before merge.

## At a glance

| Tier | Trigger | Purpose |
|------|---------|---------|
| **Fast (per-PR)** | every PR; push to master/main/dev/churn | host unit suites (one check each), Arm PSA-FF conformance, cross-compile (Cortex-M33, and the AArch64 EL3 smoke on QEMU virt/versal-virt), compiler matrix, sanitizers, valgrind, integrations, core/port split guard |
| **Nightly M33MU** | `cron: 0 8 * * *`, or `workflow_dispatch` | full M33MU emulator matrix — 11 concurrent jobs (see below) |
| **PR opt-in** | add a `ci:*` label to a PR | run one M33MU scenario, or the whole matrix, on the PR branch |

The heavy M33MU workflow (`stm32h563-build.yml`) does **not** run on
`pull_request` — PRs stay fast. It runs on push to `master`/`main`/
`wolfTrust-dev`, on the nightly schedule (via `nightly.yml`), and by
label opt-in.

## Nightly M33MU matrix (11 concurrent jobs)

`nightly.yml` calls `stm32h563-build.yml` (workflow name **M33MU**), which
fans out into one named check per test — each renders as `M33MU / <name>`:

| Check name | Label key | What it proves |
|------------|-----------|----------------|
| `M33MU / wolfBoot signed boot and rollback` | — | upstream wolfBoot signed boot + update/rollback |
| `M33MU / wolfTrust zephyr lifecycle` | — | full FF-M chain, Zephyr guest |
| `M33MU / wolfTrust freertos lifecycle` | — | full FF-M chain, FreeRTOS guest |
| `M33MU / Positive lifecycle` | `ci:positive` | lifecycle green, no faults |
| `M33MU / Guest restart recovery` | `ci:restart` | guest faults → monitor restarts it |
| `M33MU / Cross-domain isolation (L3)` | `ci:crossdomain` | SP-internal probe read blocked |
| `M33MU / FF-M IPC conformance (85/4)` | `ci:confboot` | full Arm FF-M IPC suite |
| `M33MU / dev_apis Storage (s001-s017)` | `ci:devstorage` | PSA ITS/PS conformance |
| `M33MU / dev_apis Crypto (c001-c080)` | `ci:devcrypto` | PSA Crypto conformance |
| `M33MU / Vault recovery self-heal` | `ci:vaultrecover` | #95 foreign pool reformatted |
| `M33MU / Vault recovery fail-closed` | `ci:vaultrecoversec` | #95 SECURED never wipes |

The three lifecycle/wolfBoot builds are reachable on a PR via `ci:m33mu` /
`ci:all` (the whole workflow); the 8 scenarios each have their own label.

`nightly.yml` also runs the fast lane + `core-port-split`.

## Running M33MU on a PR (label opt-in)

`pr-m33mu-select.yml` pulls heavy M33MU onto a PR without editing code:

| Label | Effect |
|-------|--------|
| `ci:<scenario>` | run that one scenario on the PR branch (`ci:devcrypto`, `ci:vaultrecoversec`, …). Add several to run several. |
| `ci:m33mu` / `ci:all` | run the full heavy workflow (both lifecycles + all 8 scenarios) on the PR branch. |
| (no label) | nothing runs — a normal PR is unaffected. |

`<scenario>` is one of the 8 label keys in the table above. The dispatcher fires
only on label change; re-add a label to re-run after a push, then drop
the labels when done — nothing to revert in the tree.

Off-PR equivalent (runs against a branch, no labels):

```bash
gh workflow run pr-m33mu-select.yml --ref <branch> -f jobs="positive devcrypto"
gh workflow run pr-m33mu-select.yml --ref <branch> -f jobs="all"
```

The local box gate `run_m33mu.sh` (a Zephyr+FreeRTOS lifecycle) and the
`make test-target` loop remain the pre-push mirror of the M33MU jobs.

## Host unit suites (per-suite checks)

`unit-tests.yml` reads `UNIT_SUITES` from `tests/host/Makefile` (via
`make -s -C tests/host print-suites`) and fans out one check per suite —
`Unit tests / ffm`, `Unit tests / spm`, `Unit tests / crypto_service`, …
Adding a suite to `UNIT_SUITES` makes it a new CI check automatically; no
workflow edit. The compiler matrix, sanitizers, and valgrind keep running
the aggregate `make test` (one job per compiler/tool) to bound job count.
