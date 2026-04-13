# Artifact status

## Badges claimed

This artifact targets two SACMAT 2026 badges:

- **Functional** — the artifact builds and runs as documented; every
  approach (`plain`, `jwt`, `enclave`, `enclave-jwt`, `wkdibe`,
  `calypso`) is exercisable end-to-end.
- **Reusable** — authored components live under `src/` (libraries,
  CoreDNS plugins, build-time overlay, client tools); experiment
  orchestration lives under `experiments/`. Each subdirectory carries
  a `LICENSE` and a `README.md` (or `VERSION.md`) that explains its
  purpose, making the components individually reusable.

SACMAT 2026 does not offer a Reproduced/Replicated badge; absolute
benchmark numbers will drift from the paper unless rerun on equivalent
hardware (Azure DC4s_v2).

## Hardware requirement

Full evaluation of the artifact **requires an Intel SGX-capable Linux VM**
(e.g., Azure DC4s_v2 or DC4s_v3) so that the enclave-protected approaches
(`enclave`, `enclave-jwt`) can run alongside the others. The `ego`
framework is installed automatically by `setup-vm.sh -with-ego`.

If a reviewer is on non-SGX hardware, the four cryptographic approaches
without enclave dependence (`plain`, `jwt`, `wkdibe`, `calypso`, plus
their `-udp` variants) still build and run; only the two enclave
approaches will fail to start.

## Reviewer time budget

| Activity | Time |
|---|---|
| `setup-vm.sh` (Go install + workspace setup) | ~3 min |
| `use-vendored.sh` (clones CoreDNS + etcd, applies overlay) | ~1 min |
| `build-components.sh` (cold build of all components) | ~5 min |
| Smoke test (`run.sh test plain`) | ~10 s |
| Single approach end-to-end run (`run.sh bench calypso 300 20 1`) | ~3 min |
| Full comparison across 6 approaches (paper Fig 5 setup) | ~30 min |
| Microbench (`go test -bench` in `src/calypso`) | ~10 min |
| RSA comparison (`go test -bench` in `src/cryptofun`) | ~5 min |

A full reviewer pass following `docs/AE-WALKTHROUGH.md` takes
approximately **60 minutes of wall-clock time** including build.

## Notes for reviewers

1. **Network access required at first build.** `use-vendored.sh` clones
   upstream CoreDNS (v1.12.4) and etcd at their pinned versions; neither
   is bundled in `src/`.
2. **Mixed licenses.** Components are released under BSD-3-Clause
   (Calypso authored components), Apache-2.0 (CoreDNS), and GPL-3.0
   (the `q` DNS client). All are compatible for distribution; see
   `LICENSES/README.md` for the inventory.
3. **Pre-generated outputs in `experiments/results/`.** The directory
   ships with the paper's baked PDF/EPS figures (visible) and the raw
   CSVs (bundled in `paper-run-data.zip`). Re-running the pipeline
   writes new files into the same directory; copy out the paper-run
   files first if you want to diff before/after.
