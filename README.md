# Calypso — SACMAT 2026 Artifact

Companion artifact for the paper *"Calypso: Zero-Trust Service Discovery
with Cryptographic Name Hiding"* (SACMAT 2026).

## Authors

- Pankaj Niroula  — `pniroula@wm.edu` (corresponding)
- Peyton Boggs    — `prboggs@wm.edu`
- Aashutosh Poudel — `apoudel01@wm.edu`
- Stephen Herwig  — `smherwig@wm.edu`

William & Mary, Department of Computer Science.

Calypso extends zero-trust data-plane protections to cloud-based service
discovery by hiding both DNS record contents and service names. The directory
(CoreDNS + etcd) is treated as untrusted, storing only ciphertexts and
RSA-based salted hashes. This artifact ships the full implementation,
evaluation orchestration, and the paper's raw data.

## Layout

```
.
├── README.md                  # this file
├── INSTALL.md                 # dependencies and setup
├── STATUS.md                  # badge claims, known limitations
├── docs/
│   └── AE-WALKTHROUGH.md      # 30-minute reviewer tour
├── src/
│   ├── plugins/               # the 3 authored CoreDNS plugins
│   │   ├── jwt_edns/          # JWT-over-OPT authorization
│   │   ├── etcd_crypto/       # AES (enclave) + WKD-IBE decryption
│   │   └── etcd_calypso/      # search-tag-based routing for Calypso
│   ├── coredns-overlay/       # files copied/appended onto upstream CoreDNS at build time
│   ├── q/                     # patched DNS client (--measure-sizes, granular timing)
│   ├── cryptofun/             # RSA-3072 baseline benchmarks (paper Table 4)
│   ├── etcd-client/           # etcd record-registration + key-provisioning tool
│   └── jwt-tools/             # JWT generator (EdDSA, ES256, RS256)
│
│   The core WKD-IBE + Calypso Go library is the standalone module
│   github.com/etclab/calypso (pinned to v0.1.0 in each consumer's
│   go.mod), published independently for reuse outside this artifact.
│
│   At build time, use-vendored.sh clones upstream CoreDNS v1.12.4 and
│   etcd, applies the overlay, and copies the plugins into the CoreDNS
│   plugin/ tree. The vendored sources are not modified upstream code.
├── experiments/               # benchmark orchestration
│   ├── scripts/               # setup, build, start/stop, bench, plot
│   ├── approaches/            # per-approach CoreDNS configs (plain, jwt, enclave, wkdibe, calypso)
│   ├── results/               # paper's baked plots (visible) + raw CSVs (zipped)
│   └── run.sh                 # main entry point: bench, compare, test
└── misc/                      # helpers for paper figures and tables
    ├── gen-microbench-dat.py  # parses go-test bench output → paper Fig 3 input
    ├── gen-rsa-comparison.py  # combines bench output → paper Table 4
    ├── measure-packet-sizes.sh # one-shot per-approach driver → paper Table 3
    └── table1-reproduce.md    # step-by-step paper Table 3 reproduction notes
```

## Quickstart

On a fresh Ubuntu 24.04 VM (or a confidential VM if the SGX/enclave
approach is needed):

```bash
# 1. Set up Go and shell environment
./experiments/scripts/setup-vm.sh

# 2. Stage vendored sources, fetch upstream CoreDNS v1.12.4 + etcd,
#    and apply the build-time overlay
./experiments/scripts/use-vendored.sh

# 3. Build all components (coredns, calypso, q, etcd, etcd-client, jwt-tools)
./experiments/scripts/build-components.sh

# 4. Smoke test: end-to-end latency comparison across two approaches
cd experiments && ./run.sh compare plain calypso 100 10 1
```

To include the SGX/enclave approach, append `-with-ego` to the setup and
build steps.

For the step-by-step tour see `docs/AE-WALKTHROUGH.md`. A printable
overview of the artifact (badges claimed, paper-to-code mapping,
walkthrough) is at `docs/artifact-doc/artifact.pdf`; rebuild from the
`.tex` source with `make` in that directory.

## What this artifact reproduces

| Paper artifact | Source |
|---|---|
| Table 3 — Packet expansion | `misc/measure-packet-sizes.sh`; see `misc/table1-reproduce.md` |
| Fig 1 — Microbench crypto latency | `misc/gen-microbench-dat.py` + `experiments/results/...` (raw) |
| Table 4 — Calypso vs RSA-3072 | `misc/gen-rsa-comparison.py` |
| Fig 2 — End-to-end CDF (UDP) | `experiments/run.sh compare plain-udp jwt-udp ...` |
| Fig 3 — End-to-end CDF (DoH) | `experiments/run.sh compare plain jwt enclave-jwt wkdibe calypso ...` |
| Fig 4 — Latency percentiles | `experiments/scripts/plot/plot-percentiles.py` |

## Badges

This artifact is submitted for SACMAT's **Functional** and **Reusable**
badges. See `STATUS.md` for what is claimed and what is not.
