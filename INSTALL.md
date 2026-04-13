# Installation

## Hardware

| Configuration | Required for |
|---|---|
| Any x86_64 Linux VM with ≥4 vCPU and ≥16 GB RAM | All approaches *except* SGX/enclave |
| Intel SGX-capable VM (e.g., Azure DC4s_v2) | The enclave-based approaches (`enclave`, `enclave-jwt`) |

The paper uses **Azure DC4s_v2 (4 vCPU, 16 GB, Coffee Lake + SGX)** running
**Ubuntu 24.04.3 LTS**. Scripts are tested against this configuration.

## Software dependencies

Installed automatically by `setup-vm.sh`; listed here for reference.

| Package | Version | Notes |
|---|---|---|
| Go | 1.25.3 | https://go.dev/dl/ |
| GitHub CLI (`gh`) | latest | https://cli.github.com/ |
| CoreDNS | v1.12.4 | cloned by `use-vendored.sh` from `coredns/coredns` |
| etcd | v3.6.0-alpha snapshot @ `6f3e25b05` | cloned by `use-vendored.sh` from `etcd-io/etcd` |
| ego (only for SGX path) | latest matching Go 1.24+ | https://github.com/edgelesssys/ego |
| Python 3 + `matplotlib` | any recent | for `plot-percentiles.py` |
| gnuplot | any recent | for CDF plots and microbench figure |
| OpenSSL | any recent | for TLS cert generation |

## Install steps

From the artifact root:

```bash
# Installs Go 1.25.3 and gh; creates workspace dirs.
# Append -with-ego on an SGX-capable VM if you intend to run the enclave approach.
./experiments/scripts/setup-vm.sh

# Reload PATH in the current shell:
source ~/.bashrc

# Stage vendored sources under experiments/repos/. Clones upstream
# CoreDNS v1.12.4 and etcd, then applies the build-time overlay
# (registers our plugins, adds ego targets, injects extra deps).
./experiments/scripts/use-vendored.sh

# Build all components into experiments/build/.
./experiments/scripts/build-components.sh
```

After this, you should have:

```
experiments/build/
├── coredns
├── etcd
├── etcdctl
├── etcd-client
├── jwt-tools
└── q
```

## Verifying installation

```bash
cd experiments

# Smoke test on the simplest approach.
./run.sh test plain
```

A successful smoke test starts CoreDNS+etcd, issues a DoH query, prints the
response, and stops the services. If you see the resolved IP, the install
is good.

For per-approach starts and individual queries, see
`experiments/README.md` and `docs/AE-WALKTHROUGH.md`.
