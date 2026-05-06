# SACMAT 2026 AE Walkthrough — Calypso

A 30-minute guided tour for SACMAT artifact reviewers. Each step lists the
command, the expected observable result, and what it demonstrates from the
paper.

**Prerequisites:** an Ubuntu 24.04 VM (DC4s_v2 if you want to exercise the
SGX approach; any x86_64 VM otherwise). Run `INSTALL.md` first.

---

## Step 1 — Smoke test (≈10 s)

```bash
cd experiments
./run.sh test plain
```

**Expected:** CoreDNS+etcd start, the test record
`testservice.test.svc.cluster.local` is registered, a single DoH query
resolves it to `10.0.1.100`, and services stop cleanly. Validates that
the build is good and the simplest data path works.

---

## Step 2 — Per-approach lifecycle (≈2 min total)

Run the full lifecycle (start, insert test record, query, stop) for
each cryptographic approach:

```bash
cd experiments
./run.sh test calypso
./run.sh test jwt
./run.sh test wkdibe
```

(Skip `enclave`/`enclave-jwt` if not on SGX.)

**Expected:** each invocation resolves `testservice.test.svc.cluster.local`
to `10.0.1.100` and stops cleanly.

**Demonstrates:** the four cryptographic approaches from
§Implementation are individually exercisable. `calypso` routes via EDNS
option 65003 with a search-tag hash; the preserved log at
`approaches/calypso/coredns.log` shows the routing path.

---

## Step 3 — End-to-end latency comparison (≈10 min)

This reproduces the *shape* of paper Fig 5 (DoH CDF):

```bash
./run.sh compare plain jwt wkdibe calypso 300 20 1
```

Output: per-approach `<approach>-aggregated-cdf.csv` and a combined
CDF PDF, written to `experiments/results/`. Compare visually against
the paper-run copy at
`experiments/results/plain-jwt-...-cdf-20251031-224821.pdf`. Absolute
latencies will differ from the paper unless run on Azure DC4s_v2; the
relative ordering and curve shapes should match.

---

## Step 4 — Packet expansion (paper Table 3) (≈5 min)

See `misc/table1-reproduce.md` for the per-approach `q --measure-sizes`
invocations. Each prints `dns_req=N dns_resp=M` for one query; collating
across 4 approaches reproduces paper Table 3 (file name is historical:
this corresponds to "Table 1" in earlier drafts).

**Demonstrates:** the cost of carrying the obfuscated name + ciphertext
in the EDNS OPT record relative to plain DNS.

---

## Step 5 — Microbenchmarks (paper Fig 1 + Table 4) (≈15 min)

The Calypso library is the standalone module
[`github.com/etclab/calypso`](https://github.com/etclab/calypso); its
test-bench is what produces the Fig 1 numbers. Clone the `v0.1.0` tag
and run it directly:

```bash
ARTIFACT=$(pwd)   # run this from the artifact root

# Calypso operations vs. number of labels (paper Fig 1 source)
git clone --branch v0.1.0 --depth 1 https://github.com/etclab/calypso /tmp/calypso
cd /tmp/calypso
go test -bench=. -benchmem -run=^$ ./... > /tmp/calypso-bench.txt
python3 "$ARTIFACT/misc/gen-microbench-dat.py" /tmp/calypso-bench.txt > /tmp/calypso-bench.dat

# RSA-3072 baseline (paper Table 4)
cd "$ARTIFACT/src/cryptofun"
go test -bench=. -benchmem -run=^$ ./... > /tmp/rsa-bench.txt
python3 ../../misc/gen-rsa-comparison.py /tmp/calypso-bench.txt /tmp/rsa-bench.txt
```

**Expected:** monotonically increasing crypto cost with label count
(matches Fig 1); RSA comparison table prints 5 rows whose ratio columns
should be in the same range as paper Table 4 (Encrypt: 40–60×, Verify:
30–45×).

---

## Step 6 — Browse pre-existing results

`experiments/results/` ships with the paper run's outputs:

- The combined CDF and percentile plots (`*-cdf-*.{pdf,eps,png}`,
  `*-percentiles-*.{pdf,eps,png}`) are visible at the top of the
  directory.
- Raw per-trial CSVs, aggregated summaries, and gnuplot inputs are
  bundled into `paper-run-data.zip`. Unzip in place if needed:
  `unzip paper-run-data.zip`.

See `experiments/results/README.md` for the full inventory and
file-naming scheme. Reviewers may diff the baked outputs against
fresh runs to inspect variance.

---

## What you do *not* need to verify

- **Numerical match to paper.** Per `STATUS.md`, this artifact targets
  Functional + Reusable, not Reproduced. Hardware drift will move
  absolute numbers.
- **SGX results on non-SGX hardware.** Skip Steps 2/3 for `enclave*`
  approaches; everything else still works.

---

## Where to file issues with the artifact

Please leave comments on the artifact's HotCRP submission. The authors
monitor the AE discussion thread for the duration of the review period.
