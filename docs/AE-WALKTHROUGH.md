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

**Expected:** CoreDNS+etcd start, a single DoH query for
`a.default.svc.cluster.local` resolves to a populated address, services
stop cleanly. Validates that the build is good and the simplest data path
works.

---

## Step 2 — Per-approach lifecycle (≈2 min total)

Start, query, stop one approach to verify each works in isolation:

```bash
cd experiments
./scripts/start.sh calypso
./build/q -i TXT verify.example.com @https://localhost:8443     # DoH lookup
./scripts/stop.sh calypso
```

Repeat for `jwt`, `wkdibe`. (Skip `enclave`/`enclave-jwt` if not on SGX.)

**Demonstrates:** the four cryptographic approaches from
§Implementation are individually exercisable. `calypso` will route via
EDNS option 65003 with a search-tag hash; logs in
`approaches/calypso/coredns.log` show the routing.

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

## Step 4 — Packet expansion (paper Table 1) (≈5 min)

See `misc/table1-reproduce.md` for the per-approach `q --measure-sizes`
invocations. Each prints `dns_req=N dns_resp=M` for one query; collating
across 4 approaches reproduces Table 1 columns.

**Demonstrates:** the cost of carrying the obfuscated name + ciphertext
in the EDNS OPT record relative to plain DNS.

---

## Step 5 — Microbenchmarks (paper Fig 3 + Table 2) (≈15 min)

```bash
# Calypso operations vs. number of labels
cd src/calypso
go test -bench=. -benchmem -run=^$ ./... > /tmp/calypso-bench.txt
python3 ../../misc/gen-microbench-dat.py /tmp/calypso-bench.txt > /tmp/calypso-bench.dat
gnuplot ../../experiments/scripts/plot/style.gpi  # optional — for inspection

# RSA-3072 baseline (paper Table 2)
cd ../cryptofun
go test -bench=. -benchmem -run=^$ ./... > /tmp/rsa-bench.txt
python3 ../../misc/gen-rsa-comparison.py /tmp/calypso-bench.txt /tmp/rsa-bench.txt
```

**Expected:** monotonically increasing crypto cost with label count
(matches Fig 3); RSA comparison table prints 5 rows whose ratio columns
should be in the same range as paper Table 2 (Encrypt: 40–60×, Verify:
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
