# Miscellaneous scripts and docs

Small parsers and docs that bridge raw benchmark output to the figures and
tables in the paper.

## Contents

| File | Purpose | Produces |
|------|---------|----------|
| `gen-microbench-dat.py`     | Parse `go test -bench` output from `src/calypso` into the column layout expected by `plots/microbench.gpi`. | `calypso-bench.dat` (paper Fig 3) |
| `gen-rsa-comparison.py`     | Combine `go test -bench` output from `src/calypso` and `src/cryptofun` to emit the Calypso-vs-RSA table. | paper Table 2 |
| `measure-packet-sizes.sh`   | Per-approach driver that issues a single query through the `q` client and prints DNS message sizes. | paper Table 1 (one row per approach) |
| `table1-reproduce.md`       | Step-by-step instructions for reproducing paper Table 1 using the script above. | paper Table 1 |

## Workflow

```bash
# Microbench (paper Fig 3)
cd src/calypso
go test -bench=. -benchmem -run='^$' ./... > /tmp/calypso-bench.txt
python3 ../../misc/gen-microbench-dat.py /tmp/calypso-bench.txt > /tmp/calypso-bench.dat
# Plot with the gnuplot script from the paper sources, or inspect the .dat directly.

# RSA comparison (paper Table 2)
cd ../cryptofun
go test -bench=. -benchmem -run='^$' ./... > /tmp/rsa-bench.txt
python3 ../../misc/gen-rsa-comparison.py /tmp/calypso-bench.txt /tmp/rsa-bench.txt

# Packet expansion (paper Table 1) — see table1-reproduce.md
```

The parsers read benchmark output structurally, so they tolerate hardware
drift between runs. Absolute numbers will differ from the paper unless run
on the paper's reference hardware (Azure DC4s_v2); column structure and
relative ordering are stable.
