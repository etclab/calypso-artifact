# Paper run — results

This directory holds the experimental outputs from the paper run.

## What is visible

The end-to-end CDF and percentile plots referenced from the paper are
left unpacked for direct inspection (PDF, EPS, and PNG renderings):

- `*-cdf-*.{pdf,eps,png}` — combined CDF plots (paper Figures 4, 5)
- `*-percentiles-*.{pdf,eps,png}` — percentile bar charts (paper Figure 6)

Filenames embed the approaches and a timestamp. The two most recent
combined plots correspond to the figures shipped in the paper:

- `plain-jwt-...-cdf-20251031-224821.pdf` — DoH (paper Figure 5)
- `plain-udp-jwt-udp-...-cdf-20251031-223728.pdf` — UDP (paper Figure 4)

## What is in `paper-run-data.zip`

Bundled to keep the directory listing manageable. Unzip in place to
restore:

```bash
unzip paper-run-data.zip
```

Contents:

- `*-trial-<n>-latencies.csv` — 10 trials per approach, raw per-query
  latencies
- `*-aggregated-cdf.csv` — CDF input used by the gnuplot scripts
- `*-aggregated-summary.txt` — percentiles with 95 % confidence
  intervals
- `*-aggregated.dat` — gnuplot-formatted summary
- `*-<timestamp>-summary.txt` — per-run summaries (one per trial)

## How to compare against fresh runs

Re-running the experiment pipeline (`experiments/run.sh compare …`)
writes new files into this directory using the same naming scheme.
Move or copy the existing files out first if you want to keep the
paper-run versions for diffing.
