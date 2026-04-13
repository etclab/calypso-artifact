#!/usr/bin/env python3
"""
Parse `go test -bench=. -benchmem` output from the calypso package
(`src/calypso/`) and emit the `calypso-bench.dat` table consumed by
plots/microbench.gpi.

Input:  raw benchmark output on stdin (or a file path as argv[1]).
Output: tab-separated .dat to stdout with columns:

    numlabels  createSearchTag  encrypt  decrypt  sign  verify  \
        issuekey_reader_nonderivable  derivekey_reader_one_wildcard

All time columns are ns/op. numlabels is the DNS label count of the
subtest's domain (e.g. "com" = 1, "a.com" = 2, ..., "i.h.g.f.e.d.c.b.a.com" = 10).

Usage:
    go test -bench=. -benchmem -run=^$ ./... | gen-microbench-dat.py > calypso-bench.dat
"""
import re
import sys

LINE_RE = re.compile(
    r"^(?P<name>Benchmark\S+?)-\d+\s+\d+\s+(?P<ns>[\d.]+)\s+ns/op"
)
DOMAIN_LABELS = [
    ("com", 1),
    ("a.com", 2),
    ("b.a.com", 3),
    ("c.b.a.com", 4),
    ("d.c.b.a.com", 5),
    ("e.d.c.b.a.com", 6),
    ("f.e.d.c.b.a.com", 7),
    ("g.f.e.d.c.b.a.com", 8),
    ("h.g.f.e.d.c.b.a.com", 9),
    ("i.h.g.f.e.d.c.b.a.com", 10),
]
LABEL_OF = dict(DOMAIN_LABELS)

COLUMNS = [
    "createSearchTag",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "issuekey_reader_nonderivable",
    "derivekey_reader_one_wildcard",
]

# Benchmark-name prefix -> column key.
PREFIX_MAP = {
    "Benchmark_createSearchTag/":                                "createSearchTag",
    "Benchmark_encrypt/":                                        "encrypt",
    "Benchmark_decrypt/":                                        "decrypt",
    "Benchmark_sign/":                                           "sign",
    "Benchmark_verify/":                                         "verify",
    "BenchmarkAuthority_IssueKey_reader_nonderivable/":          "issuekey_reader_nonderivable",
    "BenchmarkPrivateKey_DeriveKey_reader_one_wildcard/":        "derivekey_reader_one_wildcard",
}


def classify(name: str):
    """Return (column_key, numlabels) for a benchmark name, or None."""
    for prefix, col in PREFIX_MAP.items():
        if not name.startswith(prefix):
            continue
        tail = name[len(prefix):]
        # DeriveKey subtests look like "parent=*.X/child=Y". We want Y's labels.
        if "child=" in tail:
            tail = tail.split("child=", 1)[1]
        if tail in LABEL_OF:
            return col, LABEL_OF[tail]
        return None
    return None


def main() -> int:
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    # table[numlabels][column] = ns
    table = {n: {} for _, n in DOMAIN_LABELS}

    for raw in src:
        m = LINE_RE.match(raw.strip())
        if not m:
            continue
        hit = classify(m.group("name"))
        if hit is None:
            continue
        col, nlabels = hit
        table[nlabels][col] = float(m.group("ns"))

    # Check completeness and warn (but still emit what we have).
    missing = []
    for n in range(1, 11):
        for col in COLUMNS:
            if col not in table[n]:
                missing.append(f"  numlabels={n} col={col}")
    if missing:
        sys.stderr.write("warning: missing benchmark data:\n")
        sys.stderr.write("\n".join(missing) + "\n")

    # Emit .dat.
    header = ["numlabels"] + COLUMNS
    print("# " + "  ".join(header))
    print("# times are in ns; numlabels is number of DNS labels in domain name")
    for n in range(1, 11):
        row = [str(n)] + [
            f"{table[n].get(col, 0):.1f}" if col == "createSearchTag"
            else f"{int(table[n].get(col, 0))}"
            for col in COLUMNS
        ]
        print("\t".join(row))

    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
