#!/usr/bin/env python3
"""
Produce the Calypso-vs-RSA latency table (paper Table 2 /
tab:comp-calypso-rsa) from `go test -bench=.` output of two packages.

Inputs:
  - calypso-bench.txt  : raw output from `go test -bench=. -benchmem` in src/calypso
  - cryptofun-bench.txt: raw output from `go test -bench=. -benchmem` in src/cryptofun

Output (stdout): five rows -- IssueKey/KeyGen, Encrypt, Decrypt, Sign, Verify --
with Calypso times for 1-label and 10-label domains, RSA-3072 time, and the
overhead factor. All times reported in microseconds.

Usage:
  gen-rsa-comparison.py calypso-bench.txt cryptofun-bench.txt
"""
import re
import sys

LINE_RE = re.compile(r"^(?P<name>Benchmark\S+?)-\d+\s+\d+\s+(?P<ns>[\d.]+)\s+ns/op")

# Calypso benchmark name -> (paper row, labels)
CALYPSO_TARGETS = {
    "BenchmarkAuthority_IssueKey_reader_nonderivable/com":                     ("IssueKey", 1),
    "BenchmarkAuthority_IssueKey_reader_nonderivable/i.h.g.f.e.d.c.b.a.com":   ("IssueKey", 10),
    "Benchmark_encrypt/com":                                                   ("Encrypt", 1),
    "Benchmark_encrypt/i.h.g.f.e.d.c.b.a.com":                                 ("Encrypt", 10),
    "Benchmark_decrypt/com":                                                   ("Decrypt", 1),  # O(1)
    "Benchmark_sign/com":                                                      ("Sign", 1),
    "Benchmark_sign/i.h.g.f.e.d.c.b.a.com":                                    ("Sign", 10),
    "Benchmark_verify/com":                                                    ("Verify", 1),
    "Benchmark_verify/i.h.g.f.e.d.c.b.a.com":                                  ("Verify", 10),
}

# RSA benchmark names for 3072-bit key. Note the Decrypt inconsistency in
# cryptofun (uses RSADecrypt-3072 instead of keyLength:3072).
RSA_TARGETS = {
    "BenchmarkGenerateRSAKeyPair/keyLength:3072":     "IssueKey",
    "BenchmarkRSAEncrypt/keyLength:3072":             "Encrypt",
    "BenchmarkRSADecrypt/RSADecrypt-3072":            "Decrypt",
    "BenchmarkRSASignSHA256/keyLength:3072":          "Sign",
    "BenchmarkRSAVerifySHA256/keyLength:3072":        "Verify",
}

ROW_ORDER = ["IssueKey", "Encrypt", "Decrypt", "Sign", "Verify"]


def parse(path: str) -> dict:
    out = {}
    with open(path) as f:
        for raw in f:
            m = LINE_RE.match(raw.strip())
            if m:
                out[m.group("name")] = float(m.group("ns"))
    return out


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__ or "usage: gen-rsa-comparison.py CALYPSO RSA\n")
        return 2

    calypso = parse(sys.argv[1])
    cryptofun = parse(sys.argv[2])

    rows = {r: {"c1": None, "c10": None, "rsa": None} for r in ROW_ORDER}

    for name, ns in calypso.items():
        if name in CALYPSO_TARGETS:
            row, labels = CALYPSO_TARGETS[name]
            rows[row]["c1" if labels == 1 else "c10"] = ns

    for name, ns in cryptofun.items():
        if name in RSA_TARGETS:
            rows[RSA_TARGETS[name]]["rsa"] = ns

    # Emit table. Times in microseconds (ns / 1000).
    fmt = "{:<12} {:>12} {:>12} {:>12} {:>18}"
    print(fmt.format("Operation", "Calypso L=1", "Calypso L=10", "RSA-3072", "Overhead"))
    print("-" * 70)
    for row in ROW_ORDER:
        r = rows[row]
        c1_us = r["c1"] / 1000 if r["c1"] else None
        c10_us = r["c10"] / 1000 if r["c10"] else None
        rsa_us = r["rsa"] / 1000 if r["rsa"] else None

        c1_s = f"{c1_us:,.0f}" if c1_us else "N/A"
        c10_s = f"{c10_us:,.0f}" if c10_us else "N/A"
        rsa_s = f"{rsa_us:,.0f}" if rsa_us else "N/A"

        if rsa_us and c1_us and c10_us:
            lo = min(c1_us, c10_us) / rsa_us
            hi = max(c1_us, c10_us) / rsa_us
            overhead = f"{lo:.2f}x" if abs(lo - hi) < 0.01 else f"{lo:.2f}-{hi:.2f}x"
        elif rsa_us and c1_us:
            overhead = f"{c1_us / rsa_us:.2f}x"
        else:
            overhead = "N/A"

        print(fmt.format(row, c1_s, c10_s, rsa_s, overhead))

    return 0


if __name__ == "__main__":
    sys.exit(main())
