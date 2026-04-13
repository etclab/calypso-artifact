# Reproducing Table 1 — DNS Packet Expansion

Table 1 in the paper reports DNS request and response sizes for four
approaches: **Normal** (plain DoH), **JWT**, **JEDI** (WKD-IBE), and
**Calypso**. Sizes are deterministic — no averaging is needed; one
query per approach is sufficient.

## Prerequisites

After running the standard install steps (`setup-vm.sh`,
`use-vendored.sh`, `build-components.sh`):

- The `q` binary at `experiments/build/q` supports the
  `--measure-sizes` flag.
- For each approach, CoreDNS and etcd must be running and etcd must
  contain the test record. The walkthrough's per-approach lifecycle
  (Step 2 in `docs/AE-WALKTHROUGH.md`) covers this:

  ```bash
  cd experiments
  ./scripts/start.sh <approach>
  ```

  Use `./scripts/stop.sh <approach>` between approaches.

- Test record (already populated by the start script for each
  approach):
  - Domain: `a.default.svc.cluster.local`
  - Record type: `A`

- Per-approach secrets (generated under
  `experiments/approaches/<approach>/` by the start script — paths
  shown below assume that layout).

## Run

Run the measurement script once per approach. The script lives at
`misc/measure-packet-sizes.sh` and invokes the `q` binary from
`experiments/build/q` (override with `Q_BIN=…` if needed).

```bash
cd misc

# 1. Normal — plain DoH baseline.
./measure-packet-sizes.sh plain

# 2. JWT — JWT-authorized DoH.
JWT_TOKEN=$(cat ../experiments/approaches/jwt/jwt.token) \
  ./measure-packet-sizes.sh jwt

# 3. JEDI — WKD-IBE.
WKDIBE_PARAMS=../experiments/approaches/wkdibe/wkdibe.params \
WKDIBE_KEY=../experiments/approaches/wkdibe/wkdibe.key \
  ./measure-packet-sizes.sh wkd-ibe

# 4. Calypso.
CALYPSO_PARAMS=../experiments/approaches/calypso/calypso.params \
CALYPSO_KEY=../experiments/approaches/calypso/calypso.key \
  ./measure-packet-sizes.sh calypso
```

Each invocation prints a line of the form:

```
[SIZE] dns_req=<N> dns_resp=<M> http_req=<...> http_resp=<...>
```

Table 1 reports `dns_req` and `dns_resp` (the DNS message layer,
before HTTP/transport encapsulation).

## Mapping to paper Table 1

| Paper row | Script argument | Effective `q` flags                |
|-----------|-----------------|------------------------------------|
| Normal    | `plain`         | (no auth, no encryption)           |
| JWT       | `jwt`           | `--jwt --token=$JWT_TOKEN`         |
| JEDI      | `wkd-ibe`       | `--wkdibe --params=… --key=…`      |
| Calypso   | `calypso`       | `--calypso --params=… --key=…`     |

## Reference values (from paper)

| Approach | DNS Request | DNS Response |
|----------|-------------|--------------|
| Normal   | 45 B        | 88 B         |
| JWT      | 374 B       | 99 B         |
| JEDI     | 60 B        | 1733 B       |
| Calypso  | 124 B       | 1817 B       |

Absolute sizes may differ by a few bytes if the etcd-stored ciphertext
length shifts (e.g., due to IV or authentication-tag sizing); relative
expansion factors are stable.
