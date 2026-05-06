# Reproducing paper Table 3 — DNS Packet Expansion

(This file is named `table1-reproduce.md` for historical reasons; the
table it reproduces is **Table 3** in the SACMAT 2026 camera-ready.)

Table 3 reports DNS request/response sizes for four approaches:
**Normal** (plain DoH), **JWT**, **JEDI** (WKD-IBE), and **Calypso**.
Sizes are deterministic; one query per approach is enough.

## What you need from the install

After `setup-vm.sh`, `use-vendored.sh`, `build-components.sh`:

- `experiments/build/q` (supports `--measure-sizes`)
- `experiments/build/etcd-client`
- `experiments/scripts/{start,stop}.sh`
- `misc/measure-packet-sizes.sh`

The test record used throughout is
`testservice.test.svc.cluster.local = 10.0.1.100`. `start.sh` brings up
CoreDNS + etcd and provisions per-approach keys, but does **not**
insert any record — the insertion is the second step below.

## The flow (same shape for all four)

```bash
cd experiments

# 1. Bring up the approach (idempotent; reuses existing keys/certs)
./scripts/start.sh <APPROACH>

# 2. Insert the test record under the approach's crypto envelope
<INSERT_ENV> ./build/etcd-client \
    -register testservice.test.svc.cluster.local=10.0.1.100

# 3. (Calypso only) derive a concrete-domain reader key
./build/etcd-client calypso reader \
    --writer ./approaches/calypso/writer.key \
    --output ./approaches/calypso/reader.key

# 4. Measure
cd ../misc
<MEASURE_ENV> ./measure-packet-sizes.sh <SCRIPT_ARG>

# 5. Tear down
cd ../experiments && ./scripts/stop.sh
```

The variable parts per approach:

| Paper row | `<APPROACH>` (start.sh) | `<SCRIPT_ARG>` (measure-packet-sizes.sh) | `<INSERT_ENV>` | `<MEASURE_ENV>` |
|---|---|---|---|---|
| Normal  | `plain`   | `plain`   | *(none)* | *(none)* |
| JWT     | `jwt`     | `jwt`     | *(none)* | `JWT_TOKEN=$(cat ./approaches/jwt/jwt.token)` |
| JEDI    | `wkdibe`  | `wkd-ibe` | `CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=./approaches/wkdibe/params.bin WKDIBE_KEY_FILE=./approaches/wkdibe/test.key WKDIBE_MAX_DEPTH=6` | `WKDIBE_PARAMS=../experiments/approaches/wkdibe/params.bin WKDIBE_KEY=../experiments/approaches/wkdibe/test.key` |
| Calypso | `calypso` | `calypso` | `CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=./approaches/calypso/params.bin CALYPSO_WRITER_KEY=./approaches/calypso/writer.key CALYPSO_MAX_DEPTH=7` | `CALYPSO_PARAMS=../experiments/approaches/calypso/params.bin CALYPSO_KEY=../experiments/approaches/calypso/reader.key` |

Skip step 3 except for Calypso.

> **Note:** `measure-packet-sizes.sh` happens to use `wkd-ibe` (with
> hyphen) as its own argument; everywhere else (`run.sh`, `start.sh`,
> `etcd-client`) the approach is `wkdibe`. The table reflects that.

## What you'll see

Each measurement prints:

```
[SIZE] dns_req=<N> dns_resp=<M> http_req=<...> http_resp=<...>
```

Table 3 reports `dns_req` and `dns_resp` (the DNS message layer,
before HTTP/transport encapsulation).

## Reference values (from paper)

| Approach | DNS Request | DNS Response |
|----------|-------------|--------------|
| Normal   | 45 B        | 88 B         |
| JWT      | 374 B       | 99 B         |
| JEDI     | 60 B        | 1733 B       |
| Calypso  | 124 B       | 1817 B       |

Absolute sizes may shift by a few bytes (IV/auth-tag sizing in the
etcd-stored ciphertext); relative expansion factors are stable.
