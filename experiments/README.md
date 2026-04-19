# Evaluation benchmarks for Calypso DNS security

Here we'll be tracking all the scripts and code for benchmark and evaluation of Calypso.

## Experimental Setup

```bash
# 1. Install Go and create workspace dirs
./scripts/setup-vm.sh

# 2. Wire vendored sources (in ../src/) into the layout the build expects;
#    also fetches etcd at the pinned commit
./scripts/use-vendored.sh

# 3. Build components (also updates go.mod replace directives)
./scripts/build-components.sh

# For ego support (requires SGX enclave), add -with-ego to setup and build:
./scripts/setup-vm.sh -with-ego
./scripts/build-components.sh -with-ego
```

## Running Approaches

After setting up the workspace and building components:

```bash
# Start services for an approach
./scripts/start.sh <approach>

# Available approaches:
#   plain       - Plain DoH (Baseline)
#   jwt         - JWT-Authorized DoH
#   enclave     - Enclave-Protected CoreDNS
#   enclave-jwt - Enclave + JWT (AES encryption + JWT authorization)
#   wkdibe     - WKD-IBE + DoH
#   calypso     - Calypso + DoH

# Example: Start plain DoH
./scripts/start.sh plain

# Stop all running services (auto-detects approaches)
./scripts/stop.sh
```

**What the start script does:**
1. Configure CoreDNS plugins for the approach
2. Build CoreDNS binary
3. Generate TLS certificates (auto-generates if missing)
4. Start etcd on http://localhost:2379
5. Start CoreDNS with DoH on https://localhost:8443

**Logs and configuration:**
- Location: `$WORKSPACE/approaches/<approach>/` (or in-repo: `./approaches/<approach>/`)
- `etcd.log` - etcd service logs
- `coredns.log` - CoreDNS service logs
- `etcd.pid`, `coredns.pid` - Process IDs
- `ca-cert.pem`, `cert.pem`, `key.pem` - TLS certificates

**Testing:**
```bash
# Query DNS over HTTPS (using -i to skip TLS verification)
$WORKSPACE/build/q -i A example.com @https://localhost:8443

# Load test data into etcd
$WORKSPACE/build/etcdctl --endpoints=http://localhost:2379 put /skydns/com/example/test '{"host":"192.168.1.1"}'
```

## Microbenchmarks

## Macrobenchmarks

Measuring the CDF of end-to-end DNS request/response latencies for different approaches.

### Quick Start

```bash
# Compare multiple approaches (default: 300 queries, 20 services, 1 namespace)
./run.sh compare plain jwt

# With custom parameters
./run.sh compare plain jwt enclave 1000 50 5

# Benchmark individual approach
./run.sh bench plain 1000 50 5

# Run smoke test
./run.sh test jwt
```

**Available approaches:**
- `plain`, `jwt`, `enclave`, `enclave-jwt`, `wkdibe`, `calypso`
- UDP variants: `plain-udp`, `jwt-udp`, `enclave-udp`, `enclave-jwt-udp`, `wkdibe-udp`, `calypso-udp`

**Default parameters:**
- Queries: 300
- Services: 20
- Namespaces: 1

### All Commands

```bash
# Benchmark single approach
./run.sh bench <approach> [queries] [services] [namespaces]

# Compare multiple approaches (auto-generates plot)
./run.sh compare <approach1> <approach2> [...] [queries] [services] [namespaces]

# Benchmark all core approaches (DoH + UDP): plain, jwt, wkdibe, calypso
./run.sh full [queries] [services] [namespaces]

# Benchmark all approaches including enclave variants (DoH + UDP)
./run.sh full-w-ego [queries] [services] [namespaces]

# Generate plot from existing results (no re-run)
./run.sh plot <approach1> <approach2> [...] [label1] [label2] [...]

# Run smoke test
./run.sh test [approach]

# List recent results
./run.sh list

# Clean all results and JWT keys
./run.sh clean

# Stop all running services
./run.sh stop
```

**Examples:**
```bash
# Full comparison
./run.sh compare plain jwt wkdibe calypso 10000 500 10

# Run all core approaches (8 variants: plain, jwt, wkdibe, calypso + UDP)
./run.sh full 1000 50 5

# Run all approaches including enclave (12 variants: adds enclave, enclave-jwt + UDP)
./run.sh full-w-ego 1000 50 5

# Custom plot labels
./run.sh plot calypso calypso-udp "Calypso DoH" "Calypso UDP"
./run.sh plot plain jwt wkdibe wkdibe-udp calypso calypso-udp "Plain-DoH" "JWT-DoH" "WKD-IBE DoH" "WKDIBE-UDP" "Calypso DoH" "Calypso UDP"

# Test specific approach
./run.sh test wkdibe
./run.sh test enclave-jwt
```

**Results:**
- CSV files: `results/<approach>-<timestamp>-latencies.csv`
- DAT files: `results/<approach>-<timestamp>-latencies.dat`
- Plots: `results/<comparison>-comparison-<timestamp>.png`

### Parameters for tests

  #### SMALL SCALE (Startup/Small Team: ~100 services)
  ```bash
  # Run either
  ./run.sh bench plain 500 100 5
  ./run.sh plot plain 500 100 5
  # Or
  ./run.sh compare plain jwt enclave 500 100 5
  ```

  #### MEDIUM SCALE (Mid-size Company: ~500-1000 services, like Spotify/Airbnb)
  ```bash
  # Run either
  ./run.sh bench plain 1000 500 20
  ./run.sh plot plain 1000 500 20
  # Or
  ./run.sh compare plain jwt enclave 1000 500 20
  ```

  #### LARGE SCALE (Enterprise: ~2000-3000 services, like Pinterest)
  ```bash
  # Run either
  ./run.sh bench plain 2000 2000 40
  ./run.sh plot plain 2000 2000 40
  # Or
  ./run.sh compare plain jwt enclave 2000 2000 40
  ```

  #### EXTREME SCALE (Uber-class: 4000+ services)
  ```bash
  # Run either
  ./run.sh bench plain 5000 4000 75
  ./run.sh plot plain 5000 4000 75
  # Or
  ./run.sh compare plain jwt enclave 5000 4000 75
  ```

  **Rationale:**
  - Queries scaled proportionally to service count for statistical significance
  - Service-to-namespace ratios match real-world patterns (10-50 services per
  namespace)
  - Small: 100 svcs ÷ 5 ns = 20:1 ratio
  - Medium: 500 svcs ÷ 20 ns = 25:1 ratio
  - Large: 2000 svcs ÷ 40 ns = 50:1 ratio
  - Extreme: 4000 svcs ÷ 75 ns = 53:1 ratio

