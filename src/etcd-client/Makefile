.PHONY: build test vet clean clean-all verify-plaintext verify-aes verify-wkdibe verify-calypso verify-all setup-aes setup-wkdibe setup-calypso benchmark-wkdibe benchmark-calypso

# Build targets
build:
	go build -o etcd-client

test:
	go test -v

vet:
	go vet

# Cleanup targets
clean:
	rm -f etcd-client

clean-all:
	rm -f etcd-client *.pem *.key *.bin

clean-verify:
	rm -f verify_*.pem verify_*.key verify_*.bin

# Setup targets for generating test keys
setup-aes: build
	@echo "=== Setting up AES key ==="
	@openssl rand -out verify_aes.key 32
	@echo "AES setup complete"

setup-wkdibe: build
	@echo "=== Setting up WKD-IBE parameters ==="
	./etcd-client wkdibe setup --max-depth 5 --output verify_wkdibe_params.bin --master-key verify_wkdibe_master.key
	./etcd-client wkdibe keygen --params verify_wkdibe_params.bin --master-key verify_wkdibe_master.key \
		--domain "verify.example.com" --output verify_wkdibe_identity.key
	@echo "WKD-IBE setup complete"

setup-calypso: build
	@echo "=== Setting up Calypso parameters ==="
	./etcd-client calypso setup --max-depth 5 --output verify_calypso_params.bin --authority verify_calypso_authority.bin
	./etcd-client calypso keygen --params verify_calypso_params.bin --authority verify_calypso_authority.bin \
		--domain "verify.example.com" --writer --output verify_calypso_writer.key
	@echo "Calypso setup complete"

# Verification targets
verify-plaintext: build
	@echo "=== Verifying Plaintext (NoOp) Strategy ==="
	@echo "1. Clearing etcd..."
	@./etcd-client -clear || (echo "Error: etcd not running?" && exit 1)
	@echo "2. Registering verify.example.com -> 192.168.1.100"
	@./etcd-client -register verify.example.com=192.168.1.100
	@echo "3. Looking up verify.example.com"
	@./etcd-client -lookup verify.example.com
	@echo "4. Listing all records"
	@./etcd-client -list
	@echo "5. Deleting verify.example.com"
	@./etcd-client -delete verify.example.com
	@echo "6. Verifying deletion"
	@./etcd-client -lookup verify.example.com 2>&1 | grep -q "does not exist" && echo "✓ Plaintext verification complete"

verify-aes: setup-aes
	@echo "=== Verifying AES-256-GCM Strategy ==="
	@echo "1. Clearing etcd..."
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -clear
	@echo "2. Registering verify.example.com -> 192.168.1.101 (AES encrypted)"
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -register verify.example.com=192.168.1.101
	@echo "3. Looking up verify.example.com (with AES decryption)"
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -lookup verify.example.com
	@echo "4. Listing all records"
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -list
	@echo "5. Deleting verify.example.com"
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -delete verify.example.com
	@echo "6. Verifying deletion"
	@CRYPTO_TYPE=aes AES_KEY_FILE=verify_aes.key ./etcd-client -lookup verify.example.com 2>&1 | grep -q "does not exist" && echo "✓ AES verification complete"
	@$(MAKE) clean-verify

verify-wkdibe: setup-wkdibe
	@echo "=== Verifying WKD-IBE Strategy ==="
	@echo "1. Clearing etcd..."
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin ./etcd-client -clear
	@echo "2. Registering verify.example.com -> 192.168.1.102 (WKD-IBE encrypted)"
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key ./etcd-client -register verify.example.com=192.168.1.102
	@echo "3. Looking up verify.example.com (with WKD-IBE decryption)"
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key ./etcd-client -lookup verify.example.com
	@echo "4. Listing all records"
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key ./etcd-client -list
	@echo "5. Deleting verify.example.com"
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin ./etcd-client -delete verify.example.com
	@echo "6. Verifying deletion"
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key ./etcd-client -lookup verify.example.com 2>&1 | grep -q "does not exist" && echo "✓ WKD-IBE verification complete"
	@$(MAKE) clean-verify

verify-calypso: setup-calypso
	@echo "=== Verifying Calypso Strategy ==="
	@echo "1. Clearing etcd..."
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin ./etcd-client -clear
	@echo "2. Registering verify.example.com -> 192.168.1.103 (Calypso encrypted)"
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key ./etcd-client -register verify.example.com=192.168.1.103
	@echo "3. Looking up verify.example.com (with Calypso decryption)"
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key ./etcd-client -lookup verify.example.com
	@echo "4. Listing all records"
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key ./etcd-client -list
	@echo "5. Deleting verify.example.com"
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key ./etcd-client -delete verify.example.com
	@echo "6. Verifying deletion"
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key ./etcd-client -lookup verify.example.com 2>&1 | grep -q "does not exist" && echo "✓ Calypso verification complete"
	@$(MAKE) clean-verify

verify-all: verify-plaintext verify-aes verify-wkdibe verify-calypso
	@echo ""
	@echo "=========================================="
	@echo "✓ All verification tests passed!"
	@echo "=========================================="

# Benchmark targets
N ?= 100
benchmark-wkdibe: setup-wkdibe
	@echo "=== Benchmarking WKD-IBE Lookup (N=$(N)) ==="
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin ./etcd-client -clear > /dev/null 2>&1
	@CRYPTO_TYPE=wkdibe WKDIBE_PARAMS_FILE=verify_wkdibe_params.bin WKDIBE_KEY_FILE=verify_wkdibe_identity.key \
		./etcd-client -register verify.example.com=192.168.1.102 > /dev/null 2>&1
	@echo "Running $(N) lookups..."
	@python3 -c 'import time, subprocess, os; times = []; env = os.environ.copy(); env.update({"CRYPTO_TYPE": "wkdibe", "WKDIBE_PARAMS_FILE": "verify_wkdibe_params.bin", "WKDIBE_KEY_FILE": "verify_wkdibe_identity.key"}); [times.append((lambda: (time.time(), subprocess.run(["./etcd-client", "-lookup", "verify.example.com"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), time.time()))()[0::2]) for _ in range($(N))]; times = [(t[1]-t[0])*1000 for t in times]; print(f"Mean lookup time: {sum(times)/len(times):.3f} ms (over $(N) runs)")'
	@$(MAKE) clean-verify

benchmark-calypso: setup-calypso
	@echo "=== Benchmarking Calypso Lookup (N=$(N)) ==="
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin ./etcd-client -clear > /dev/null 2>&1
	@CRYPTO_TYPE=calypso CALYPSO_PARAMS_FILE=verify_calypso_params.bin CALYPSO_WRITER_KEY=verify_calypso_writer.key \
		./etcd-client -register verify.example.com=192.168.1.103 > /dev/null 2>&1
	@echo "Running $(N) lookups..."
	@python3 -c 'import time, subprocess, os; times = []; env = os.environ.copy(); env.update({"CRYPTO_TYPE": "calypso", "CALYPSO_PARAMS_FILE": "verify_calypso_params.bin", "CALYPSO_WRITER_KEY": "verify_calypso_writer.key"}); [times.append((lambda: (time.time(), subprocess.run(["./etcd-client", "-lookup", "verify.example.com"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), time.time()))()[0::2]) for _ in range($(N))]; times = [(t[1]-t[0])*1000 for t in times]; print(f"Mean lookup time: {sum(times)/len(times):.3f} ms (over $(N) runs)")'
	@$(MAKE) clean-verify

help:
	@echo "Available targets:"
	@echo ""
	@echo "Build & Test:"
	@echo "  build           - Build the etcd-client binary"
	@echo "  test            - Run all Go tests"
	@echo "  vet             - Run go vet"
	@echo ""
	@echo "Setup (generate test keys):"
	@echo "  setup-aes       - Generate AES test key"
	@echo "  setup-wkdibe    - Generate WKD-IBE test keys"
	@echo "  setup-calypso   - Generate Calypso test keys"
	@echo ""
	@echo "Verification (minimal end-to-end tests):"
	@echo "  verify-plaintext - Verify plaintext (NoOp) strategy"
	@echo "  verify-aes       - Verify AES-256-GCM encryption strategy"
	@echo "  verify-wkdibe    - Verify WKD-IBE encryption strategy"
	@echo "  verify-calypso   - Verify Calypso encryption strategy"
	@echo "  verify-all       - Run all verification tests"
	@echo ""
	@echo "Benchmarking:"
	@echo "  benchmark-wkdibe  - Benchmark WKD-IBE lookup (default N=100, use N=X to override)"
	@echo "  benchmark-calypso - Benchmark Calypso lookup (default N=100, use N=X to override)"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean           - Remove built binary"
	@echo "  clean-all       - Remove binary and all .pem/.key/.bin files"
	@echo "  clean-verify    - Remove only verification test keys"
	@echo ""
	@echo "Note: Verification tests require etcd running at localhost:2379"