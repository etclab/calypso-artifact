.PHONY: build clean test keys token verify deps

# Build the binary
build:
	go build -o jwt-tools

# Install dependencies
deps:
	go mod tidy

# Generate EdDSA key pair (default)
keys:
	./jwt-tools generate-keys

# Generate keys for specified algorithm
keys-algo:
	./jwt-tools generate-keys --algorithm "$(ALG)"

# Generate sample JWT token with specified algorithm (ALG=RS256|ES256|EdDSA)
token:
	@if [ -z "$(ALG)" ]; then \
		./jwt-tools generate-token --client-id "sample-client" --permissions "query" --expiry "1h"; \
	else \
		./jwt-tools generate-token --algorithm "$(ALG)" --client-id "sample-client" --permissions "query" --expiry "1h"; \
	fi

# Generate a JWT token without query permissions
token-no-query:
	@if [ -z "$(ALG)" ]; then \
		./jwt-tools generate-token --client-id "restricted-client" --permissions "update" --expiry "1h"; \
	else \
		./jwt-tools generate-token --algorithm "$(ALG)" --client-id "restricted-client" --permissions "update" --expiry "1h"; \
	fi

# Complete demo: generate keys and token for specified algorithm
demo:
	@if [ -z "$(ALG)" ]; then \
		echo "Usage: make demo ALG=<RS256|ES256|EdDSA>"; \
		exit 1; \
	fi
	./jwt-tools generate-keys --algorithm "$(ALG)"
	./jwt-tools generate-token --algorithm "$(ALG)" --client-id "$(ALG)-client" --permissions "query" --expiry "1h"

# Verify a token (requires TOKEN variable)
verify:
	@if [ -z "$(TOKEN)" ]; then echo "Usage: make verify TOKEN=<jwt-token>"; exit 1; fi
	./jwt-tools verify-token "$(TOKEN)"

# Clean build artifacts
clean:
	rm -f jwt-tools private.pem public.pem

# Build and generate keys in one step
setup: build keys

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the jwt-tools binary"
	@echo "  deps        - Install Go dependencies"
	@echo "  keys        - Generate EdDSA key pair (default)"
	@echo "  keys-algo   - Generate keys for algorithm (ALG=RS256|ES256|EdDSA)"
	@echo "  token       - Generate sample JWT token (default EdDSA, optional ALG=RS256|ES256|EdDSA)"
	@echo "  token-no-query - Generate JWT token without query permissions (optional ALG=)"
	@echo "  demo        - Generate keys and token for algorithm (ALG=RS256|ES256|EdDSA)"
	@echo "  verify      - Verify JWT token (requires TOKEN=<jwt-token>)"
	@echo "  setup       - Build and generate keys"
	@echo "  clean       - Clean build artifacts"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make token ALG=ES256      # Generate ES256 token"
	@echo "  make demo ALG=EdDSA       # Full EdDSA demo"
	@echo "  make keys-algo ALG=ES256  # Generate ES256 keys only"