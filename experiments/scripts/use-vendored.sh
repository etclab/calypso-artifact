#!/bin/bash
# use-vendored.sh — stage the vendored sources under repos/ in the layout the
# build scripts expect. Idempotent; safe to re-run.
#
# - Symlinks the in-tree Go packages from src/.
# - Clones upstream CoreDNS at the pinned tag and applies the overlay
#   (registers our plugins, adds ego targets, injects extra deps).
# - Clones upstream etcd at the pinned commit.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT="$(cd "$WORKSPACE/.." && pwd)"
SRC="$ROOT/src"

COREDNS_REPO="coredns/coredns"
COREDNS_TAG="v1.12.4"

ETCD_REPO="etcd-io/etcd"
ETCD_COMMIT="6f3e25b053a01c9574a198e32e5bf6ba2363f4b2"   # snapshot used in paper run

if [ ! -d "$SRC" ]; then
    echo "ERROR: vendored src/ not found at $SRC" >&2
    exit 1
fi

mkdir -p "$WORKSPACE/repos" "$WORKSPACE/build"

link() {
    local target="$1" linkname="$2"
    if [ -L "$linkname" ] && [ "$(readlink "$linkname")" = "$target" ]; then
        echo "  ⊙ $linkname (already linked)"
    elif [ -e "$linkname" ]; then
        echo "  ⚠ $linkname exists and is not the expected symlink — leaving it alone"
    else
        ln -s "$target" "$linkname"
        echo "  ↪ $linkname → $target"
    fi
}

cd "$WORKSPACE/repos"
link "$SRC/calypso"   calypso
link "$SRC/q"         q
link "$SRC/cryptofun" cryptofun

# build-components.sh expects ztrust-dns/{etcd-client,jwt-tools}; mirror layout.
mkdir -p ztrust-dns
link "$SRC/etcd-client" ztrust-dns/etcd-client
link "$SRC/jwt-tools"   ztrust-dns/jwt-tools

apply_coredns_overlay() {
    local cd_dir="$1"

    # Copy our plugin sources into plugin/.
    for p in jwt_edns etcd_crypto etcd_calypso; do
        if [ ! -d "$cd_dir/plugin/$p" ]; then
            cp -R "$SRC/plugins/$p" "$cd_dir/plugin/"
            echo "  + plugin/$p"
        fi
    done

    # Overwrite plugin.cfg, append ego Makefile targets, copy dev/ and gen_certs.sh.
    cp "$SRC/coredns-overlay/plugin.cfg" "$cd_dir/plugin.cfg"
    if ! grep -q '^ego:' "$cd_dir/Makefile"; then
        cat "$SRC/coredns-overlay/Makefile.ego" >> "$cd_dir/Makefile"
    fi
    # Copy dev/ contents idempotently (the trailing /. avoids nested dev/dev/
    # if the destination already exists from a prior run).
    mkdir -p "$cd_dir/dev"
    cp -R "$SRC/coredns-overlay/dev/." "$cd_dir/dev/"
    cp "$SRC/coredns-overlay/gen_certs.sh" "$cd_dir/gen_certs.sh"

    # Inject extra direct dependencies into go.mod.
    while read -r line; do
        case "$line" in ''|\#*) continue;; esac
        (cd "$cd_dir" && go mod edit -require="$line")
    done < "$SRC/coredns-overlay/go.mod.requires"

    echo "  ✓ overlay applied"
}

if [ ! -d "coredns" ]; then
    if ! command -v gh >/dev/null 2>&1; then
        echo "ERROR: gh CLI not found and coredns not present locally." >&2
        echo "Install gh (https://cli.github.com/) or manually clone $COREDNS_REPO into ./coredns" >&2
        exit 1
    fi
    echo "  ↓ Cloning $COREDNS_REPO at $COREDNS_TAG"
    gh repo clone "$COREDNS_REPO" coredns -- --quiet --branch "$COREDNS_TAG" --depth 1
else
    echo "  ⊙ coredns (already present)"
fi
# Always (re)apply the overlay — idempotent. This catches the case where
# coredns/ exists from a prior run or a manual clone but hasn't been patched.
apply_coredns_overlay "$WORKSPACE/repos/coredns"

if [ ! -d "etcd" ]; then
    if ! command -v gh >/dev/null 2>&1; then
        echo "ERROR: gh CLI not found and etcd not present locally." >&2
        exit 1
    fi
    echo "  ↓ Cloning $ETCD_REPO at $ETCD_COMMIT"
    gh repo clone "$ETCD_REPO" etcd -- --quiet
    (cd etcd && git checkout --quiet "$ETCD_COMMIT")
    echo "  ✓ etcd cloned and checked out"
else
    echo "  ⊙ etcd (already present)"
fi

echo ""
echo "Done. experiments/repos/ is ready for build-components.sh."
