# Calypso CoreDNS plugins

The three CoreDNS plugins authored for this paper. Compiled into a
CoreDNS binary by `experiments/scripts/use-vendored.sh`, which clones
upstream CoreDNS at `v1.12.4` and copies these directories into its
`plugin/` tree.

| Plugin            | Purpose                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `jwt_edns/`       | JWT authorization carried in EDNS OPT records (option code 65001).      |
| `etcd_crypto/`    | Decrypts records stored under AES (enclave path) or WKD-IBE.            |
| `etcd_calypso/`   | Routes Calypso queries by search-tag hash (EDNS option 65003) and returns the encrypted record blob. |

The unmodified upstream `etcd` plugin shipped with CoreDNS v1.12.4 is
used as-is for the plain DoH, JWT, and WKD-IBE approaches.

Released under BSD-3-Clause; see `LICENSE`.
