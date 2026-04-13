# CoreDNS overlay

Files applied on top of the upstream CoreDNS v1.12.4 source tree by
`experiments/scripts/use-vendored.sh` to build the CoreDNS variant used
in this paper.

| File                | Application |
|---------------------|-------------|
| `plugin.cfg`        | overwrites `plugin.cfg` to register `jwt_edns` and `etcd_calypso` directives. (`etcd_crypto` is enabled selectively per approach by the `configure_coredns_plugins` helper in `experiments/scripts/lib/common.sh`.) |
| `Makefile.ego`      | appended to `Makefile` to add `ego`, `ego-eval`, and `ego-run` targets that build CoreDNS for execution inside an SGX enclave via the ego framework. |
| `go.mod.requires`   | one direct dependency per line; injected into `go.mod` via `go mod edit -require`. |
| `dev/`              | copied to `dev/` — ego enclave configuration files. |
| `gen_certs.sh`      | copied to the repository root — generates a CA and server certificates for the DoH listeners. |

The plugin sources themselves live in `src/plugins/` and are copied into
`coredns/plugin/` by the same script.
