# License inventory

This artifact bundles components under multiple compatible open-source
licenses. Each component carries its own `LICENSE` file in its directory;
this index summarizes them.

| Component | License | Notes |
|---|---|---|
| `src/plugins/`         | BSD-3-Clause  | The 3 CoreDNS plugins authored for this paper |
| `src/coredns-overlay/` | BSD-3-Clause  | Build-time overlay applied onto upstream CoreDNS |
| `src/calypso/`         | BSD-3-Clause  | Authored for this paper |
| `src/cryptofun/`       | BSD-3-Clause  | Authored for this paper |
| `src/etcd-client/`     | BSD-3-Clause  | Authored for this paper |
| `src/jwt-tools/`       | BSD-3-Clause  | Authored for this paper |
| `experiments/`         | BSD-3-Clause  | Experiment orchestration scripts |
| `src/q/`               | GPL-3.0       | DNS query client; carries upstream GPL-3.0 |
| Fetched on demand:     |               |  |
| CoreDNS v1.12.4 (via `use-vendored.sh`) | Apache-2.0 | Upstream coredns/coredns |
| etcd (via `use-vendored.sh`)            | Apache-2.0 | Upstream etcd-io/etcd |
| ego (optional, SGX)                     | various    | See https://github.com/edgelesssys/ego |

## Compatibility

All licenses listed are mutually compatible for an artifact distribution:

- BSD-3 → Apache-2.0: permissive ↔ permissive, no constraints. Our
  CoreDNS plugins (BSD-3) compile against vanilla CoreDNS (Apache-2.0)
  to produce a CoreDNS binary; both licenses' obligations are met.
- BSD-3 → GPL-3: BSD-3 code can be incorporated into a GPL combined work.
  The GPL-3 licensing of the resulting `q` binary does not retroactively
  affect the BSD-3 libraries it imports — those libraries remain
  separately reusable under BSD-3.
- Each component's binary inherits its own license; mixing components in
  one tarball is standard practice.

## Reusing parts of this artifact in other projects

If you want to reuse a single component (e.g., the `calypso` Go package),
copy its directory along with its `LICENSE` file. The BSD-3-Clause grant
is permissive; you do not need to inherit any other license from this
artifact.

`BSD-3-Clause.txt` in this directory is the canonical text used for all
BSD-3-Clause components in the artifact.
