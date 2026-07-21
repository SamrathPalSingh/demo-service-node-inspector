# Node Inspector infrastructure requirements

## Contract metadata

- Schema version: `1.0`
- Kind: `service-requirements`
- Contract ID: `node-inspector`
- Name: `Node Inspector`
- Owner: `runtime-observability-team`
- Repository: `demo-service-node-inspector`
- Contact: `#runtime-observability`

This Markdown file is the service team's hand-maintained contract source. The
published JSON adds the current repository manifests so an incoming infra test
can compare the declaration with the implementation.

## Critical severity

### NODE-SEC-001 - Preserve mount syscall compatibility

#### Requirements

- The workload startup path executes `mount(2)` to create a temporary inspection filesystem and requires `CAP_SYS_ADMIN`.
- Do not apply a cluster-wide AppArmor or seccomp default that denies this operation until this service has a tested compatible profile or no longer invokes `mount(2)`.

#### Remediation

- Provide and validate a narrowly scoped service-specific AppArmor/seccomp profile, grant an explicit temporary exception, or migrate the implementation away from `mount(2)` before enabling the cluster default.

#### Deterministic signals

- `seccomp_default:\s*true`
- `seccomp-default:\s*"?true`
- `(apparmor_default|app_armor_default):\s*true`
