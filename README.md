# Demo Node Inspector Service

This is the second real service consumer in the distributed infra-app contract
testing POC. It is intentionally sensitive to runtime confinement.

## The deliberate compatibility dependency

`cmd/node-inspector/main.go` starts by running:

```text
mount -t tmpfs tmpfs /mnt/runtime-check
```

The Deployment runs the Go binary as root and adds `CAP_SYS_ADMIN`, but does
not select an AppArmor or seccomp profile. Its owner-published rule
`NODE-SEC-001` therefore requires the platform to preserve mount syscall
compatibility until the team has a tested, narrow profile or removes the mount
operation.

This is demo behavior, not a recommended production workload design.

## How an infra PR is tested here

`.github/workflows/infra-contract-test.yml` listens for the
`infra_contract_test` repository dispatch. Because GitHub executes it from the
default branch, the workflow evaluates trusted service code rather than code
from the infra PR.

`cmd/infra-contract-test` combines:

- the incoming infra PR description and exact GitHub diff;
- the published Node Inspector contract;
- `cmd/node-inspector/main.go`;
- `k8s/deployment.yaml`; and
- other bounded, relevant repository context.

Gemini produces a strict JSON verdict. A deterministic critical guard also
recognizes the concrete combination of an added cluster-wide AppArmor/seccomp
default and this repository's `mount` dependency. The workflow uploads the
result as:

```text
infra-contract-<correlation-id>-node-inspector
```

The original infra workflow downloads that artifact and includes it in the
aggregate merge gate.

## GitHub setup

Create and push the repository:

```powershell
gh repo create demo-service-node-inspector --public --source . --remote origin --push
```

Add Actions secrets:

- `GEMINI_API_KEY`
- `CONTRACT_FANOUT_TOKEN`
- `REGISTRY_WRITE_TOKEN`

Optionally add variables `GEMINI_MODEL` and `CONTRACT_REGISTRY_REPO`. Push this
workflow to `main` before opening the infra demo PR.

## Local verification

```powershell
go test ./...

go run ./cmd/infra-contract-test `
  --service-id node-inspector `
  --contract ../demo-contract-registry/contracts/services/node-inspector.json `
  --diff ../demo-infra-platform/fixtures/enable-security-defaults.diff `
  --engine deterministic
```

The evaluator command is expected to exit `1` with `NODE-SEC-001`. That means
the compatibility test worked; it is not a test-runner crash.

## Contract publication

`infra-requirements.md` is the hand-maintained source. The publisher parses it,
captures the Go startup implementation and Deployment, and updates
`contracts/services/node-inspector.json` in the registry after changes land on
`main`.

## License

MIT
