# Agent-Governance-Kit - Architecture

## System Overview

Agent-Governance-Kit is a policy-as-code framework for controlling, auditing, and enforcing rules on AI agent behavior. It provides a DSL for defining governance policies, a runtime evaluator, audit logging, and integration hooks for agent frameworks.

```
┌──────────────────────────────────────────────────────────────────┐
│                      Policy Editor (Web UI)                      │
│  ┌──────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │
│  │ Editor   │  │ Simulator  │  │ Library    │  │ Audit View │  │
│  └─────┬────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  │
├────────┼──────────────┼───────────────┼───────────────┼──────────┤
│                      Policy Engine                               │
│  ┌─────▼──────────────▼───────────────▼───────────────▼──────┐  │
│  │                GovernanceEngine                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │ Policy   │  │ Evaluator│  │ Enforcer │  │ Auditor  │  │  │
│  │  │ Parser   │  │ (OPA)    │  │          │  │          │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                      Runtime Integration                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ Pre-hook │  │ Post-hook│  │ Middleware│  │ Sidecar      │   │
│  │ (before) │  │ (after)  │  │          │  │ (proxy)      │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
├──────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌────────────────┐  ┌────────────────┐  │
│  │  Policy Store    │  │  Audit Log     │  │  Notification  │  │
│  │  (Postgres)      │  │  (append-only) │  │  (webhook)     │  │
│  └──────────────────┘  └────────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Policy Editor
Web-based interface for authoring and testing governance policies.

| Component | Responsibility |
|-----------|---------------|
| `Editor` | Syntax-highlighted policy authoring with autocomplete |
| `Simulator` | Test policies against sample agent actions |
| `Library` | Browse and share community governance templates |
| `Audit View` | Visualize policy enforcement history and violations |

### Policy Engine

| Component | Responsibility |
|-----------|---------------|
| `GovernanceEngine` | Core orchestrator for policy evaluation and enforcement |
| `PolicyParser` | Parses policy DSL into executable AST |
| `Evaluator` | OPA-based policy evaluation engine |
| `Enforcer` | Blocks, warns, or logs based on policy decisions |
| `Auditor` | Records all policy decisions with full context |

### Runtime Integration
Multiple integration patterns for agent frameworks.

- **Pre-hook**: Evaluate before agent action executes
- **Post-hook**: Audit after agent action completes
- **Middleware**: Express/gRPC middleware for API-based agents
- **Sidecar**: Proxy pattern for non-invasive integration

## Data Flow

```
┌──────────┐     ┌───────────┐     ┌──────────────┐
│ Agent    │────▶│ Pre-hook  │────▶│ Policy       │
│ Action   │     │ (intercept│     │ Evaluator    │
└──────────┘     └───────────┘     └──────┬───────┘
                                          │
                    ┌─────────────────────▼──────────────────┐
                    │         OPA Policy Evaluation          │
                    │    (policy DSL → allow/deny/modify)    │
                    └─────────────────────┬──────────────────┘
                                          │
                    ┌───────────┐         │         ┌───────────┐
                    │  DENY     │         │         │  ALLOW    │
                    │  (block + │         │         │  (proceed)│
                    │   audit)  │         │         │           │
                    └─────┬─────┘         │         └─────┬─────┘
                          │               │               │
                          ▼               ▼               ▼
                    ┌─────────────────────────────────────────┐
                    │      Audit Log (append-only)            │
                    └─────────────────────────────────────────┘
```

## Directory Structure

```
agent-governance-kit/
├── src/
│   ├── engine/              # Policy engine core
│   │   ├── governance.ts
│   │   ├── parser.ts
│   │   ├── evaluator.ts
│   │   ├── enforcer.ts
│   │   └── auditor.ts
│   ├── policies/            # Built-in policies
│   │   ├── cost-limits.rego
│   │   ├── tool-allowlist.rego
│   │   ├── pii-filter.rego
│   │   └── rate-limit.rego
│   ├── integrations/        # Runtime hooks
│   │   ├── pre-hook.ts
│   │   ├── post-hook.ts
│   │   ├── middleware.ts
│   │   └── sidecar.ts
│   ├── web/                 # Policy editor UI
│   │   ├── editor/
│   │   ├── simulator/
│   │   └── audit-view/
│   ├── store/               # Policy persistence
│   │   ├── policyStore.ts
│   │   └── auditLog.ts
│   └── notifications/       # Alert system
├── policies/                # Default policy library
│   └── examples/
├── tests/
├── docs/
├── package.json
└── tsconfig.json
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| OPA for evaluation | Industry-standard policy engine with Rego DSL |
| Append-only audit log | Tamper-evident record of all governance decisions |
| Multiple integration patterns | Accommodates different agent architectures |
| Policy as code | Version-controllable, testable, and shareable |
| Simulator before deploy | Test policies against scenarios before enforcement |

## Dependencies

- **Engine**: `open-policy-agent` (OPA), `rego` (JS bindings)
- **Store**: `pg` (Postgres)
- **Web**: `react`, `codemirror` (editor)
- **Build**: `typescript`, `esbuild`
- **Testing**: `vitest`, `opa-test`

## Security Considerations

- Policy evaluation is deterministic and auditable
- Audit logs are cryptographically signed and append-only
- Policy changes require approval workflow (RBAC)
- No PII stored in audit logs; only decision metadata
- Rate limiting on policy evaluation to prevent DoS
- Policy store encrypted at rest

## Performance Characteristics

- Policy evaluation: <5ms per action
- Audit log write: <10ms (async append)
- Batch evaluation: 1000 actions/second
- Policy compilation: <100ms for complex policies
- Audit query: <200ms for 1M log entries

## Extension Points

| Extension | Mechanism |
|-----------|-----------|
| Custom policies | Write Rego policies and register in policy store |
| Custom evaluators | Replace OPA with alternative policy engines |
| Custom integrations | Implement hook interfaces for new agent frameworks |
| Custom audit sinks | Export audit logs to SIEM or external systems |
| Custom enforcers | Modify enforcement behavior (block, quarantine, notify) |
