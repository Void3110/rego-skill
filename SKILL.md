---
name: rego-skill
description: |
  Generate, review, and test OPA Rego policies following security best practices.
  Use when working with authorization policies, access control, ABAC/RBAC systems,
  API gateway rules, Kubernetes admission control, or when user mentions OPA, Rego,
  policy-as-code, authorization, or permission policies. Assumes OPA CLI is installed.
---

# Rego Policy Development

You are an expert in Open Policy Agent (OPA) and the Rego policy language.

## Mandatory Workflow

**ALWAYS follow this sequence for any policy task:**

1. **Understand** - Clarify requirements before writing code
2. **Generate** - Write policy with explicit default deny
3. **Test** - Create comprehensive `*_test.rego` with allow AND deny cases
4. **Validate** - Run `opa check` and `opa test . -v`
5. **Review** - Check against security checklist
6. **Iterate** - Fix any failures before declaring complete

**NEVER skip the test step.** Every policy must have tests that pass.

## Quick Reference

| Task | Guide |
|------|-------|
| Generate policy | Follow [GENERATE.md](GENERATE.md) |
| Security review | Check [SECURITY.md](SECURITY.md) |
| Write tests | Follow [TESTING.md](TESTING.md) |
| Best practices | See [BEST-PRACTICES.md](BEST-PRACTICES.md) |

## Core Principles

### 1. Always Default Deny

Every policy MUST start with explicit default deny:

```rego
package mypackage

import rego.v1

default allow := false

allow if {
    # explicit conditions only
}
```

### 2. Modern Rego Syntax

Use `import rego.v1` for modern syntax:

```rego
import rego.v1

# Use 'if' keyword
allow if {
    some role in input.user.roles
    role == "admin"
}

# Use 'contains' for sets
violations contains msg if {
    # condition
    msg := "violation message"
}

# Use 'every' for universal checks
all_valid if {
    every item in input.items {
        item.status == "approved"
    }
}
```

### 3. Structured Decisions

Return structured objects for better debugging:

```rego
decision := {
    "allowed": allowed,
    "reason": reason,
    "context": {
        "user": input.user.id,
        "action": input.action
    }
}
```

### 4. Always Write Tests

Every policy needs a companion `*_test.rego` file:

```rego
package mypackage_test

import rego.v1
import data.mypackage

test_allow_admin if {
    mypackage.allow with input as {
        "user": {"roles": ["admin"]}
    }
}

test_deny_guest if {
    not mypackage.allow with input as {
        "user": {"roles": ["guest"]}
    }
}
```

## Validation Commands

Always validate your work:

```bash
# Check syntax
opa check policy.rego

# Run tests
opa test . -v

# Format code
opa fmt -w policy.rego

# Test with coverage
opa test . -v --coverage
```

## Common Patterns

### RBAC (Role-Based Access Control)

```rego
package rbac

import rego.v1

default allow := false

allow if {
    some role in input.user.roles
    some permission in role_permissions[role]
    permission == required_permission
}

role_permissions := {
    "admin": ["read", "write", "delete"],
    "editor": ["read", "write"],
    "viewer": ["read"]
}

required_permission := "read" if input.action == "GET"
required_permission := "write" if input.action in ["POST", "PUT", "PATCH"]
required_permission := "delete" if input.action == "DELETE"
```

### ABAC (Attribute-Based Access Control)

```rego
package abac

import rego.v1

default allow := false

# Owner can do anything with their resources
allow if {
    input.user.id == input.resource.owner_id
}

# Department access
allow if {
    input.user.department == input.resource.department
    input.action in ["read", "list"]
}
```

### API Gateway Authorization

```rego
package gateway

import rego.v1

default allow := false

allow if {
    is_public_path
}

allow if {
    is_authenticated
    has_required_permission
}

is_public_path if {
    some pattern in public_patterns
    glob.match(pattern, [], input.path)
}

public_patterns := [
    "/api/health",
    "/api/public/*"
]

is_authenticated if {
    input.token.valid == true
    time.now_ns() < input.token.exp * 1e9
}

has_required_permission if {
    required := path_permissions[input.method][_]
    glob.match(required.pattern, [], input.path)
    some role in input.token.roles
    role in required.roles
}
```

## Security Checklist

Before completing any policy:

- [ ] Default deny is explicit (`default allow := false`)
- [ ] No unconditional `allow := true`
- [ ] Input validation for required fields
- [ ] Type checking where needed (`is_string`, `is_array`)
- [ ] No path traversal vulnerabilities
- [ ] Tests cover allow AND deny cases
- [ ] Tests cover edge cases (null, empty, missing)

## Detailed Guides

For comprehensive guidance, see:

- [GENERATE.md](GENERATE.md) - Step-by-step policy generation
- [SECURITY.md](SECURITY.md) - Security review checklist
- [TESTING.md](TESTING.md) - Test patterns and coverage
- [BEST-PRACTICES.md](BEST-PRACTICES.md) - Performance and style

## Example Files

See `examples/` directory for complete working examples:

- `rbac_test.rego` - RBAC with tests
- `gateway_test.rego` - API gateway with tests

---

## Suite-wide security audit (Workflow)

The generate / test / review loop above handles ONE policy at a time inline. To audit an entire
policy corpus for security drift, this skill ships a **read-only fan-out workflow**:
`rego-security-audit-workflow.js`. It spawns one auditor per `.rego` policy, scores each against the
10-check rubric below, **adversarially verifies every failed check** (so a misread doesn't become a
false alarm), runs a cross-policy conflict pass over same-package groups, and returns a dated report
payload. **It is report-only — it never edits a policy.** The skill (this wrapper) owns the date and
the git write/commit; the workflow owns the fan-out (it's read-only against git).

> Requires a Claude Code harness with the `Workflow` (multi-agent orchestration) tool. The inline
> generate / test / review loop works without it; only this corpus-audit needs it.

### The 10 checks (each cites a SECURITY.md / BEST-PRACTICES.md section)

| Check | Source | What it verifies |
|-------|--------|------------------|
| `DEFAULT_DENY` | SECURITY §1 | Explicit default deny; no unconditional allow. |
| `INPUT_VALIDATION` | SECURITY §2 | Required fields checked; missing → deny not error; null/type handled. |
| `PRIV_ESCALATION` | SECURITY §3 | Strict-inequality role levels; self-mod blocked; protected roles unassignable. |
| `PATH_TRAVERSAL` | SECURITY §4 | Path/id inputs validated (`..`, `/`, `%`, `\`); no raw startswith. |
| `REDOS` | SECURITY §4 | No user-controlled regex; glob/literal preferred. |
| `DATA_EXPOSURE` | SECURITY §5 | Denial reasons don't leak roles/permissions/structure. |
| `TIME_BASED` | SECURITY §6 | Token exp/nbf checked before access (where tokens are handled). |
| `EVAL_CONFLICT` | BEST-PRACTICES | Competing rules mutually exclusive (whitelist guards / else-chains). |
| `DOMAIN_LOGIC_LEAK` | BEST-PRACTICES | Policy does authz only — no business/validation/workflow logic. |
| `TEST_COVERAGE` | TESTING | Companion `*_test.rego` covers allow + deny + edge cases. |

> **Conventions are NOT findings.** Each policy is judged against ITS OWN idiom. Using
> `import future.keywords` instead of `import rego.v1`, or returning `{"allow": bool}` instead of a
> bare `allow`, is recorded descriptively and **never raised as a check failure**. Only genuine,
> exploitable authorization defects are reported.

### Running the audit

```
- [ ] 1. DATE=$(date +%F); ensure <root>/audit-reports/ exists.
- [ ] 2. Run the workflow (background; you're notified on completion).
- [ ] 3. Render the returned payload into <root>/audit-reports/REGO-SECURITY-AUDIT-<DATE>.md.
- [ ] 4. Commit the report to a branch (never the default branch). Do NOT push or open an MR unless asked.
- [ ] 5. Report the headline counts; offer to fix Critical/Medium items via the inline generate/review loop.
```

**Step 2 — invoke:**
```
Workflow({
  scriptPath: "<this-skill-dir>/rego-security-audit-workflow.js",
  args: { date: "<DATE>", policyRoot: "<dir-with-.rego-files>" }   // policyRoot defaults to cwd
  // optional: focus (steer) | policies:[explicit list] | maxPolicies (default 12)
})
```

The payload is `{ date, rubricVersion, scope:{audited,total,deferred,baselineTests,maxPolicies,policyRoot}, confirmed:[…severity-sorted, false alarms already dropped…], policyVerdicts:[…], crossPolicy:[…] }`.
`confirmed` = findings that **survived adversarial verification**. `crossPolicy` = same-package
overlapping/shadowed-rule / `eval_conflict` issues a single-policy auditor can't see.

> **Date:** YOU own the date — use the `$DATE` you computed for the filename, heading, and commit. If
> the payload's `date` reads `"(undated)"` (args didn't propagate), ignore it and stamp `$DATE` anyway.

**Step 3 — report shape** (`REGO-SECURITY-AUDIT-<DATE>.md`):
```markdown
# Rego Security Audit — <DATE>

**Scope:** audited <audited> of <total> policies; baseline `<baselineTests>`. **<N> confirmed findings
(<C> Critical), <R> false alarms dropped, <X> cross-policy issues.**

## Confirmed findings (fix these)        <!-- one ### block per item, Critical first -->
### [<severity>/<check>] <policy>
- **Evidence:** <evidence>
- **Rubric:** SECURITY/BEST-PRACTICES <section>
- _verifier:_ <reConfirm>                <!-- or "unverified — confirm manually" if no verdict -->

## Cross-policy issues                    <!-- from crossPolicy[]; omit section if empty -->
### [<severity>/<kind>] <policies>
- <detail>

## Per-policy verdicts
| Policy | Package | Decision shape | Tests | Fails | N/A | Summary |
|--------|---------|----------------|-------|-------|-----|---------|
| … (one row per policyVerdicts entry) … |
```

If `confirmed` is empty, still write the report (a clean run is a useful record) and say so.

**Step 4 — commit to a branch** (never the default branch; no push/MR unless asked).

### Incremental mode (optional)
The workflow carries a `RUBRIC_VERSION`. To audit only changed policies, the wrapper computes the set
whose `git hash-object` differs from the last report's manifest (or all, if `RUBRIC_VERSION` bumped),
and passes them as `args.policies`. First cut: full-suite every run (small corpora audit fast).

### Notes & anti-patterns
- **Report-only is the contract.** This workflow *finds*; you *fix* (via the inline generate/review
  loop). An unattended agent "fixing" a large gateway policy is worse than a reported finding.
- **The verify phase matters.** A policy isn't insecure because one agent misread it — every
  Critical/Medium finding is adversarially re-checked, and false alarms are dropped before the report.
- **Sizing:** keep a run ≤ ~12 policies / ~50 agents. `maxPolicies` (default 12) bounds it; deferred
  policies are listed in `scope.deferred` and re-surface on a later run.
