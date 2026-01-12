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
