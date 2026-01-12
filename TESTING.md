# Rego Testing Patterns

## Test File Structure

Test files must:
- End with `_test.rego`
- Be in same directory as policy
- Import the package being tested

```rego
package authorization_test

import rego.v1
import data.authorization
```

## Test Naming Convention

Use descriptive names that indicate:
- `test_allow_` - Tests that should pass (allow)
- `test_deny_` - Tests that should fail (deny)
- What's being tested

```rego
test_allow_admin_can_delete_any_resource if { ... }
test_deny_guest_cannot_write if { ... }
test_deny_expired_token if { ... }
test_allow_owner_full_access if { ... }
```

## Test Categories

### 1. Happy Path Tests

Test that valid requests are allowed:

```rego
test_allow_admin_full_access if {
    authorization.allow with input as {
        "user": {"id": "admin-1", "roles": ["admin"]},
        "action": "delete",
        "resource": {"id": "doc-1", "type": "document"}
    }
}

test_allow_owner_read_own_resource if {
    authorization.allow with input as {
        "user": {"id": "user-123"},
        "action": "read",
        "resource": {"id": "doc-1", "owner_id": "user-123"}
    }
}
```

### 2. Denial Tests

Test that invalid requests are denied:

```rego
test_deny_guest_cannot_delete if {
    not authorization.allow with input as {
        "user": {"id": "guest-1", "roles": ["guest"]},
        "action": "delete",
        "resource": {"id": "doc-1"}
    }
}

test_deny_wrong_department if {
    not authorization.allow with input as {
        "user": {"id": "user-1", "department": "sales"},
        "action": "read",
        "resource": {"department": "engineering"}
    }
}
```

### 3. Edge Case Tests

Test boundary conditions:

```rego
# Empty arrays
test_deny_empty_roles if {
    not authorization.allow with input as {
        "user": {"id": "user-1", "roles": []},
        "action": "read",
        "resource": {"id": "doc-1"}
    }
}

# Null values
test_deny_null_user_id if {
    not authorization.allow with input as {
        "user": {"id": null, "roles": ["user"]},
        "action": "read",
        "resource": {"id": "doc-1"}
    }
}

# Missing fields
test_deny_missing_user if {
    not authorization.allow with input as {
        "action": "read",
        "resource": {"id": "doc-1"}
    }
}

test_deny_missing_action if {
    not authorization.allow with input as {
        "user": {"id": "user-1"},
        "resource": {"id": "doc-1"}
    }
}

# Empty strings
test_deny_empty_user_id if {
    not authorization.allow with input as {
        "user": {"id": "", "roles": ["user"]},
        "action": "read",
        "resource": {"id": "doc-1"}
    }
}
```

### 4. Security Tests

Test security-critical scenarios:

```rego
# Privilege escalation
test_deny_user_cannot_assign_admin_role if {
    not authorization.can_assign_role with input as {
        "user": {"id": "user-1", "role": "manager"},
        "target_role": "admin"
    }
}

# Self-modification
test_deny_self_role_change if {
    not authorization.can_change_role with input as {
        "user": {"id": "user-1"},
        "target": {"id": "user-1"},
        "new_role": "admin"
    }
}

# Path traversal
test_deny_path_traversal if {
    not authorization.allow with input as {
        "user": {"id": "user-1"},
        "path": "/public/../admin/secrets"
    }
}
```

### 5. Structured Decision Tests

Test decision objects:

```rego
test_decision_includes_reason_on_deny if {
    result := authorization.decision with input as {
        "user": {"id": "user-1", "roles": ["guest"]},
        "action": "delete",
        "resource": {"id": "doc-1"}
    }
    result.allowed == false
    result.reason != ""
}

test_decision_context_populated if {
    result := authorization.decision with input as {
        "user": {"id": "user-123"},
        "action": "read",
        "resource": {"id": "doc-456"}
    }
    result.context.user == "user-123"
    result.context.action == "read"
}
```

## Test Fixtures

Define reusable test data:

```rego
# Users
admin_user := {
    "id": "admin-1",
    "roles": ["admin"],
    "department": "IT",
    "clearance": "top-secret"
}

manager_user := {
    "id": "manager-1",
    "roles": ["manager"],
    "department": "engineering",
    "clearance": "confidential"
}

regular_user := {
    "id": "user-1",
    "roles": ["user"],
    "department": "engineering",
    "clearance": "internal"
}

guest_user := {
    "id": "guest-1",
    "roles": ["guest"],
    "department": "",
    "clearance": "none"
}

# Resources
public_document := {
    "id": "doc-public",
    "type": "document",
    "classification": "public",
    "owner_id": "user-1"
}

confidential_document := {
    "id": "doc-conf",
    "type": "document",
    "classification": "confidential",
    "owner_id": "manager-1",
    "department": "engineering"
}

# Tokens (for API gateway tests)
valid_token := {
    "sub": "user-1",
    "roles": ["user"],
    "exp": 9999999999,  # Far future
    "nbf": 0,           # Always valid
    "valid": true
}

expired_token := {
    "sub": "user-1",
    "roles": ["user"],
    "exp": 1000000000,  # 2001 - expired
    "nbf": 0,
    "valid": true
}

future_token := {
    "sub": "user-1",
    "roles": ["user"],
    "exp": 9999999999,
    "nbf": 9999999998,  # Not yet valid
    "valid": true
}

invalid_token := {
    "sub": "user-1",
    "roles": ["user"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": false      # Signature invalid
}

# Role definitions (for ABAC tests)
role_reader := {
    "name": "reader",
    "permissions": {
        "project": ["read"],
        "request": ["read"]
    }
}

role_writer := {
    "name": "writer",
    "permissions": {
        "project": ["read", "write"],
        "request": ["read", "write"]
    }
}
```

## Running Tests

### Basic Test Run

```bash
# Run all tests
opa test . -v

# Run tests in specific directory
opa test ./policies -v

# Run specific test file
opa test policy_test.rego -v
```

### With Coverage

```bash
# Show coverage summary
opa test . --coverage

# JSON coverage for CI/CD
opa test . --coverage --format=json

# Detailed coverage report
opa test . --coverage --format=json | jq '.files'
```

### Watch Mode (Development)

```bash
# Re-run tests on file changes
opa test . -v --watch
```

## Coverage Requirements

Aim for these coverage targets:

| Category | Target |
|----------|--------|
| Allow rules | 100% |
| Deny conditions | 100% |
| Helper rules | 90%+ |
| Edge cases | All identified |

## Test Organization Template

```rego
package mypackage_test

import rego.v1
import data.mypackage

###################
# Test Fixtures
###################

admin_user := {...}
regular_user := {...}
test_resource := {...}

###################
# Allow Tests
###################

test_allow_admin_full_access if {...}
test_allow_owner_access if {...}

###################
# Deny Tests
###################

test_deny_guest_write if {...}
test_deny_wrong_department if {...}

###################
# Edge Case Tests
###################

test_deny_missing_user if {...}
test_deny_empty_roles if {...}
test_deny_null_values if {...}

###################
# Security Tests
###################

test_deny_privilege_escalation if {...}
test_deny_self_modification if {...}

###################
# Decision Tests
###################

test_decision_structure if {...}
test_decision_reason if {...}
```

## Common Testing Mistakes

### 1. Not Testing Denials

**Wrong:**
```rego
# Only tests that things work
test_allow_admin if {
    policy.allow with input as admin_request
}
```

**Right:**
```rego
# Test both allow AND deny
test_allow_admin if {
    policy.allow with input as admin_request
}

test_deny_non_admin if {
    not policy.allow with input as guest_request
}
```

### 2. Insufficient Edge Cases

**Wrong:**
```rego
# Only happy path
test_allow_user if {
    policy.allow with input as valid_user_request
}
```

**Right:**
```rego
test_allow_user if {...}
test_deny_missing_user if {...}
test_deny_null_user_id if {...}
test_deny_empty_roles if {...}
```

### 3. Not Using Fixtures

**Wrong:**
```rego
# Duplicated test data
test_one if {
    policy.allow with input as {
        "user": {"id": "admin", "roles": ["admin"]},
        "action": "read"
    }
}

test_two if {
    policy.allow with input as {
        "user": {"id": "admin", "roles": ["admin"]},
        "action": "write"
    }
}
```

**Right:**
```rego
admin_user := {"id": "admin", "roles": ["admin"]}

test_admin_read if {
    policy.allow with input as {"user": admin_user, "action": "read"}
}

test_admin_write if {
    policy.allow with input as {"user": admin_user, "action": "write"}
}
```
