# Policy Generation Guide

## Step-by-Step Process

### 1. Clarify Requirements

Before writing any code, understand:

- **Who**: What users/roles/attributes are involved?
- **What**: What resources are being accessed?
- **When**: Are there time-based or context conditions?
- **Input structure**: What does the input JSON look like?

Ask clarifying questions if requirements are unclear.

### 2. Define Input Structure

Document the expected input:

```rego
# Expected input structure:
# {
#   "user": {
#     "id": "user-123",
#     "roles": ["admin", "developer"],
#     "department": "engineering",
#     "tags": {"clearance": "secret"}
#   },
#   "action": "read",
#   "resource": {
#     "type": "document",
#     "id": "doc-456",
#     "owner_id": "user-789",
#     "classification": "confidential"
#   }
# }
```

### 3. Start with Default Deny

```rego
package authorization

import rego.v1

default allow := false
```

### 4. Implement Allow Rules

Write specific, explicit conditions:

```rego
# Rule 1: Owners can access their resources
allow if {
    input.user.id == input.resource.owner_id
}

# Rule 2: Admins can access everything
allow if {
    "admin" in input.user.roles
}

# Rule 3: Department members can read department resources
allow if {
    input.action == "read"
    input.user.department == input.resource.department
}
```

### 5. Add Helper Rules

Extract complex logic into named rules:

```rego
is_owner if {
    input.user.id == input.resource.owner_id
}

is_admin if {
    "admin" in input.user.roles
}

has_clearance if {
    user_clearance := object.get(input.user.tags, "clearance", "none")
    required_clearance := clearance_levels[input.resource.classification]
    clearance_rank[user_clearance] >= required_clearance
}

clearance_levels := {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3
}

clearance_rank := {
    "none": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
    "top-secret": 4
}
```

### 6. Add Structured Decision (Optional)

For debugging and audit:

```rego
decision := {
    "allowed": allow,
    "reason": reason,
    "evaluated_at": time.now_ns(),
    "user": input.user.id,
    "action": input.action,
    "resource": input.resource.id
}

reason := "owner access" if is_owner
reason := "admin access" if is_admin
reason := "department access" if {
    input.action == "read"
    input.user.department == input.resource.department
}
reason := "denied: no matching rule" if not allow
```

### 7. Write Comprehensive Tests

Create `policy_test.rego`:

```rego
package authorization_test

import rego.v1
import data.authorization

# Test fixtures
admin_user := {
    "id": "admin-1",
    "roles": ["admin"],
    "department": "IT"
}

owner_user := {
    "id": "user-123",
    "roles": ["developer"],
    "department": "engineering"
}

other_user := {
    "id": "user-456",
    "roles": ["developer"],
    "department": "sales"
}

test_resource := {
    "type": "document",
    "id": "doc-1",
    "owner_id": "user-123",
    "department": "engineering"
}

# Allow tests
test_allow_owner if {
    authorization.allow with input as {
        "user": owner_user,
        "action": "write",
        "resource": test_resource
    }
}

test_allow_admin if {
    authorization.allow with input as {
        "user": admin_user,
        "action": "delete",
        "resource": test_resource
    }
}

test_allow_department_read if {
    authorization.allow with input as {
        "user": {"id": "eng-user", "roles": [], "department": "engineering"},
        "action": "read",
        "resource": test_resource
    }
}

# Deny tests
test_deny_other_user_write if {
    not authorization.allow with input as {
        "user": other_user,
        "action": "write",
        "resource": test_resource
    }
}

test_deny_department_write if {
    not authorization.allow with input as {
        "user": {"id": "eng-user", "roles": [], "department": "engineering"},
        "action": "write",
        "resource": test_resource
    }
}

# Edge case tests
test_deny_missing_user if {
    not authorization.allow with input as {
        "action": "read",
        "resource": test_resource
    }
}

test_deny_empty_roles if {
    not authorization.allow with input as {
        "user": {"id": "user-1", "roles": [], "department": "other"},
        "action": "write",
        "resource": test_resource
    }
}
```

### 8. Validate

```bash
# Check syntax
opa check policy.rego policy_test.rego

# Run tests
opa test . -v

# Check coverage
opa test . --coverage --format=json | jq '.coverage'

# Format
opa fmt -w *.rego
```

## Template

Use this template for new policies:

```rego
package [package_name]

import rego.v1

# Expected input structure:
# {
#   "user": {...},
#   "action": "...",
#   "resource": {...}
# }

default allow := false

# Rule 1: [description]
allow if {
    # conditions
}

# Rule 2: [description]
allow if {
    # conditions
}

# Helper rules
# ...

# Structured decision (optional)
decision := {
    "allowed": allow,
    "reason": reason
}

reason := "[reason]" if [condition]
reason := "denied" if not allow
```
