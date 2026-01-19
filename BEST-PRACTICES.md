# Rego Best Practices

## Code Organization

### Package Naming

Use hierarchical, descriptive names:

```rego
package organization.domain.subdomain

# Examples:
package mycompany.authorization.api_gateway
package mycompany.authorization.team_management
package mycompany.validation.input
```

### Import Organization

Order imports consistently:

```rego
# 1. Rego version
import rego.v1

# 2. Data imports
import data.common.helpers
import data.roles.definitions

# 3. Input aliases (optional)
import input.user as current_user
import input.resource as target
```

### Rule Organization

Structure rules logically:

```rego
package authorization

import rego.v1

###################
# Default & Main Rules
###################

default allow := false

allow if is_admin
allow if is_owner
allow if has_permission

###################
# Role Checks
###################

is_admin if "admin" in input.user.roles
is_owner if input.user.id == input.resource.owner_id

###################
# Permission Checks
###################

has_permission if {
    required := action_permissions[input.action]
    some role in input.user.roles
    required in role_permissions[role]
}

###################
# Data
###################

action_permissions := {
    "read": "view",
    "write": "edit",
    "delete": "admin"
}

role_permissions := {
    "admin": ["view", "edit", "admin"],
    "editor": ["view", "edit"],
    "viewer": ["view"]
}
```

## Performance Optimization

### Avoid O(n²) Operations

**Slow:**
```rego
# Nested iteration - O(n*m)
violation contains msg if {
    some i, j
    users[i].department == departments[j].name
    # ...
}
```

**Fast:**
```rego
# Pre-index - O(n+m)
department_names := {d.name | d := departments[_]}

violation contains msg if {
    some user in users
    user.department in department_names
    # ...
}
```

### Use Early Termination

```rego
# Stops at first match
is_admin if {
    some role in input.user.roles
    role == "admin"
}
```

### Index Lookups

```rego
# Direct lookup - O(1)
user_role := role_definitions[input.user.role_id]

# vs iteration - O(n)
user_role := role if {
    some role in role_definitions
    role.id == input.user.role_id
}
```

### Avoid Unnecessary Computation

```rego
# Compute once, reuse
user_permissions := {p |
    some role in input.user.roles
    some p in role_permissions[role]
}

allow if "read" in user_permissions
deny_write if not "write" in user_permissions
```

## Modern Rego Syntax

### Use `import rego.v1`

Enables modern keywords and stricter semantics:

```rego
import rego.v1

# 'if' keyword required
allow if {
    condition
}

# 'in' keyword for membership
allow if "admin" in input.roles

# 'contains' for set rules
errors contains msg if {
    # condition
    msg := "error message"
}

# 'every' for universal quantification
all_approved if {
    every item in input.items {
        item.status == "approved"
    }
}
```

### Avoid Deprecated Patterns

**Old:**
```rego
allow {
    input.user.role == "admin"
}

errors[msg] {
    msg := "error"
}
```

**New:**
```rego
allow if {
    input.user.role == "admin"
}

errors contains msg if {
    msg := "error"
}
```

## Error Handling

### Safe Field Access

```rego
# Use object.get for optional fields
department := object.get(input.user, "department", "unknown")
clearance := object.get(input.user.tags, "clearance", "none")

# Check existence before access
valid_user if {
    input.user
    input.user.id
    is_string(input.user.id)
}
```

### Meaningful Default Values

```rego
# Provide sensible defaults
max_items := object.get(input.config, "max_items", 100)
timeout := object.get(input.config, "timeout_seconds", 30)

# Use empty collections, not null
user_roles := object.get(input.user, "roles", [])
user_tags := object.get(input.user, "tags", {})
```

## Documentation

### Rule Comments

```rego
# Allow access if user is the resource owner.
# Owners have full control over their resources regardless of role.
allow if is_owner

# Check if user has required permission for the action.
# Maps actions to permissions and checks against user's role permissions.
has_permission if {
    required := action_permissions[input.action]
    some role in input.user.roles
    required in role_permissions[role]
}
```

### Input Documentation

```rego
# Expected input structure:
# {
#   "user": {
#     "id": string,           # Required: unique user identifier
#     "roles": [string],      # Required: list of role names
#     "department": string,   # Optional: user's department
#     "tags": {string: any}   # Optional: custom attributes
#   },
#   "action": string,         # Required: "read", "write", "delete"
#   "resource": {
#     "id": string,           # Required: resource identifier
#     "type": string,         # Required: resource type
#     "owner_id": string,     # Required: owner's user id
#     "department": string    # Optional: resource department
#   }
# }
```

## Debugging

### Print Statements (Development Only)

```rego
allow if {
    print("Checking user:", input.user.id)
    print("User roles:", input.user.roles)
    is_admin
    print("User is admin, allowing")
}
```

### Trace Output

```bash
# Enable tracing
opa eval -d policy.rego -i input.json "data.policy.allow" --explain=full
```

### Structured Decisions for Debugging

```rego
decision := {
    "allowed": allow,
    "reason": reason,
    "checks": {
        "is_admin": is_admin,
        "is_owner": is_owner,
        "has_permission": has_permission
    },
    "input_summary": {
        "user_id": input.user.id,
        "action": input.action,
        "resource_id": input.resource.id
    }
}
```

## Preventing eval_conflict_error

When multiple rules can produce different outputs for the same input, OPA throws `eval_conflict_error: functions must not produce multiple outputs for same inputs`. This commonly occurs with function-like rules that handle different conditions.

### Problem: Overlapping Rule Conditions

```rego
# WRONG: These rules can both match for unknown actions!

# Rule 1: Deny if user doesn't have project access
evaluate_action(action) := decision if {
    action != "create_project"
    not has_project_access
    decision := {"allowed": false, "reason": "Access denied: must be team member"}
}

# Rule 2: Deny unknown actions
evaluate_action(action) := decision if {
    not action in known_actions
    decision := {"allowed": false, "reason": sprintf("Unknown action: %s", [action])}
}

# When action="fake_action" AND user has no project access,
# BOTH rules match and produce DIFFERENT decisions → eval_conflict_error!
```

### Solution: Ensure Mutually Exclusive Conditions

Add `action in known_actions` check to rules that should only apply to known actions:

```rego
# CORRECT: Rules are now mutually exclusive

known_actions := ["view_project", "update_project", "delete_project"]

# Rule 1: Only applies to known actions
evaluate_action(action) := decision if {
    action != "create_project"
    action in known_actions  # ← Add this check!
    not has_project_access
    decision := {"allowed": false, "reason": "Access denied: must be team member"}
}

# Rule 2: Only catches truly unknown actions
evaluate_action(action) := decision if {
    not action in known_actions
    decision := {"allowed": false, "reason": sprintf("Unknown action: %s", [action])}
}
```

### Pattern: Known Actions Whitelist

For authorization policies with multiple rules, define a whitelist and guard all rules:

```rego
# Define all known actions
known_actions := [
    "view_project", "create_project", "update_project", "delete_project",
    "view_member", "create_member", "update_member", "delete_member"
]

# Permission granted
evaluate_action(action) := decision if {
    action in known_actions  # Guard: only known actions
    has_permission(action)
    decision := {"allowed": true, "reason": ""}
}

# Permission denied
evaluate_action(action) := decision if {
    action in known_actions  # Guard: only known actions
    not has_permission(action)
    decision := {"allowed": false, "reason": "Permission denied"}
}

# No role assigned (only for known actions)
evaluate_action(action) := decision if {
    action in known_actions  # Guard: only known actions
    not has_role_definition
    decision := {"allowed": false, "reason": "No role assigned"}
}

# Catch-all for unknown actions (LAST, no guard needed)
evaluate_action(action) := decision if {
    not action in known_actions
    decision := {"allowed": false, "reason": sprintf("Unknown action: %s", [action])}
}
```

### Alternative: Use `else` Chains

For simpler cases, use `else` to create explicit priority:

```rego
evaluate_action(action) := {"allowed": true, "reason": ""} if {
    has_permission(action)
} else := {"allowed": false, "reason": "Permission denied"} if {
    action in known_actions
} else := {"allowed": false, "reason": sprintf("Unknown action: %s", [action])}
```

### Testing for Conflicts

Always test with unknown actions:

```rego
test_unknown_action_with_various_contexts if {
    # Test unknown action when user has no access
    result := evaluate_action("fake_action") with input as {
        "user": {"preferred_username": "non-member"},
        "actions": ["fake_action"]
    }
    result.allowed == false
    contains(result.reason, "Unknown action")
}
```

## Common Anti-Patterns

### 1. No Default Deny

**Wrong:**
```rego
allow if is_admin
allow if is_owner
# Missing: default allow := false
```

### 2. Implicit Dependencies

**Wrong:**
```rego
allow if {
    input.user.clearance >= 3  # What if clearance is missing?
}
```

**Right:**
```rego
allow if {
    clearance := object.get(input.user, "clearance", 0)
    clearance >= 3
}
```

### 3. Magic Numbers

**Wrong:**
```rego
allow if {
    input.user.level >= 70
}
```

**Right:**
```rego
manager_level := 70

allow if {
    input.user.level >= manager_level
}
```

### 4. Complex Inline Logic

**Wrong:**
```rego
allow if {
    some role in input.user.roles
    role in ["admin", "superadmin", "owner"]
    time.now_ns() < input.token.exp * 1e9
    input.resource.status != "deleted"
    # ... more conditions
}
```

**Right:**
```rego
allow if {
    is_privileged_role
    token_valid
    resource_accessible
}

is_privileged_role if {
    some role in input.user.roles
    role in privileged_roles
}

privileged_roles := ["admin", "superadmin", "owner"]

token_valid if {
    time.now_ns() < input.token.exp * 1e9
}

resource_accessible if {
    input.resource.status != "deleted"
}
```

### 5. Domain Logic in Policies (Critical Anti-Pattern)

OPA policies should only handle **authorization decisions** (who can do what), not **business/domain logic** (how things work). Mixing domain logic into policies creates maintenance nightmares and violates separation of concerns.

**Wrong - Domain logic in policy:**
```rego
# DON'T: Calculate discounts in policy
allow if {
    input.action == "apply_discount"
    input.user.membership == "gold"
    input.order.total >= 100
    # Policy is now calculating business rules!
    discount := input.order.total * 0.15
    discount <= input.user.max_discount
}

# DON'T: Validate business rules in policy
allow if {
    input.action == "create_order"
    count(input.order.items) > 0
    count(input.order.items) <= 50
    every item in input.order.items {
        item.quantity > 0
        item.price > 0
    }
}

# DON'T: Implement workflow state machines
allow if {
    input.action == "approve_request"
    input.request.status == "pending_review"
    input.request.reviewer_count >= 2
    input.request.created_at < time.now_ns() - 86400000000000
}
```

**Right - Pure authorization:**
```rego
# DO: Check permissions only
allow if {
    input.action == "apply_discount"
    "discount:apply" in input.user.permissions
}

# DO: Check role-based access
allow if {
    input.action == "create_order"
    has_role("order_creator")
}

# DO: Check simple authorization attributes
allow if {
    input.action == "approve_request"
    has_role("approver")
    input.user.id != input.request.created_by  # Separation of duties
}
```

**Where domain logic belongs:**
- **Application layer**: Business rules, validation, calculations
- **Domain services**: State machines, workflows, complex logic
- **Database constraints**: Data integrity rules

**What belongs in OPA policies:**
- Role/permission checks
- Attribute-based access control (ABAC)
- Resource ownership verification
- Tenant isolation
- Time-based access windows (simple)
- IP/network restrictions

**Warning signs you're adding domain logic:**
- Calculations beyond simple comparisons
- Complex validation rules
- State machine transitions
- Business rule enforcement
- Data transformation
- Workflow orchestration

## Formatting

Always format with `opa fmt`:

```bash
# Format in place
opa fmt -w policy.rego

# Check formatting
opa fmt -l policy.rego
```

## Checklist

Before committing a policy:

- [ ] `default allow := false` is present
- [ ] Uses `import rego.v1`
- [ ] Rules are organized logically
- [ ] Complex logic extracted to helper rules
- [ ] Input structure documented
- [ ] Tests exist and pass
- [ ] Code formatted with `opa fmt`
- [ ] No magic numbers
- [ ] Safe field access with defaults
- [ ] No `eval_conflict_error` risk (mutually exclusive rule conditions)
- [ ] Unknown action/input tests included
