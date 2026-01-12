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
