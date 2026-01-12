# Security Review Checklist

Use this checklist when reviewing Rego policies for security vulnerabilities.

## 1. Authorization Bypass Prevention

### Default Deny

- [ ] Policy has explicit `default allow := false`
- [ ] No unconditional `allow := true` statements
- [ ] All paths through policy result in explicit allow or implicit deny

**Vulnerable:**
```rego
# DANGEROUS: No default deny
allow if {
    input.user.role == "admin"
}
# If user.role is missing, allow is undefined (not false!)
```

**Secure:**
```rego
default allow := false

allow if {
    input.user.role == "admin"
}
```

### Super-Admin Bypass

- [ ] Super-admin checks are intentional and documented
- [ ] Super-admin cannot be assigned through normal flows

**Review carefully:**
```rego
# Is this intentional?
allow if {
    input.user.is_super_admin == true
}
```

## 2. Input Validation

### Required Fields

- [ ] All required fields are checked for existence
- [ ] Missing fields result in denial, not errors

**Vulnerable:**
```rego
allow if {
    input.user.id == input.resource.owner_id  # Fails if fields missing
}
```

**Secure:**
```rego
allow if {
    input.user.id  # Ensures field exists
    input.resource.owner_id
    input.user.id == input.resource.owner_id
}
```

### Type Validation

- [ ] Type assertions used where needed
- [ ] Array/object structure validated

```rego
valid_input if {
    is_string(input.user.id)
    is_array(input.user.roles)
    count(input.user.id) > 0
    count(input.user.id) < 256
}
```

### Null Handling

- [ ] Null values handled explicitly
- [ ] `object.get` used with defaults for optional fields

```rego
# Safe access with default
user_department := object.get(input.user, "department", "unknown")

# Explicit null check
valid_user if {
    input.user.id != null
    input.user.id != ""
}
```

## 3. Privilege Escalation Prevention

### Role Level Hierarchy

- [ ] Role comparisons use strict inequality where needed
- [ ] Users cannot assign roles higher than their own

```rego
# User can only modify users with LOWER level
can_modify_user if {
    user_level := role_levels[input.user.role]
    target_level := role_levels[input.target.role]
    user_level > target_level  # Strictly greater, not >=
}

role_levels := {
    "owner": 100,
    "admin": 90,
    "manager": 70,
    "user": 50
}
```

### Self-Modification

- [ ] Self-modification blocked where required
- [ ] Users cannot elevate their own privileges

```rego
# Prevent self-role-change
can_change_role if {
    input.user.id != input.target.id  # Not self
    can_modify_user
}
```

### Protected Roles

- [ ] System roles cannot be modified
- [ ] Protected roles cannot be assigned by non-admins

```rego
protected_roles := {"owner", "system", "superadmin"}

can_assign_role if {
    not input.target_role in protected_roles
    # ... other conditions
}
```

## 4. Path and Pattern Vulnerabilities

### Path Traversal

- [ ] Path inputs normalized before comparison
- [ ] `..` sequences blocked or handled
- [ ] No direct string comparison for paths

**Vulnerable:**
```rego
# Can be bypassed with /../admin
allow if {
    startswith(input.path, "/public")
}
```

**Secure:**
```rego
allow if {
    normalized := normalize_path(input.path)
    not contains(normalized, "..")
    startswith(normalized, "/public/")
}

normalize_path(path) := result if {
    # Remove double slashes, resolve . and ..
    parts := split(path, "/")
    cleaned := [p | p := parts[_]; p != ""; p != "."]
    result := concat("/", cleaned)
}
```

### Regex Injection (ReDoS)

- [ ] User input not used directly in regex patterns
- [ ] Complex regex patterns reviewed for catastrophic backtracking

**Vulnerable:**
```rego
# User-controlled pattern = ReDoS risk
allow if {
    regex.match(input.pattern, input.path)
}
```

**Secure:**
```rego
# Use literal matching or predefined patterns
allow if {
    some pattern in allowed_patterns
    glob.match(pattern, [], input.path)
}

allowed_patterns := ["/api/v1/*", "/public/*"]
```

## 5. Data Exposure

### Error Messages

- [ ] Denial reasons don't reveal internal structure
- [ ] Role names and permissions not leaked in errors

**Leaky:**
```rego
reason := sprintf("User lacks permission '%s' for role '%s'",
    [required_permission, input.user.role])
```

**Secure:**
```rego
reason := "Insufficient permissions"
```

### Partial Evaluation

- [ ] Sensitive data not exposed through partial eval
- [ ] Filtered results don't reveal existence of hidden items

## 6. Time-Based Vulnerabilities

### Token Expiration

- [ ] Expiration checked before access
- [ ] Clock skew considered

```rego
token_valid if {
    now := time.now_ns()
    input.token.exp * 1e9 > now  # exp is in seconds
    input.token.nbf * 1e9 < now  # not before
}
```

### Time-of-Check vs Time-of-Use

- [ ] Data consistency verified
- [ ] Stale cache considerations documented

## 7. Common Vulnerabilities Summary

| Vulnerability | Check | Fix |
|--------------|-------|-----|
| No default deny | `default allow := false` | Add explicit default |
| Missing field crash | Field existence | Check before compare |
| Path traversal | `contains(path, "..")` | Normalize and validate |
| Privilege escalation | Level comparison | Strict inequality |
| Self-modification | User ID comparison | Block self-changes |
| ReDoS | Regex with user input | Use glob or literals |
| Info leakage | Error messages | Generic messages |
| Token bypass | Expiration check | Validate timestamps |

## Security Review Template

```
## Policy: [name]
## Reviewer: [name]
## Date: [date]

### Checks Performed

- [ ] Default deny verified
- [ ] Input validation reviewed
- [ ] Privilege escalation paths checked
- [ ] Path/pattern vulnerabilities checked
- [ ] Data exposure reviewed
- [ ] Time-based checks verified
- [ ] Test coverage adequate

### Findings

1. [Finding 1]
   - Severity: [High/Medium/Low]
   - Location: [file:line]
   - Recommendation: [fix]

### Approval

- [ ] Approved for deployment
- [ ] Requires changes
```
