# Role-Based Access Control (RBAC) Example
# Demonstrates basic RBAC with role hierarchy

package examples.rbac

# Expected input:
# {
#   "user": {"id": "...", "roles": ["admin", "developer"]},
#   "action": "read" | "write" | "delete",
#   "resource": {"type": "document", "id": "..."}
# }

default allow := false

# Admins can do anything
allow if is_admin

# Users with matching permission can perform action
allow if has_permission

# Helper: Check if user is admin
is_admin if "admin" in input.user.roles

# Helper: Check if user has required permission
has_permission if {
    required := action_to_permission[input.action]
    some role in input.user.roles
    required in role_permissions[role]
}

# Map actions to permission names
action_to_permission := {
    "read": "view",
    "list": "view",
    "write": "edit",
    "create": "edit",
    "update": "edit",
    "delete": "delete"
}

# Define role permissions
role_permissions := {
    "admin": ["view", "edit", "delete", "manage"],
    "editor": ["view", "edit"],
    "viewer": ["view"],
    "guest": []
}

# Structured decision for debugging
decision := {
    "allowed": allow,
    "reason": reason,
    "user_roles": input.user.roles,
    "required_permission": action_to_permission[input.action]
}

reason := "admin access" if is_admin
reason := "role permission" if {
    not is_admin
    has_permission
}
reason := "denied: insufficient permissions" if not allow
