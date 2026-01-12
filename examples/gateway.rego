# API Gateway Authorization Example
# Demonstrates JWT validation and path-based authorization

package examples.gateway

import rego.v1

# Expected input:
# {
#   "method": "GET" | "POST" | "PUT" | "DELETE",
#   "path": "/api/v1/users/123",
#   "token": {
#     "sub": "user-123",
#     "roles": ["user", "admin"],
#     "exp": 1735689600,
#     "nbf": 1735600000,
#     "valid": true
#   }
# }

default allow := false

# Public endpoints don't require authentication
allow if is_public_endpoint

# Authenticated requests with valid token and permission
allow if {
    is_authenticated
    has_endpoint_permission
}

###################
# Authentication
###################

is_authenticated if {
    input.token.valid == true
    token_not_expired
    token_active
}

token_not_expired if {
    now := time.now_ns() / 1e9  # Convert to seconds
    input.token.exp > now
}

token_active if {
    now := time.now_ns() / 1e9
    input.token.nbf <= now
}

###################
# Public Endpoints
###################

is_public_endpoint if {
    some pattern in public_patterns
    glob.match(pattern, [], input.path)
}

public_patterns := [
    "/api/health",
    "/api/health/*",
    "/api/public/*",
    "/api/v*/auth/login",
    "/api/v*/auth/register"
]

###################
# Permission Checks
###################

has_endpoint_permission if {
    some rule in endpoint_rules
    method_matches(rule)
    path_matches(rule)
    role_matches(rule)
}

method_matches(rule) if {
    rule.methods[_] == input.method
}

method_matches(rule) if {
    rule.methods[_] == "*"
}

path_matches(rule) if {
    glob.match(rule.path, [], input.path)
}

role_matches(rule) if {
    some required_role in rule.roles
    some user_role in input.token.roles
    required_role == user_role
}

role_matches(rule) if {
    rule.roles[_] == "*"
}

###################
# Endpoint Rules
###################

endpoint_rules := [
    # Admin-only endpoints
    {
        "path": "/api/v*/admin/*",
        "methods": ["*"],
        "roles": ["admin"]
    },
    # User management - admins and managers
    {
        "path": "/api/v*/users",
        "methods": ["GET"],
        "roles": ["admin", "manager", "user"]
    },
    {
        "path": "/api/v*/users/*",
        "methods": ["GET"],
        "roles": ["admin", "manager", "user"]
    },
    {
        "path": "/api/v*/users",
        "methods": ["POST"],
        "roles": ["admin"]
    },
    {
        "path": "/api/v*/users/*",
        "methods": ["PUT", "DELETE"],
        "roles": ["admin", "manager"]
    },
    # Projects - any authenticated user can read
    {
        "path": "/api/v*/projects",
        "methods": ["GET"],
        "roles": ["*"]
    },
    {
        "path": "/api/v*/projects/*",
        "methods": ["GET"],
        "roles": ["*"]
    },
    {
        "path": "/api/v*/projects",
        "methods": ["POST"],
        "roles": ["admin", "manager", "developer"]
    },
    {
        "path": "/api/v*/projects/*",
        "methods": ["PUT", "DELETE"],
        "roles": ["admin", "manager"]
    }
]

###################
# Decision Output
###################

decision := {
    "allowed": allow,
    "reason": reason,
    "path": input.path,
    "method": input.method,
    "user": object.get(input.token, "sub", "anonymous")
}

reason := "public endpoint" if is_public_endpoint
reason := "authenticated with permission" if {
    not is_public_endpoint
    is_authenticated
    has_endpoint_permission
}
reason := "invalid or expired token" if {
    not is_public_endpoint
    not is_authenticated
}
reason := "insufficient permissions" if {
    not is_public_endpoint
    is_authenticated
    not has_endpoint_permission
}
