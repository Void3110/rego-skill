# Ticket API Gateway Authorization Policy
# Version: 1.0.0
# Purpose: Authorize HTTP requests to Ticket Processing API endpoints
# Domain: Ticket Processing System (service desk, support requests)
#
# Covered Endpoints:
# | Method | Path                                              | Permission |
# |--------|---------------------------------------------------|------------|
# | GET    | /api/v3/projects/{id}/requests                    | read       |
# | POST   | /api/v3/projects/{id}/requests                    | write      |
# | GET    | /api/v3/projects/{id}/requests/{rid}              | read       |
# | GET    | /api/v3/projects/{id}/requests/activity/{rid}     | read       |
# | GET    | /api/v3/projects/{id}/request-templates           | read       |
# | GET/POST | /api/v3/projects/{id}/request-templates/{tid}   | read       |

package paas.request.gateway

import rego.v1

###################
# Default Deny
###################

default allow := false

###################
# Endpoint Definitions
###################

# Request API endpoint patterns
# All endpoints require: authenticated user + team membership + permission
request_endpoints := [
    {
        "pattern": "^/api/v3/projects/[^/]+/requests$",
        "methods": ["GET"],
        "permission": "read",
        "description": "List project requests"
    },
    {
        "pattern": "^/api/v3/projects/[^/]+/requests$",
        "methods": ["POST"],
        "permission": "write",
        "description": "Create new request"
    },
    {
        "pattern": "^/api/v3/projects/[^/]+/requests/[^/]+$",
        "methods": ["GET"],
        "permission": "read",
        "description": "Get request by ID"
    },
    {
        "pattern": "^/api/v3/projects/[^/]+/requests/activity/[^/]+$",
        "methods": ["GET"],
        "permission": "read",
        "description": "Get request activity log"
    },
    {
        "pattern": "^/api/v3/projects/[^/]+/request-templates$",
        "methods": ["GET"],
        "permission": "read",
        "description": "List request templates"
    },
    {
        "pattern": "^/api/v3/projects/[^/]+/request-templates/[^/]+$",
        "methods": ["GET", "POST"],
        "permission": "read",
        "description": "Get/update template fields"
    }
]

###################
# Helper Functions
###################

# Check if user is authenticated
is_authenticated if {
    input.token.valid == true
    is_string(input.token.sub)
    count(input.token.sub) > 0
}

# Check if token is not expired
token_valid if {
    is_authenticated
    now := time.now_ns()
    input.token.exp * 1e9 > now
    input.token.nbf * 1e9 <= now
}

# Check if user has a role definition (is team member)
has_role_definition if {
    is_object(input.role_definition)
    is_object(input.role_definition.permissions)
}

# Check if role has permission category for requests
role_has_permission(required_category) if {
    categories := input.role_definition.permissions.request
    required_category in categories
}

# Find matching endpoint for current request
matching_endpoint := endpoint if {
    some endpoint in request_endpoints
    regex.match(endpoint.pattern, input.path)
    input.method in endpoint.methods
}

# Check if this is a request API path
is_request_path if {
    regex.match("^/api/v3/projects/[^/]+/request", input.path)
}

###################
# Authorization Rules
###################

# Main allow rule - all conditions must be met
allow if {
    token_valid
    has_role_definition
    endpoint := matching_endpoint
    role_has_permission(endpoint.permission)
}

###################
# Structured Decision
###################

# Detailed decision for debugging and audit
decision := result if {
    not is_request_path
    result := {
        "allowed": false,
        "reason": "not a request endpoint",
        "path": input.path
    }
}

decision := result if {
    is_request_path
    not is_authenticated
    result := {
        "allowed": false,
        "reason": "not authenticated",
        "path": input.path
    }
}

decision := result if {
    is_request_path
    is_authenticated
    not token_valid
    result := {
        "allowed": false,
        "reason": "token expired or not yet valid",
        "path": input.path
    }
}

decision := result if {
    is_request_path
    token_valid
    not has_role_definition
    result := {
        "allowed": false,
        "reason": "not a team member",
        "path": input.path,
        "user": input.token.sub
    }
}

decision := result if {
    is_request_path
    token_valid
    has_role_definition
    not matching_endpoint
    result := {
        "allowed": false,
        "reason": "unknown endpoint or method",
        "path": input.path,
        "method": input.method
    }
}

decision := result if {
    is_request_path
    token_valid
    has_role_definition
    endpoint := matching_endpoint
    not role_has_permission(endpoint.permission)
    result := {
        "allowed": false,
        "reason": "insufficient permissions",
        "path": input.path,
        "required_permission": endpoint.permission,
        "user_categories": input.role_definition.permissions.request
    }
}

decision := result if {
    allow
    endpoint := matching_endpoint
    result := {
        "allowed": true,
        "reason": "authorized",
        "path": input.path,
        "endpoint": endpoint.description,
        "user": input.token.sub
    }
}

###################
# Debug Helpers
###################

# Get all categories user has for requests
user_request_categories := categories if {
    categories := input.role_definition.permissions.request
} else := []
