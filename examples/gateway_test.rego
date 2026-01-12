# Tests for API Gateway policy

package examples.gateway_test

import rego.v1
import data.examples.gateway

###################
# Test Fixtures
###################

# Valid tokens
admin_token := {
    "sub": "admin-1",
    "roles": ["admin"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": true
}

manager_token := {
    "sub": "manager-1",
    "roles": ["manager"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": true
}

user_token := {
    "sub": "user-1",
    "roles": ["user"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": true
}

developer_token := {
    "sub": "dev-1",
    "roles": ["developer"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": true
}

# Invalid tokens
expired_token := {
    "sub": "user-1",
    "roles": ["admin"],
    "exp": 1000000000,  # Expired
    "nbf": 0,
    "valid": true
}

future_token := {
    "sub": "user-1",
    "roles": ["admin"],
    "exp": 9999999999,
    "nbf": 9999999998,  # Not yet valid
    "valid": true
}

invalid_token := {
    "sub": "user-1",
    "roles": ["admin"],
    "exp": 9999999999,
    "nbf": 0,
    "valid": false
}

###################
# Public Endpoint Tests
###################

test_allow_health_endpoint if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/health"
    }
}

test_allow_public_resource if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/public/docs"
    }
}

test_allow_login_without_token if {
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v1/auth/login"
    }
}

test_allow_register_without_token if {
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v2/auth/register"
    }
}

###################
# Admin Endpoint Tests
###################

test_allow_admin_access_admin_endpoint if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/admin/settings",
        "token": admin_token
    }
}

test_deny_user_access_admin_endpoint if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/admin/settings",
        "token": user_token
    }
}

test_deny_manager_access_admin_endpoint if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/admin/settings",
        "token": manager_token
    }
}

###################
# User Management Tests
###################

test_allow_admin_create_user if {
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v1/users",
        "token": admin_token
    }
}

test_deny_user_create_user if {
    not gateway.allow with input as {
        "method": "POST",
        "path": "/api/v1/users",
        "token": user_token
    }
}

test_allow_user_read_users if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/users",
        "token": user_token
    }
}

test_allow_manager_update_user if {
    gateway.allow with input as {
        "method": "PUT",
        "path": "/api/v1/users/123",
        "token": manager_token
    }
}

test_deny_user_update_user if {
    not gateway.allow with input as {
        "method": "PUT",
        "path": "/api/v1/users/123",
        "token": user_token
    }
}

###################
# Project Tests
###################

test_allow_any_user_read_projects if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/projects",
        "token": user_token
    }
}

test_allow_developer_create_project if {
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v1/projects",
        "token": developer_token
    }
}

test_deny_user_create_project if {
    not gateway.allow with input as {
        "method": "POST",
        "path": "/api/v1/projects",
        "token": user_token
    }
}

###################
# Token Validation Tests
###################

test_deny_expired_token if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/users",
        "token": expired_token
    }
}

test_deny_future_token if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/users",
        "token": future_token
    }
}

test_deny_invalid_token if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/users",
        "token": invalid_token
    }
}

test_deny_missing_token if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v1/users"
    }
}

###################
# Decision Tests
###################

test_decision_public_reason if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/health",
        "token": {}
    }
    result.allowed == true
    result.reason == "public endpoint"
}

test_decision_authenticated_reason if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v1/projects",
        "token": user_token
    }
    result.allowed == true
    result.reason == "authenticated with permission"
}

test_decision_expired_reason if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v1/users",
        "token": expired_token
    }
    result.allowed == false
    result.reason == "invalid or expired token"
}

test_decision_permission_denied_reason if {
    result := gateway.decision with input as {
        "method": "POST",
        "path": "/api/v1/users",
        "token": user_token
    }
    result.allowed == false
    result.reason == "insufficient permissions"
}
