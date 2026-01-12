# Tests for Request API Gateway Authorization Policy

package paas.request.gateway_test

import rego.v1
import data.paas.request.gateway

###################
# Test Fixtures
###################

# Valid tokens
valid_token := {
    "sub": "user-123",
    "exp": 9999999999,
    "nbf": 0,
    "valid": true
}

expired_token := {
    "sub": "user-123",
    "exp": 1000000000,  # Expired
    "nbf": 0,
    "valid": true
}

future_token := {
    "sub": "user-123",
    "exp": 9999999999,
    "nbf": 9999999998,  # Not yet valid
    "valid": true
}

invalid_token := {
    "sub": "user-123",
    "exp": 9999999999,
    "nbf": 0,
    "valid": false
}

# Role definitions
role_reader := {
    "name": "reader",
    "permissions": {
        "request": ["read"]
    }
}

role_writer := {
    "name": "writer",
    "permissions": {
        "request": ["read", "write"]
    }
}

role_no_request := {
    "name": "other",
    "permissions": {
        "project": ["read", "write"]
    }
}

###################
# List Requests Tests
###################

test_allow_reader_list_requests if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_allow_writer_list_requests if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_writer
    }
}

test_deny_no_token_list_requests if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "role_definition": role_reader
    }
}

test_deny_expired_token_list_requests if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": expired_token,
        "role_definition": role_reader
    }
}

test_deny_no_role_definition_list_requests if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token
    }
}

test_deny_wrong_permissions_list_requests if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_no_request
    }
}

###################
# Create Request Tests
###################

test_allow_writer_create_request if {
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_writer
    }
}

test_deny_reader_create_request if {
    not gateway.allow with input as {
        "method": "POST",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_reader
    }
}

###################
# Get Request by ID Tests
###################

test_allow_reader_get_request_by_id if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests/req-456",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_allow_get_request_uuid_format if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/550e8400-e29b-41d4-a716-446655440000/requests/660e8400-e29b-41d4-a716-446655440001",
        "token": valid_token,
        "role_definition": role_reader
    }
}

###################
# Activity Log Tests
###################

test_allow_reader_get_activity if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests/activity/req-456",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_deny_no_read_permission_activity if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests/activity/req-456",
        "token": valid_token,
        "role_definition": role_no_request
    }
}

###################
# Request Templates Tests
###################

test_allow_reader_list_templates if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/request-templates",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_allow_reader_get_template if {
    gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/request-templates/tmpl-789",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_allow_reader_update_template_fields if {
    # POST to template is for updating form field values (read permission)
    gateway.allow with input as {
        "method": "POST",
        "path": "/api/v3/projects/proj-123/request-templates/tmpl-789",
        "token": valid_token,
        "role_definition": role_reader
    }
}

###################
# Token Validation Tests
###################

test_deny_invalid_token_flag if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": invalid_token,
        "role_definition": role_reader
    }
}

test_deny_future_token if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": future_token,
        "role_definition": role_reader
    }
}

test_deny_empty_sub if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": {
            "sub": "",
            "exp": 9999999999,
            "nbf": 0,
            "valid": true
        },
        "role_definition": role_reader
    }
}

###################
# Method Validation Tests
###################

test_deny_wrong_method_put if {
    not gateway.allow with input as {
        "method": "PUT",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_writer
    }
}

test_deny_wrong_method_delete if {
    not gateway.allow with input as {
        "method": "DELETE",
        "path": "/api/v3/projects/proj-123/requests/req-456",
        "token": valid_token,
        "role_definition": role_writer
    }
}

###################
# Path Edge Cases
###################

test_deny_non_request_path if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/environments",
        "token": valid_token,
        "role_definition": role_reader
    }
}

test_deny_v2_api_version if {
    not gateway.allow with input as {
        "method": "GET",
        "path": "/api/v2/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_reader
    }
}

###################
# Decision Tests
###################

test_decision_authorized_shows_details if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_reader
    }
    result.allowed == true
    result.reason == "authorized"
    result.user == "user-123"
}

test_decision_not_authenticated if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": invalid_token,
        "role_definition": role_reader
    }
    result.allowed == false
    result.reason == "not authenticated"
}

test_decision_expired_token if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": expired_token,
        "role_definition": role_reader
    }
    result.allowed == false
    result.reason == "token expired or not yet valid"
}

test_decision_not_team_member if {
    result := gateway.decision with input as {
        "method": "GET",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token
    }
    result.allowed == false
    result.reason == "not a team member"
}

test_decision_insufficient_permissions if {
    result := gateway.decision with input as {
        "method": "POST",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_reader
    }
    result.allowed == false
    result.reason == "insufficient permissions"
    result.required_permission == "write"
}

test_decision_unknown_method if {
    result := gateway.decision with input as {
        "method": "PATCH",
        "path": "/api/v3/projects/proj-123/requests",
        "token": valid_token,
        "role_definition": role_writer
    }
    result.allowed == false
    result.reason == "unknown endpoint or method"
}

###################
# Helper Function Tests
###################

test_is_authenticated_valid if {
    gateway.is_authenticated with input as {
        "token": valid_token
    }
}

test_not_authenticated_invalid if {
    not gateway.is_authenticated with input as {
        "token": invalid_token
    }
}

test_has_role_definition if {
    gateway.has_role_definition with input as {
        "role_definition": role_reader
    }
}

test_not_has_role_definition_missing if {
    not gateway.has_role_definition with input as {}
}

test_is_request_path_requests if {
    gateway.is_request_path with input as {
        "path": "/api/v3/projects/proj-123/requests"
    }
}

test_is_request_path_templates if {
    gateway.is_request_path with input as {
        "path": "/api/v3/projects/proj-123/request-templates"
    }
}

test_not_request_path_other if {
    not gateway.is_request_path with input as {
        "path": "/api/v3/projects/proj-123/environments"
    }
}

test_user_request_categories_present if {
    result := gateway.user_request_categories with input as {
        "role_definition": role_reader
    }
    result == ["read"]
}

test_user_request_categories_empty if {
    result := gateway.user_request_categories with input as {
        "role_definition": role_no_request
    }
    count(result) == 0
}
