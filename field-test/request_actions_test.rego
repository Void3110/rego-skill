# Tests for Request Domain Actions Policy

package paas.request.actions_test

import data.paas.request.actions

###################
# Test Fixtures
###################

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

role_admin := {
    "name": "admin",
    "permissions": {
        "request": ["read", "write", "delete", "manage"]
    }
}

role_no_request := {
    "name": "other",
    "permissions": {
        "project": ["read", "write"]
    }
}

role_empty := {
    "name": "empty",
    "permissions": {}
}

###################
# Domain Action Tests
###################

test_is_request_action_list if {
    actions.is_request_action("list_request")
}

test_is_request_action_view if {
    actions.is_request_action("view_request")
}

test_is_request_action_create if {
    actions.is_request_action("create_request")
}

test_is_request_action_activity if {
    actions.is_request_action("view_request_activity")
}

test_is_request_action_list_template if {
    actions.is_request_action("list_request_template")
}

test_is_request_action_view_template if {
    actions.is_request_action("view_request_template")
}

test_not_request_action_unknown if {
    not actions.is_request_action("delete_request")
}

test_not_request_action_other_domain if {
    not actions.is_request_action("list_project")
}

###################
# Category Mapping Tests
###################

test_read_category_contains_list if {
    actions.action_in_category("list_request", "read")
}

test_read_category_contains_view if {
    actions.action_in_category("view_request", "read")
}

test_read_category_contains_activity if {
    actions.action_in_category("view_request_activity", "read")
}

test_read_category_contains_list_template if {
    actions.action_in_category("list_request_template", "read")
}

test_read_category_contains_view_template if {
    actions.action_in_category("view_request_template", "read")
}

test_write_category_contains_create if {
    actions.action_in_category("create_request", "write")
}

test_create_not_in_read_category if {
    not actions.action_in_category("create_request", "read")
}

test_list_not_in_write_category if {
    not actions.action_in_category("list_request", "write")
}

test_delete_category_empty if {
    count(actions.category_actions.delete) == 0
}

###################
# Permission Tests - Reader Role
###################

test_reader_can_list_request if {
    actions.has_permission with input as {
        "action": "list_request",
        "role_definition": role_reader
    }
}

test_reader_can_view_request if {
    actions.has_permission with input as {
        "action": "view_request",
        "role_definition": role_reader
    }
}

test_reader_can_view_activity if {
    actions.has_permission with input as {
        "action": "view_request_activity",
        "role_definition": role_reader
    }
}

test_reader_cannot_create_request if {
    not actions.has_permission with input as {
        "action": "create_request",
        "role_definition": role_reader
    }
}

###################
# Permission Tests - Writer Role
###################

test_writer_can_list_request if {
    actions.has_permission with input as {
        "action": "list_request",
        "role_definition": role_writer
    }
}

test_writer_can_create_request if {
    actions.has_permission with input as {
        "action": "create_request",
        "role_definition": role_writer
    }
}

###################
# Permission Tests - Admin Role
###################

test_admin_can_list_request if {
    actions.has_permission with input as {
        "action": "list_request",
        "role_definition": role_admin
    }
}

test_admin_can_create_request if {
    actions.has_permission with input as {
        "action": "create_request",
        "role_definition": role_admin
    }
}

###################
# Permission Tests - Edge Cases
###################

test_deny_no_request_permissions if {
    not actions.has_permission with input as {
        "action": "list_request",
        "role_definition": role_no_request
    }
}

test_deny_empty_permissions if {
    not actions.has_permission with input as {
        "action": "list_request",
        "role_definition": role_empty
    }
}

test_deny_unknown_action if {
    not actions.has_permission with input as {
        "action": "delete_request",
        "role_definition": role_admin
    }
}

test_deny_missing_role_definition if {
    not actions.has_permission with input as {
        "action": "list_request"
    }
}

###################
# Decision Tests
###################

test_decision_allowed_shows_reason if {
    result := actions.decision with input as {
        "action": "list_request",
        "role_definition": role_reader
    }
    result.allowed == true
    result.reason == "role has permission"
    result.action == "list_request"
}

test_decision_denied_shows_reason if {
    result := actions.decision with input as {
        "action": "create_request",
        "role_definition": role_reader
    }
    result.allowed == false
    result.reason == "insufficient permissions"
}

test_decision_unknown_action if {
    result := actions.decision with input as {
        "action": "unknown_action",
        "role_definition": role_reader
    }
    result.allowed == false
    result.reason == "unknown action"
}

###################
# Helper Function Tests
###################

test_required_category_for_list if {
    actions.required_category("list_request") == "read"
}

test_required_category_for_create if {
    actions.required_category("create_request") == "write"
}

test_actions_for_read_category if {
    result := actions.actions_for_category("read")
    count(result) == 5
    "list_request" in result
    "view_request" in result
}

test_actions_for_write_category if {
    result := actions.actions_for_category("write")
    count(result) == 1
    "create_request" in result
}
