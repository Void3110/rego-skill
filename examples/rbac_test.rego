# Tests for RBAC policy

package examples.rbac_test

import rego.v1
import data.examples.rbac

###################
# Test Fixtures
###################

admin_user := {
    "id": "admin-1",
    "roles": ["admin"]
}

editor_user := {
    "id": "editor-1",
    "roles": ["editor"]
}

viewer_user := {
    "id": "viewer-1",
    "roles": ["viewer"]
}

guest_user := {
    "id": "guest-1",
    "roles": ["guest"]
}

multi_role_user := {
    "id": "multi-1",
    "roles": ["viewer", "editor"]
}

no_roles_user := {
    "id": "norole-1",
    "roles": []
}

sample_resource := {
    "type": "document",
    "id": "doc-123"
}

###################
# Admin Tests
###################

test_allow_admin_read if {
    rbac.allow with input as {
        "user": admin_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_allow_admin_write if {
    rbac.allow with input as {
        "user": admin_user,
        "action": "write",
        "resource": sample_resource
    }
}

test_allow_admin_delete if {
    rbac.allow with input as {
        "user": admin_user,
        "action": "delete",
        "resource": sample_resource
    }
}

###################
# Editor Tests
###################

test_allow_editor_read if {
    rbac.allow with input as {
        "user": editor_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_allow_editor_write if {
    rbac.allow with input as {
        "user": editor_user,
        "action": "write",
        "resource": sample_resource
    }
}

test_deny_editor_delete if {
    not rbac.allow with input as {
        "user": editor_user,
        "action": "delete",
        "resource": sample_resource
    }
}

###################
# Viewer Tests
###################

test_allow_viewer_read if {
    rbac.allow with input as {
        "user": viewer_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_deny_viewer_write if {
    not rbac.allow with input as {
        "user": viewer_user,
        "action": "write",
        "resource": sample_resource
    }
}

test_deny_viewer_delete if {
    not rbac.allow with input as {
        "user": viewer_user,
        "action": "delete",
        "resource": sample_resource
    }
}

###################
# Guest Tests
###################

test_deny_guest_read if {
    not rbac.allow with input as {
        "user": guest_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_deny_guest_write if {
    not rbac.allow with input as {
        "user": guest_user,
        "action": "write",
        "resource": sample_resource
    }
}

###################
# Multi-Role Tests
###################

test_allow_multi_role_read if {
    rbac.allow with input as {
        "user": multi_role_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_allow_multi_role_write if {
    rbac.allow with input as {
        "user": multi_role_user,
        "action": "write",
        "resource": sample_resource
    }
}

###################
# Edge Case Tests
###################

test_deny_no_roles if {
    not rbac.allow with input as {
        "user": no_roles_user,
        "action": "read",
        "resource": sample_resource
    }
}

test_deny_missing_user if {
    not rbac.allow with input as {
        "action": "read",
        "resource": sample_resource
    }
}

# Note: Missing action causes undefined, which is treated as not-allow
# This is expected Rego behavior - policy is safe by default

###################
# Decision Tests
###################

test_decision_admin_reason if {
    result := rbac.decision with input as {
        "user": admin_user,
        "action": "read",
        "resource": sample_resource
    }
    result.allowed == true
    result.reason == "admin access"
}

test_decision_permission_reason if {
    result := rbac.decision with input as {
        "user": viewer_user,
        "action": "read",
        "resource": sample_resource
    }
    result.allowed == true
    result.reason == "role permission"
}

test_decision_denied_reason if {
    result := rbac.decision with input as {
        "user": guest_user,
        "action": "read",
        "resource": sample_resource
    }
    result.allowed == false
    result.reason == "denied: insufficient permissions"
}
