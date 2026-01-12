# Ticket Domain Actions Policy
# Version: 1.0.0
# Purpose: Define ticket domain actions and category mapping for ABAC
# Domain: Ticket Processing System (service desk, support requests)

package paas.request.actions

import rego.v1

###################
# Domain Actions
###################

# All valid actions in the request domain
# Following naming convention: <verb>_<resource-singular>
request_domain_actions := [
    "list_request",           # List project requests
    "view_request",           # Get request details
    "create_request",         # Submit new request
    "view_request_activity",  # View activity log
    "list_request_template",  # List available templates
    "view_request_template"   # Get template fields (for form)
]

# Check if action belongs to request domain
is_request_action(action) if {
    action in request_domain_actions
}

###################
# Category Mapping
###################

# Permission category assignments
# Category expansion allows role definitions to grant categories (read, write, etc.)
# which are then expanded to specific actions
category_actions := {
    "read": [
        "list_request",
        "view_request",
        "view_request_activity",
        "list_request_template",
        "view_request_template"
    ],
    "write": [
        "create_request"
    ],
    "delete": [],  # No delete - requests are managed by workflow
    "deploy": [],  # N/A for requests
    "manage": []   # N/A for requests
}

# Get all actions for a given category
actions_for_category(category) := actions if {
    actions := category_actions[category]
}

# Check if an action belongs to a category
action_in_category(action, category) if {
    some a in category_actions[category]
    a == action
}

###################
# Permission Resolution
###################

# Role definition structure expected:
# {
#   "permissions": {
#     "request": ["read", "write"]  # Categories granted
#   }
# }

default has_permission := false

# Check if role_definition grants permission for action
has_permission if {
    # Get required action from input
    action := input.action

    # Ensure it's a request domain action
    is_request_action(action)

    # Get role's request permissions (categories)
    role_categories := input.role_definition.permissions.request

    # Check if any granted category includes this action
    some category in role_categories
    action_in_category(action, category)
}

###################
# Structured Decision
###################

# Return detailed decision for debugging and audit
decision := result if {
    has_permission
    result := {
        "allowed": true,
        "reason": "role has permission",
        "action": input.action,
        "granted_categories": input.role_definition.permissions.request
    }
}

decision := result if {
    not has_permission
    is_request_action(input.action)
    result := {
        "allowed": false,
        "reason": "insufficient permissions",
        "action": input.action,
        "required_domain": "request"
    }
}

decision := result if {
    not is_request_action(input.action)
    result := {
        "allowed": false,
        "reason": "unknown action",
        "action": input.action
    }
}

###################
# Helper Functions
###################

# Get the category required for a specific action
required_category(action) := category if {
    some cat, actions in category_actions
    action in actions
    category := cat
}
