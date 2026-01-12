# Field Test: Ticket Processing API

This directory contains policies generated during rego-skill field testing using a real-world Ticket Processing System API as the target.

## API Overview

A project-scoped ticket management system where:
- Users submit service requests/tickets within projects
- Team membership determines access
- Role permissions control read/write capabilities
- Tickets follow a workflow lifecycle (creating → processing → done)

## Endpoints Covered

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| GET | `/api/v3/projects/{id}/requests` | List project tickets | read |
| POST | `/api/v3/projects/{id}/requests` | Submit new ticket | write |
| GET | `/api/v3/projects/{id}/requests/{rid}` | Get ticket details | read |
| GET | `/api/v3/projects/{id}/requests/activity/{rid}` | View activity log | read |
| GET | `/api/v3/projects/{id}/request-templates` | List ticket templates | read |
| GET/POST | `/api/v3/projects/{id}/request-templates/{tid}` | Get/update template | read |

## Generated Policies

### request_actions.rego
Domain action definitions and category mapping:
- 6 actions: `list_request`, `view_request`, `create_request`, etc.
- Category expansion: `read` → 5 actions, `write` → 1 action
- Permission resolution based on role definitions

### request_gateway.rego
API gateway authorization:
- Endpoint pattern matching with regex
- Token validation (exp, nbf, valid)
- Team membership check via role_definition
- Permission requirement per endpoint

## Test Results

```
$ opa test . -v
PASS: 73/73

$ opa test . --coverage
Coverage: 99.5%
```

## Security Verification

All checklist items passed:
- [x] Default deny explicit
- [x] No unconditional allow
- [x] Input validation present
- [x] Token expiration checked
- [x] Tests cover allow AND deny cases
- [x] Edge cases covered (expired, future, empty, missing)

## Usage

Run tests:
```bash
cd field-test
opa test . -v
```

These policies demonstrate rego-skill generating production-quality authorization for a real API with comprehensive test coverage.
