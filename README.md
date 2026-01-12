# rego-skill

A Claude Code skill for generating, reviewing, and testing OPA Rego policies following security best practices.

## Features

- **Policy Generation** - Create secure policies with default deny
- **Security Review** - Comprehensive checklist for vulnerability detection
- **Test Generation** - Automatic test creation with allow/deny/edge cases
- **Modern Syntax** - Uses `import rego.v1` with `if`, `in`, `every` keywords
- **Structured Decisions** - Rich output for debugging and auditing

## Installation

### Personal Installation

```bash
# Clone to your Claude skills directory
git clone https://github.com/Void3110/rego-skill.git ~/.claude/skills/rego-skill
```

### Project Installation

```bash
# Clone to your project
git clone https://github.com/Void3110/rego-skill.git .claude/skills/rego-skill

# Commit to share with team
git add .claude/skills/rego-skill
git commit -m "Add rego-skill for OPA policy development"
```

## Prerequisites

- [OPA CLI](https://www.openpolicyagent.org/docs/latest/#1-download-opa) installed
- [Claude Code](https://claude.com/code) CLI

## Usage

The skill auto-activates when you mention OPA, Rego, authorization policies, or access control.

### Generate a Policy

```
User: Create a policy where admins can read, write, and delete. Editors can read and write. Viewers can only read.
```

Claude will:
1. Clarify requirements
2. Generate policy with `default allow := false`
3. Create comprehensive `*_test.rego`
4. Validate with `opa check` and `opa test . -v`
5. Review against security checklist

### Review Existing Policy

```
User: Review @policies/auth.rego for security issues
```

### Write Tests

```
User: Write tests for @policies/gateway.rego
```

## Mandatory Workflow

Every policy task follows this sequence:

1. **Understand** - Clarify requirements before writing code
2. **Generate** - Write policy with explicit default deny
3. **Test** - Create comprehensive tests with allow AND deny cases
4. **Validate** - Run `opa check` and `opa test . -v`
5. **Review** - Check against security checklist
6. **Iterate** - Fix any failures before declaring complete

## Documentation

| Document | Purpose |
|----------|---------|
| [SKILL.md](SKILL.md) | Core instructions and patterns |
| [GENERATE.md](GENERATE.md) | Step-by-step policy generation |
| [SECURITY.md](SECURITY.md) | Security review checklist |
| [TESTING.md](TESTING.md) | Test patterns and coverage |
| [BEST-PRACTICES.md](BEST-PRACTICES.md) | Performance and style |

## Examples

See `examples/` for complete working policies:

- `rbac.rego` + `rbac_test.rego` - Role-Based Access Control
- `gateway.rego` + `gateway_test.rego` - API Gateway Authorization

Run example tests:

```bash
cd examples
opa test . -v
# PASS: 41/41
```

## Quick Reference

### Default Deny Pattern

```rego
package mypackage

import rego.v1

default allow := false

allow if {
    # explicit conditions only
}
```

### Modern Rego Syntax

```rego
import rego.v1

# Use 'if' keyword
allow if {
    some role in input.user.roles
    role == "admin"
}

# Use 'contains' for sets
violations contains msg if {
    # condition
    msg := "violation message"
}

# Use 'every' for universal checks
all_valid if {
    every item in input.items {
        item.status == "approved"
    }
}
```

### Structured Decisions

```rego
decision := {
    "allowed": allowed,
    "reason": reason,
    "context": {
        "user": input.user.id,
        "action": input.action
    }
}
```

## Security Checklist

Before completing any policy:

- [ ] Default deny is explicit (`default allow := false`)
- [ ] No unconditional `allow := true`
- [ ] Input validation for required fields
- [ ] Type checking where needed (`is_string`, `is_array`)
- [ ] No path traversal vulnerabilities
- [ ] Tests cover allow AND deny cases
- [ ] Tests cover edge cases (null, empty, missing)

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Related

- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Claude Code](https://claude.com/code)
