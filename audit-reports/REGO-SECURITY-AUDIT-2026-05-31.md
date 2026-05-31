# Rego Security Audit — 2026-05-31

**Scope:** audited 4 of 4 policies (`examples/` + `field-test/`); baseline `opa test examples/ field-test/` = **PASS: 114/114**. Rubric v1 (10 checks).
**3 confirmed findings (0 Critical, 1 Medium, 2 Low), 3 cross-policy issues (0 Critical), 0 false alarms dropped.**

> Sample report produced by this skill's own suite-wide security-audit workflow (`rego-security-audit-workflow.js`), run against the policies shipped in this repo. **Report-only** — the audit never edits a policy. Each Critical/Medium finding was adversarially re-checked (the verifier actually ran `opa eval` to reproduce the bypass). Style/idiom divergence (`import future.keywords` vs `rego.v1`, `{"allow": bool}` vs bare `allow`) is never a finding.

---

## Confirmed findings (fix these)

### [Medium/PATH_TRAVERSAL] examples/gateway.rego — `glob.match` lets `*` cross `/`, bypassing the auth gate
- **Evidence:** `is_public_endpoint` / `path_matches` call `glob.match(pattern, [], input.path)` (lines 58, 89). The empty `[]` separators argument defaults to `["."]`, so `*` and `v*` match **across `/`**. `glob.match("/api/v*/auth/login", [], "/api/v1/admin/things/auth/login")` returns `true`, classifying an attacker-crafted multi-segment path as a PUBLIC, unauthenticated endpoint. `input.path` is never normalized or rejected for `..`.
- **Rubric:** SECURITY §4 (Path and Pattern Vulnerabilities).
- _verifier (reproduced with `opa eval`):_ `data.examples.gateway.allow` returns **true with no `input.token`** for `/api/v1/admin/things/auth/login`, `/api/health/admin/delete-everything`, and `/api/v1/users/123/auth/login` — because `allow if is_public_endpoint` is checked first and needs no token. `/api/v1/admin/auth/login` matches BOTH the admin rule and the public pattern, so an admin-namespace path is served anonymously. The genuine `/api/v1/admin/settings` correctly returns false. **Fix:** pass `["/"]` as the glob delimiter (closes the bypass; legit `/api/v1/auth/login` still matches) and/or reject `..`. 23/23 tests pass — a working policy with an uncovered bypass.

### [Low/DATA_EXPOSURE] examples/rbac.rego — debug `decision` object echoes caller roles
- **Evidence:** The debug `decision` object reflects `"user_roles": input.user.roles` and `"required_permission": action_to_permission[input.action]` (lines 55-56). Bounded — only the caller's OWN roles + a generic permission name, explicitly labeled "for debugging." If returned to clients (instead of the bare `allow`), it leaks internal permission naming. The load-bearing gate `allow` is a clean boolean.
- **Rubric:** SECURITY §5 (Data Exposure). Defensive nit.

### [Low/DATA_EXPOSURE] field-test/request_gateway.rego — debug `decision` echoes caller permissions
- **Evidence:** The `decision` object returns `"user_categories": input.role_definition.permissions.request` (line 197) — the caller's full request-permission list — plus `"required_permission"` and verbose reasons. Documented audit/debug output (line 130), not the gateway's load-bearing `allow`, and only the caller's OWN permissions. Low impact.
- **Rubric:** SECURITY §5 (Data Exposure).

---

## Cross-policy issues

These span the two `field-test/` request policies and a single-file audit cannot see them. Both are documented-as-intentional layering in `field-test/README.md` — but the gateway and action layers have drifted, so a reviewer should reconcile them.

### [Medium/SHARED_HELPER_DRIFT] request_gateway.rego ↔ request_actions.rego — gateway re-derives permissions instead of honoring the action policy
`request_actions.rego` (`paas.request.actions`) owns the request-domain authority: the action whitelist (`is_request_action`), the category→action map (`category_actions`), and `has_permission`. `request_gateway.rego` (`paas.request.gateway`) does **not** import it and re-implements the same "does this role's request categories grant access" decision as its own `role_has_permission(required_category)` — a category-literal membership check that skips the action whitelist and category-expansion entirely. The gateway is a second, independent authority that can **grant where the actions policy would deny**.

### [Medium/OVERLAPPING_RULES] request_gateway.rego ↔ request_actions.rego — divergent decision on template write
For `POST /api/v3/projects/{id}/request-templates/{tid}` (update template fields): the gateway maps it to permission `read` (lines 64-68), so a **reader is allowed to POST** (asserted by `test_allow_reader_update_template_fields`). `request_actions.rego` has **no** `update_request_template` action and `category_actions.write = [create_request]` only — so the same operation evaluated against the action model falls through to the unknown-action deny branch. The gateway grants what the action-level authority would not authorize.

### [Low/OVERLAPPING_RULES] request_gateway.rego ↔ request_actions.rego — operation→category maps disagree on the template POST
The two layers implement the same operation→category mapping in parallel (gateway's per-endpoint `permission` field vs actions' `category_actions`) and agree on every operation **except** the template POST (mapped to `read` at the gateway, with no corresponding action in the action vocabulary). Documented as intentional in `field-test/README.md` line 22 — but the two layers should be reconciled (e.g. add an `update_request_template` action under `read`). Confirmed clean on the other axes: no duplicate-package `eval_conflict`, the `read`/`write` vocabulary is present and non-empty, and both policies are deny-by-default.

---

## Per-policy verdicts

| Policy | Package | Decision shape | Tests | Fails | N/A | Summary |
|--------|---------|----------------|-------|-------|-----|---------|
| examples/rbac.rego | examples.rbac | bare `allow` + debug `decision` | ✅ 41/41 | 1 | 4 | Solid default-deny RBAC by role-set lookup; safe on missing/unknown input, no eval conflicts. Only nit: debug `decision` reflects caller's own roles (Low). |
| examples/gateway.rego | examples.gateway | bare `allow` + `decision`/`reason` | ✅ 23/23 | 1 | 2 | Solid default-deny gateway with proper token exp/nbf checks and non-leaky reasons; one real defect: `glob.match(..., [], path)` lets `*` cross `/` → public-pattern over-match bypasses auth (Medium). |
| field-test/request_actions.rego | paas.request.actions | bare `has_permission` + `decision` | ✅ 36/36 | 0 | 4 | Healthy authz-only action/category policy: default-deny, safe missing-input handling, mutually-exclusive decision bodies (no eval_conflict), no paths/regex/tokens. Clean. |
| field-test/request_gateway.rego | paas.request.gateway | bare `allow` + audit `decision` | ✅ 37/37 | 1 | 1 | Solid fail-closed gateway: default-deny, anchored-regex routing, exp/nbf enforced; only gap is the audit `decision` echoing the caller's permission list (Low). |

---

## Notes

- **Baseline unchanged:** `opa test examples/ field-test/` = 114/114 before and after. The workflow is read-only — it never edits a policy.
- **Highlight:** the audit found a real, reproducible auth bypass in this repo's own `examples/gateway.rego` (the `glob.match` delimiter issue) — exactly the class of defect the skill's `SECURITY.md` §4 warns about, demonstrated end-to-end with `opa eval`.
- **Convention guard held:** every policy mixes idioms (some `rego.v1`, structured-vs-bare decisions) and none was flagged for style — only genuine authorization defects.
- **Rubric v1**, 10 checks — see `SECURITY.md` / `BEST-PRACTICES.md` for definitions and `SKILL.md` → "Suite-wide security audit" for how to run it.
