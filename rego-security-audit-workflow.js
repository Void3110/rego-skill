export const meta = {
  name: 'rego-security-audit',
  description: 'Suite-wide security audit of every .rego policy against the SECURITY.md + BEST-PRACTICES.md rubric — fan out one auditor per policy, adversarially verify each failed check, reason over same-package groups for cross-policy conflicts, synthesize a dated drift report. Report-only — never edits a policy.',
  whenToUse: 'Periodically, or after touching policy logic, to catch authorization-bypass / priv-esc / path-traversal / ReDoS / eval_conflict / domain-logic-leak drift across the policy corpus. The authoring path stays the rego-skill generate/test loop; this is its read-only audit sibling. Read-only against git: never switches branches or stages anything.',
  phases: [
    { title: 'Scope', detail: 'enumerate .rego policies (+ baseline opa test/check)' },
    { title: 'Audit', detail: 'one auditor per policy scores it against the CHECKS' },
    { title: 'Verify', detail: 'adversarially refute each FAILED check from the policy + tests' },
    { title: 'Synthesize', detail: 'cross-policy conflict pass + dated security drift report' },
  ],
}

// ---- args ----
// { date: "2026-05-31" }   REQUIRED — workflows cannot call Date.now(); the wrapper supplies today.
//                          If absent the skill still stamps the real date when it renders the report,
//                          so an "(undated)" payload is recoverable — but pass it.
// { policyRoot: "..." }    optional — directory to scan for *.rego. Default cwd ('.') so the skill
//                          works anywhere; pass the dir holding your policies (e.g. "policies" or ".").
// { policies: [...] }      optional — explicit policy-file list (INCREMENTAL mode; bypasses scoping + cap).
//                          The skill computes the changed-since-last-report set via git hash-object.
// { focus: "..." }         optional — free-text steer.
// { maxPolicies: 12 }      optional — cap the audited set at N policies (sizing guard: too many
//                          concurrent agents starves the verify phase). Larger/denser policies are
//                          ranked first. An explicit `policies` list bypasses the cap.
// Defensive: the harness can deliver `args` as a JSON STRING rather than a parsed object (the tool warns
// that a stringified value reaches the script verbatim). Normalize to an object so `args.x` access works
// regardless of how it arrived — otherwise every field reads undefined and the workflow silently falls
// back to its defaults (the symptom: policyRoot='.' + no explicit policies → it audits the whole cwd).
let A = args
if (typeof A === 'string') { try { A = JSON.parse(A) } catch (e) { A = {} } }
if (!A || typeof A !== 'object') A = {}

const DATE = A.date || '(undated)'
const POLICY_ROOT = A.policyRoot || '.'
const EXPLICIT_POLICIES = (Array.isArray(A.policies) && A.policies.length) ? A.policies : null
const FOCUS = A.focus || ''
const MAX_POLICIES = A.maxPolicies || 12

// Bump when the audit RUBRIC changes (a CHECK's pass/fail semantics, a new/removed CHECK). The skill
// stores this in each report; a bumped version invalidates carried-forward verdicts → forces a full
// re-audit even for content-unchanged policies. History:
//   1 = initial 10-check rubric (DEFAULT_DENY … TEST_COVERAGE)
const RUBRIC_VERSION = 1

const sevRank = { Critical: 0, Medium: 1, Low: 2 } // verify-cap ranking AND final sort — declare once

// The 10 CHECKS. Each maps to a SECURITY.md / BEST-PRACTICES.md section — the auditor cites the section.
// These are AUTHORIZATION-CORRECTNESS checks, NOT style. A policy that uses future.keywords instead of
// rego.v1, or returns {"allow": bool} instead of a bare allow, is NOT a finding — see the auditor prompt.
const CHECKS = [
  'DEFAULT_DENY',     // SECURITY §1: explicit default deny; no unconditional allow; every path → explicit allow or implicit deny.
  'INPUT_VALIDATION', // SECURITY §2: required fields checked; missing → deny not error; type/null handling (object.get defaults).
  'PRIV_ESCALATION',  // SECURITY §3: strict-inequality role levels; self-mod blocked where required; protected roles unassignable.
  'PATH_TRAVERSAL',   // SECURITY §4: path inputs normalized/validated (.. , / , %, backslash); no raw startswith on attacker path.
  'REDOS',            // SECURITY §4: no user-controlled regex; glob/literal patterns preferred.
  'DATA_EXPOSURE',    // SECURITY §5: denial reasons don't leak roles/permissions/internal structure.
  'TIME_BASED',       // SECURITY §6: token exp/nbf checked before access WHERE the policy handles tokens (else na).
  'EVAL_CONFLICT',    // BEST-PRACTICES: function/partial rules mutually exclusive; known-actions whitelist or else-chains.
  'DOMAIN_LOGIC_LEAK',// BEST-PRACTICES: policy does authz only — no calculations/validation/state-machine/workflow logic.
  'TEST_COVERAGE',    // SECURITY + TESTING: companion *_test.rego exists; covers allow AND deny AND edge (missing/null/empty/unknown-action).
]

const SCORECARD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['policy', 'packageName', 'decisionShape', 'conventions', 'hasTests', 'checks', 'summary'],
  properties: {
    policy: { type: 'string', description: 'repo-relative policy path' },
    packageName: { type: 'string', description: 'the `package x.y.z` declared in the policy — used to group same-package policies for the cross-policy pass' },
    decisionShape: { type: 'string', description: 'what the policy returns: e.g. "bare allow := false", "{\\"allow\\": bool}", "structured decision object". DESCRIPTIVE only — never a finding.' },
    conventions: { type: 'string', description: 'this policy\'s OWN idiom you observed: rego.v1 vs future.keywords, bare allow vs object decision, helper style. Record so divergence-from-skill-defaults is NOT flagged as a finding.' },
    hasTests: { type: 'boolean', description: 'whether a companion *_test.rego exists for this policy' },
    checks: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['check', 'status', 'evidence'],
        properties: {
          check: { type: 'string', enum: CHECKS },
          status: { type: 'string', enum: ['pass', 'fail', 'na'], description: 'na ONLY when the check genuinely does not apply to this policy (e.g. TIME_BASED on a policy that handles no tokens; PRIV_ESCALATION on a policy with no role-level hierarchy) — state why in evidence.' },
          severity: { type: 'string', enum: ['Critical', 'Medium', 'Low'], description: 'severity if status=fail; omit otherwise. Critical=an actual authorization bypass / priv-esc / traversal a caller could exploit. Medium=a real gap that weakens the policy but is not directly exploitable as-is. Low=defensive nit / minor missing edge test.' },
          evidence: { type: 'string', description: 'the concrete rule name / file:line / test name that proves pass, fail, or na — quote it. A fail MUST cite the exploitable construct.' },
        },
      },
    },
    crossPolicyNotes: { type: 'string', description: 'OPTIONAL: observations that need other policies to confirm — same package as another policy, a rule that may overlap/shadow another policy\'s rule, a shared helper. Empty if none. Confirmed in the cross-policy pass, not here.' },
    summary: { type: 'string', description: 'one-line security health verdict for this policy' },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['refuted', 'confidence', 'reason'],
  properties: {
    refuted: { type: 'boolean', description: 'true if the FAILED check is a FALSE ALARM (the policy is actually fine). false if the failure is real and exploitable.' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reason: { type: 'string', description: 'why the failure is real / why it is a false alarm — cite the policy construct + its tests you read.' },
  },
}

const CROSS_POLICY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['conflicts'],
  properties: {
    conflicts: {
      type: 'array',
      description: 'cross-policy issues a single-policy auditor cannot see: overlapping/shadowed rules across policies in the same package, eval_conflict risk from multiple files contributing the same rule, inconsistent default decisions. Empty array if none found.',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['kind', 'severity', 'policies', 'detail'],
        properties: {
          kind: { type: 'string', enum: ['OVERLAPPING_RULES', 'SHADOWED_RULE', 'EVAL_CONFLICT_RISK', 'INCONSISTENT_DEFAULT', 'SHARED_HELPER_DRIFT'], description: 'the cross-policy issue class' },
          severity: { type: 'string', enum: ['Critical', 'Medium', 'Low'] },
          policies: { type: 'array', items: { type: 'string' }, description: 'the policy files involved' },
          detail: { type: 'string', description: 'what the conflict is and why it matters — cite the rules/packages.' },
        },
      },
    },
  },
}

// ============================================================================
// Phase 1: scope — enumerate policies + baseline opa test/check (one agent).
// ============================================================================
phase('Scope')
const SCOPE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['policies', 'totalPolicies', 'baselineTests'],
  properties: {
    policies: {
      type: 'array',
      description: 'one entry per *.rego policy file (NOT *_test.rego)',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['policy', 'hasTests', 'lineCount'],
        properties: {
          policy: { type: 'string', description: 'repo-relative path to the policy .rego (not the _test file)' },
          hasTests: { type: 'boolean', description: 'whether a sibling <name>_test.rego exists' },
          lineCount: { type: 'integer', description: 'wc -l of the policy file — used to rank risk (bigger = more rules = audit first)' },
        },
      },
    },
    totalPolicies: { type: 'integer', description: 'count of policy files found (excluding _test.rego)' },
    baselineTests: { type: 'string', description: 'the result line from `opa test <root>` e.g. "PASS: 491/491", or the error if it did not run' },
  },
}

let scope
if (EXPLICIT_POLICIES) {
  // Explicit list is AUTHORITATIVE — the agent only ENRICHES metadata for exactly these files; we never
  // let it widen the set (an earlier version's scope agent enumerated the whole tree and ignored the list).
  log(`Explicit policy list supplied (${EXPLICIT_POLICIES.length}) — auditing exactly these, enriching metadata only`)
  scope = await agent(
    `You are gathering metadata for a Rego security audit of a FIXED set of policy files. READ-ONLY: do not switch branches or stage anything. DO NOT enumerate or add any other files — report on EXACTLY these and ONLY these:
${EXPLICIT_POLICIES.map(p => '  - ' + p).join('\n')}
For each one: does a sibling <name>_test.rego exist (hasTests)? what is its line count (wc -l of that exact file)?
Also run \`opa test ${POLICY_ROOT}\` once and return its summary line as baselineTests (if opa is unavailable, say so).
Return policies = one entry per file ABOVE (with policy path, hasTests, lineCount), totalPolicies = ${EXPLICIT_POLICIES.length}, baselineTests.`,
    { label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA }
  )
} else {
  scope = await agent(
    `You are scoping a Rego security audit for the policies under ${POLICY_ROOT}. READ-ONLY: do not switch branches or stage anything.

STEP 1 — enumerate: \`find ${POLICY_ROOT} -name '*.rego' ! -name '*_test.rego'\`. These are the policy files. For EACH, record its line count (wc -l) and whether a sibling test file (same path with _test before .rego, e.g. foo.rego → foo_test.rego) exists.

STEP 2 — baseline: run \`opa test ${POLICY_ROOT}\` and capture the summary line (e.g. "PASS: 491/491"). If opa is not installed or the dir has no tests, record that string instead — do not fail the scope.

Return policies (each with policy path, hasTests, lineCount), totalPolicies, baselineTests. ${FOCUS ? 'Reviewer steer: ' + FOCUS : ''}`,
    { label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA }
  )
}

const baselineTests = (scope && scope.baselineTests) || '(baseline not captured)'
const enriched = (scope && scope.policies) || []
// Build a metadata lookup from whatever the agent returned, keyed by path.
const metaByPath = {}
for (const e of enriched) { if (e && e.policy) metaByPath[e.policy] = e }

let toAudit, deferred, allCount
if (EXPLICIT_POLICIES) {
  // Authoritative: audit exactly the explicit list; pull metadata from the lookup, default if missing.
  toAudit = EXPLICIT_POLICIES.map(path => ({
    policy: path,
    hasTests: metaByPath[path] ? !!metaByPath[path].hasTests : false,
    lineCount: metaByPath[path] ? (metaByPath[path].lineCount || 0) : 0,
  }))
  deferred = []
  allCount = EXPLICIT_POLICIES.length
} else {
  // Rank by line count desc (bigger policy = more rules = more attack surface = audit first), then cap.
  const ranked = [...enriched].sort((a, b) => (b.lineCount || 0) - (a.lineCount || 0))
  toAudit = ranked.slice(0, MAX_POLICIES)
  deferred = ranked.slice(MAX_POLICIES).map(p => p.policy)
  allCount = enriched.length
}
log(`Scope: ${toAudit.length} policy(ies) this run (of ${allCount} found${deferred.length ? `, ${deferred.length} deferred past maxPolicies=${MAX_POLICIES}` : ''}); baseline ${baselineTests}`)

// ============================================================================
// Phase 2+3 pipelined: audit each policy, then adversarially verify each failed Critical/Medium check.
// ============================================================================
const AUDITOR_COMMON = `You are auditing ONE Rego (OPA) policy file for SECURITY/AUTHORIZATION-CORRECTNESS against a fixed rubric. READ-ONLY: do not switch branches, stage, or edit anything.

Read the policy IN FULL, then read its companion *_test.rego (if any). Score it against these checks:
- DEFAULT_DENY      — explicit default deny is present; no unconditional allow; every path resolves to explicit allow or implicit deny.
- INPUT_VALIDATION  — required input fields are checked before use; a missing field DENIES rather than erroring; null/type handled (e.g. object.get with a default).
- PRIV_ESCALATION   — where the policy has a role/level hierarchy: comparisons use STRICT inequality; users can't grant roles above their own; self-modification blocked where required; protected/system roles unassignable. (na if the policy has no such hierarchy — say so.)
- PATH_TRAVERSAL    — where the policy authorizes by path/resource id: the input is validated/normalized (rejects "..", "/", "%", backslash) and not raw-startswith-compared. (na if the policy authorizes by attributes only, not paths.)
- REDOS             — no user-controlled value is fed into a regex pattern; literal/glob matching preferred. (na if no regex at all.)
- DATA_EXPOSURE     — denial reasons / decision output do not leak role names, permission lists, or internal structure to the caller. (na if the policy returns only a boolean and no reason.)
- TIME_BASED        — where the policy handles tokens/sessions: expiry (exp) and not-before (nbf) are checked before granting. (na if the policy never inspects tokens/time.)
- EVAL_CONFLICT     — function-style or partial rules that can match the same input are MUTUALLY EXCLUSIVE (known-actions whitelist guards, or else-chains); no risk of "multiple outputs for same input" (eval_conflict_error). (na if the policy has only simple boolean allow rules with no competing outputs.)
- DOMAIN_LOGIC_LEAK — the policy does AUTHORIZATION ONLY: no business calculations, data validation beyond authz, state-machine/workflow transitions, or data transformation. (na is unusual — most policies should pass.)
- TEST_COVERAGE     — a companion *_test.rego exists AND covers allow cases, deny cases, and edge cases (missing/null/empty input, unknown action). Fail if no tests or only happy-path.

CRITICAL — judge each policy against ITS OWN conventions, NOT against any "modern Rego" ideal:
- Using \`import future.keywords.{if,in}\` instead of \`import rego.v1\` is NOT a finding. Both are valid.
- Returning \`{"allow": bool}\` or a structured decision object instead of a bare \`allow\` is NOT a finding.
- Helper-rule style, comment density, package naming are NOT findings.
- Record the policy's observed conventions/decisionShape in those fields (descriptive), but NEVER raise a check failure for style/idiom divergence. Only raise a fail for a genuine AUTHORIZATION-CORRECTNESS defect with concrete, exploitable evidence (cite the rule name / file:line).

For each check return status pass/fail/na with evidence (quote the construct). Set severity only on fail. Put any observation that needs OTHER policies to confirm (same package, possibly-overlapping rule, shared helper) into crossPolicyNotes — do not score it as a fail here.`

const perPolicy = await pipeline(
  toAudit,
  (p) => agent(
    `${AUDITOR_COMMON}

POLICY: ${p.policy}  (${p.lineCount} lines, hasTests=${p.hasTests})${FOCUS ? `
Reviewer steer: ${FOCUS}` : ''}`,
    { label: `audit:${(p.policy || '').split('/').pop().replace('.rego', '')}`, phase: 'Audit', schema: SCORECARD_SCHEMA, agentType: 'general-purpose' }
  ),
  (card, p) => {
    const checks = (card && card.checks) || []
    const failed = checks.filter(c => c.status === 'fail')
    if (!failed.length) return { card, p, verified: [] }
    // Verify only Critical/Medium fails (a real bypass deserves a skeptic). Low fails pass through
    // unverified. Cap per-policy at VERIFY_PER_POLICY (Critical first) so one noisy policy can't spawn a
    // verifier swarm — the overflow passes through unverified rather than verified-or-dropped.
    const VERIFY_PER_POLICY = 4
    const rankedFails = failed
      .filter(c => c.severity === 'Critical' || c.severity === 'Medium')
      .sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))
    const toVerify = rankedFails.slice(0, VERIFY_PER_POLICY)
    const overflow = rankedFails.slice(VERIFY_PER_POLICY)
    const passthrough = [
      ...failed.filter(c => c.severity !== 'Critical' && c.severity !== 'Medium'),
      ...overflow,
    ].map(c => ({ check: c, verdict: null })) // null verdict → surfaces as unverified in synthesize
    if (!toVerify.length) return { card, p, verified: passthrough }
    return parallel(toVerify.map(c => () =>
      agent(
        `Adversarially REFUTE this Rego security finding for ${p.policy}. READ-ONLY.
Read the CURRENT policy + its *_test.rego yourself. Try HARD to show the policy is ACTUALLY SAFE: the alleged bypass is already blocked elsewhere in the policy, the input is validated upstream, the rule cannot actually match the claimed input, or the finding misread the policy / is a style nit not a real defect. A finding SURVIVES only if you can re-confirm from the current policy that the authorization defect is genuine and exploitable. Default to refuted=true (policy is fine) if you cannot independently confirm an exploitable bypass. A style/idiom divergence (future.keywords vs rego.v1, {"allow":bool} decision shape) is ALWAYS refuted — it is not a security defect.

FINDING [${c.check}/${c.severity}] in ${p.policy}
  evidence the auditor gave: ${c.evidence}`,
        { label: `verify:${(p.policy || '').split('/').pop().replace('.rego', '')}:${c.check}`, phase: 'Verify', schema: VERDICT_SCHEMA, agentType: 'general-purpose' }
      ).then(v => ({ check: c, verdict: v }))
    )).then(verified => ({ card, p, verified: [...verified, ...passthrough] }))
  }
)

// ============================================================================
// Phase 4: cross-policy conflict pass (the one genuine barrier) + synthesize.
// ============================================================================
phase('Synthesize')
const rows = perPolicy.filter(Boolean)

// Group audited policies by package; only packages with >1 policy (or with crossPolicyNotes) need the pass.
const byPackage = {}
for (const r of rows) {
  const pkg = (r.card && r.card.packageName) || '(unknown)'
  ;(byPackage[pkg] ||= []).push(r)
}
const crossGroups = Object.entries(byPackage).filter(([, rs]) =>
  rs.length > 1 || rs.some(r => r.card && r.card.crossPolicyNotes && r.card.crossPolicyNotes.trim())
)

let crossPolicy = []
if (crossGroups.length) {
  const crossResults = await parallel(crossGroups.map(([pkg, rs]) => () => {
    const notes = rs.map(r => `- ${r.card.policy} (package ${r.card.packageName}): ${r.card.crossPolicyNotes || 'no notes'}`).join('\n')
    const files = rs.map(r => r.card.policy).join(', ')
    return agent(
      `You are checking for CROSS-POLICY authorization conflicts among Rego policies in (or related to) package "${pkg}". READ-ONLY.
These policies are involved: ${files}
Single-policy auditors already flagged these cross-policy observations:
${notes}

Read the involved policies. Look ONLY for issues that span MORE THAN ONE policy and a single-file audit could miss:
- OVERLAPPING_RULES / SHADOWED_RULE — two policies (or rules) authorize the same request differently, or one masks another.
- EVAL_CONFLICT_RISK — multiple files contribute a rule with the SAME name/path that could produce conflicting outputs for one input (eval_conflict_error across files).
- INCONSISTENT_DEFAULT — the policies in this package disagree on the default decision (one defaults deny, another effectively allows).
- SHARED_HELPER_DRIFT — a helper meant to be shared has diverged between policies.
Do NOT re-report single-policy findings, and do NOT flag style/idiom.

You MUST finish by calling the StructuredOutput tool with {"conflicts": [...]}. If you find NO cross-policy issues (the common, healthy case — separate files in the same package namespace that simply don't collide is NOT a conflict), call it with {"conflicts": []}. An empty result is a valid, expected answer — do NOT end with prose instead of the tool call.`,
      { label: `cross:${pkg.split('.').pop()}`, phase: 'Synthesize', schema: CROSS_POLICY_SCHEMA, agentType: 'general-purpose' }
    ).then(res => ((res && res.conflicts) || []))
  }))
  crossPolicy = crossResults.filter(Boolean).flat()
}

// Confirmed = a failed check whose adversarial verdict did NOT refute it. A null verdict (Low passthrough,
// overflow, or a verify agent that errored) surfaces as unverified — fail-safe toward REPORTING the finding
// (absent verdict = "could not refute" = survives), flagged so the report marks it needs-manual-confirm.
const confirmed = []
for (const r of rows) {
  const vitems = (r.verified || []).filter(item => item && item.check)
  for (const item of vitems) {
    if (item.verdict && item.verdict.refuted === true) continue // false alarm — drop
    confirmed.push({
      policy: r.card && r.card.policy,
      check: item.check.check,
      severity: item.check.severity || 'Medium',
      evidence: item.check.evidence,
      unverified: !item.verdict,
      reConfirm: item.verdict && item.verdict.reason,
    })
  }
}
confirmed.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))

const refutedCount = rows.reduce((n, r) => n + (r.verified || []).filter(v => v && v.verdict && v.verdict.refuted === true).length, 0)
const policyVerdicts = rows.map(r => ({
  policy: r.card && r.card.policy,
  packageName: r.card && r.card.packageName,
  decisionShape: r.card && r.card.decisionShape,
  conventions: r.card && r.card.conventions,
  hasTests: r.card && r.card.hasTests,
  failCount: ((r.card && r.card.checks) || []).filter(c => c.status === 'fail').length,
  naCount: ((r.card && r.card.checks) || []).filter(c => c.status === 'na').length,
  summary: r.card && r.card.summary,
}))

log(`Audit complete: ${confirmed.length} confirmed finding(s) across ${rows.length} policy(ies) (${confirmed.filter(c => c.severity === 'Critical').length} Critical), ${refutedCount} false alarm(s) dropped, ${crossPolicy.length} cross-policy issue(s)`)

return {
  date: DATE,
  rubricVersion: RUBRIC_VERSION,
  scope: {
    audited: rows.length,
    total: allCount,
    deferred,
    baselineTests,
    maxPolicies: MAX_POLICIES,
    policyRoot: POLICY_ROOT,
  },
  confirmed,
  policyVerdicts,
  crossPolicy,
}
