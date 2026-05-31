# The Security-Audit Workflow — In Depth

This document explains the `rego-security-audit-workflow.js` fan-out in detail: what a Claude
Code **Workflow** is (a relatively new harness feature), how this particular workflow is
structured phase by phase, what it costs in tokens, and the design decisions that make it
trustworthy. For *how to run it*, see the "Suite-wide security audit" section of
[SKILL.md](SKILL.md); this doc is the deep reference behind that.

---

## 1. What a Claude Code "Workflow" is

A **Workflow** is a Claude Code feature that runs a deterministic JavaScript orchestration
script which spawns and coordinates multiple sub-agents. It is distinct from a normal agent turn:

| | Normal agent turn | Workflow |
|---|---|---|
| Control flow | The model decides what to do next, step by step | A **plain JS script** decides — loops, conditionals, fan-out are deterministic |
| Parallelism | One agent, sequential tool calls | Many sub-agents running **concurrently** (capped, see §4) |
| Output | Free-form text | The script's `return` value (structured data) |
| Reproducibility | Varies turn to turn | Same script + same inputs → same shape; supports **resume** from a journal |

The script gets a small set of host functions:

- `agent(prompt, opts)` — spawn one sub-agent. With `opts.schema` (a JSON Schema) the agent is
  **forced to emit a validated structured object** (it calls a `StructuredOutput` tool; the
  harness retries on mismatch), so the script gets typed data back, not prose.
- `pipeline(items, stage1, stage2, …)` — run each item through all stages **independently**, with
  no barrier between stages (item A can be in stage 3 while item B is still in stage 1).
- `parallel(thunks)` — run tasks concurrently and **wait for all** (a barrier). A failed thunk
  resolves to `null` rather than rejecting the whole batch.
- `phase(title)` / `log(msg)` — progress reporting.
- `args` — the inputs passed in by the caller.

> **Why this matters for an audit:** auditing N policies is *embarrassingly parallel* — each
> policy is independent, scored against a fixed rubric. A Workflow lets us fan out one
> specialized auditor per policy, then fan out one skeptic per finding, all concurrently, and
> collate the results deterministically. A single agent doing this serially would be far slower
> and would lose focus across a large corpus.

### Requirements / availability

- This is a **newer Claude Code harness capability**. You need a Claude Code version that exposes
  the `Workflow` tool. The rest of this skill — the inline generate / test / review loop — works
  without it; **only this corpus-audit needs Workflows.** If your harness doesn't have it, the
  skill still functions; you just don't get the suite-wide audit.
- The workflow itself only needs the `opa` CLI (for the baseline `opa test`) and read access to
  the policy files. It is **read-only**: it never edits a policy, switches git branches, or stages
  anything.

---

## 2. ⚠️ Token cost — this can be expensive

**A Workflow spawns many agents, and each agent is its own context window.** That is the whole
point (parallel, independent reasoning), but it means a run can consume a large amount of tokens —
far more than a single agent turn. Budget for it.

### Where the tokens go

For a corpus of **P** policies, a full run spawns roughly:

```
1 (scope)
+ P (one auditor per policy — each reads the full policy + its test file)
+ up to 4·P (verifiers — one skeptic per failed Critical/Medium check, capped at 4/policy)
+ ~G (cross-policy agents — one per package group with >1 policy)
```

So the agent count is **O(P)** but with a meaningful constant (the verify fan-out). Each auditor
reads an entire policy — and real gateway policies can be **1,000–2,000 lines** — so the per-agent
input is not trivial.

### Real measured cost (from this skill's own development)

| Run | Policies | Agents | Wall-clock | Sub-agent tokens |
|---|---|---|---|---|
| Smoke | 1 | 3 | ~2 min | ~100k |
| Package family | 4 | 10 | ~6 min | ~550k |
| Full suite | 8 (one 1,828-line) | 17 | ~50 min | ~480k |

Note the full suite took *longer* but used *fewer* tokens per policy than the 4-policy run,
because the 4-policy run hit a dense cross-policy package (more verify + cross agents). **Token
cost tracks findings density and cross-policy structure, not just policy count.**

### Cost controls built into this workflow

- **`maxPolicies` (default 12)** — caps the audited set. Larger/denser policies are ranked first;
  the rest are deferred to a later run (reported in `scope.deferred`, not silently dropped). This
  is the primary cost/sizing guard.
- **Verify cap (4 per policy)** — only Critical/Medium findings get a skeptic, and at most 4 per
  policy; Lows pass through unverified. Stops one noisy policy from spawning a verifier swarm.
- **Concurrency cap** — the harness caps concurrent agents at ~`min(16, cores−2)`; excess queue.
  This bounds *peak* resource use but not *total* tokens.
- **Incremental mode** (`policies: […]`) — audit only the changed policies (the skill computes the
  changed set via `git hash-object`), carrying forward unchanged verdicts.

### Rules of thumb

- Keep a run **≤ ~12 policies / ~50 agents** for a comfortable ~6-minute, single-digit-dollar run.
- A high ratio of `unverified` / null verdicts in a report is a **sizing signal** (too many agents
  starved the verify phase) — re-run smaller, don't conclude the policies are bad.
- For a big corpus, prefer **incremental** runs (changed policies only) over full sweeps.

---

## 3. This workflow's architecture, phase by phase

Four phases. Phases 2 and 3 are **pipelined** (no barrier — a policy's findings start verifying as
soon as that policy's audit returns, while other policies are still being audited). Phase 4 has the
one genuine barrier (cross-policy reasoning needs all per-policy results first).

```
            ┌─────────┐
   args ───▶│ 1 SCOPE │  one agent: find *.rego, baseline `opa test`, per-policy metadata
            └────┬────┘
                 │  policies[] (ranked by size, capped at maxPolicies)
                 ▼
        ┌──────────────────┐   pipeline — per policy, no barrier between Audit→Verify
        │ 2 AUDIT (1/policy)│  read policy + tests, score 10 CHECKS → scorecard
        └────────┬─────────┘
                 │ failed Critical/Medium checks (≤4/policy)
                 ▼
        ┌──────────────────┐
        │ 3 VERIFY (1/fail) │  adversarial skeptic: try to REFUTE the finding from code
        └────────┬─────────┘
                 │  all per-policy results
                 ▼   ────────────── barrier ──────────────
            ┌──────────────────────┐
            │ 4 SYNTHESIZE          │  group by package; one cross-policy agent per
            │  + cross-policy pass  │  multi-policy group; collate dated report payload
            └──────────┬───────────┘
                       ▼
                 return { date, scope, confirmed[], policyVerdicts[], crossPolicy[] }
```

### Phase 1 — Scope (1 agent)

Enumerates `*.rego` policy files under `policyRoot` (excluding `*_test.rego`), records each
policy's line count and whether it has a companion test, and runs `opa test` once for a baseline.
Policies are then **ranked by line count** (bigger = more attack surface = audit first) and capped
at `maxPolicies`. An explicit `policies` list bypasses enumeration and the cap entirely
(incremental mode) and is treated as **authoritative** — the scope agent only enriches metadata for
exactly those files, it cannot widen the set.

### Phase 2 — Audit (1 agent per policy) → scorecard

Each auditor reads its policy **in full** plus its `*_test.rego`, and scores it against the **10
checks** (each mapped to a `SECURITY.md` / `BEST-PRACTICES.md` section):

`DEFAULT_DENY`, `INPUT_VALIDATION`, `PRIV_ESCALATION`, `PATH_TRAVERSAL`, `REDOS`, `DATA_EXPOSURE`,
`TIME_BASED`, `EVAL_CONFLICT`, `DOMAIN_LOGIC_LEAK`, `TEST_COVERAGE`.

Each check returns `pass` / `fail` / `na` with **evidence** (a quoted rule name / `file:line`). The
scorecard also records the policy's `packageName`, `decisionShape`, and observed `conventions`.

> **The single most important rule in the auditor prompt:** *judge each policy against its OWN
> conventions, never against a "modern Rego" ideal.* `import future.keywords` vs `rego.v1`, a
> `{"allow": bool}` object vs a bare `allow`, helper-rule style — all recorded **descriptively** and
> **never** raised as a finding. Only genuine, exploitable authorization defects are reported. This
> is what keeps the report signal-dense instead of drowning in style nits. (Validated: across full
> runs on a corpus that mixes idioms, zero style-divergence findings were produced.)

### Phase 3 — Verify (1 adversarial agent per failed Critical/Medium check)

Every Critical/Medium finding gets an independent **skeptic** prompted to *refute* it: read the
current policy + tests and try to show the policy is actually safe (the bypass is blocked elsewhere,
the input is validated upstream, the rule can't match the claimed input, or the auditor misread).
A finding **survives only if the skeptic cannot refute it from the code**; the default is
`refuted = true` (drop the finding) when in doubt. Lows pass through unverified (verifying every
low-stakes nit across a corpus isn't worth the fan-out).

> This phase is the antidote to confident-but-wrong findings. In practice it both **drops false
> alarms** and **strengthens real ones** — e.g. a verifier for a path-traversal finding actually ran
> `opa eval` to *reproduce the exploit* end-to-end before confirming it.

### Phase 4 — Synthesize + cross-policy pass (1 agent per multi-policy package group)

Per-policy auditors are blind to each other, so a final pass groups the audited policies by
`packageName` and, for each group with more than one policy (or any cross-policy notes), spawns one
agent to look for issues a single-file audit **cannot** see: overlapping/shadowed rules across
files, `eval_conflict` risk from multiple files contributing the same rule, inconsistent defaults,
shared-helper drift. This is the **highest-value output** of the workflow — it's where the
genuinely interesting findings live (helper drift between a gateway policy and its fine-grained
action policy, a privilege-escalation guard present in one file but missing in the mutation path,
etc.).

The script then collates everything into the return payload:

```js
{
  date, rubricVersion,
  scope: { audited, total, deferred, baselineTests, maxPolicies, policyRoot },
  confirmed: [ … severity-sorted findings that SURVIVED verification … ],
  policyVerdicts: [ … one row per policy: package, decisionShape, conventions, fails, na, summary … ],
  crossPolicy: [ … cross-package conflicts … ],
}
```

The skill wrapper renders this into a dated `REGO-SECURITY-AUDIT-<date>.md` and commits it to a
branch. **Report-only** — neither the workflow nor the wrapper edits a policy.

---

## 4. Design decisions & lessons (why it's built this way)

These are the non-obvious calls, several learned the hard way during development:

1. **Schema-forced structured output everywhere.** Every agent returns a validated object, not
   prose. The script never parses free text. This is what makes the fan-out composable.

2. **Pipeline, not barrier, between Audit and Verify.** A policy's findings start verifying the
   moment that policy's audit returns — other policies are still being audited in parallel. Wall-
   clock is the slowest single policy's chain, not the sum. The *only* barrier is before the
   cross-policy pass, which genuinely needs all per-policy results.

3. **Adversarial verification with a "default to refuted" bias.** A finding must be re-confirmed
   from code to survive. This trades a few false negatives for far fewer false positives — the
   right trade for a report a human will act on.

4. **Judge against the policy's own conventions.** (See Phase 2.) Without this, an auditor flags
   every policy that doesn't use the skill's preferred idiom, and the real findings drown. This was
   the #1 correctness requirement and is enforced explicitly in the auditor + verifier prompts.

5. **`maxPolicies` + per-policy verify cap.** Sizing matters more than raw policy count: too many
   concurrent agents *starves* the verify phase (verifiers return null because tool I/O is saturated),
   which shows up as a high `unverified` ratio. The caps keep total agents under that point. If you
   see lots of `unverified`, re-run smaller — it's a sizing signal, not a verdict on the policies.

6. **`args` is normalized at the top of the script.** The harness can deliver `args` as a JSON
   **string** rather than a parsed object; if you read `args.field` directly you get `undefined` and
   the workflow silently falls back to all defaults (e.g. auditing the entire cwd instead of the
   intended subset). The script defensively `JSON.parse`es a string `args`. *(If you fork this
   workflow, keep that guard.)*

7. **Report-only is a hard contract.** The audit *finds*; a human (with the inline generate/review
   loop) *fixes*. An unattended agent "fixing" a 1,800-line gateway policy is more dangerous than a
   reported finding. The workflow is read-only against both the filesystem and git.

---

## 5. See also

- [SKILL.md](SKILL.md) → "Suite-wide security audit" — how to invoke it (the wrapper steps).
- [SECURITY.md](SECURITY.md) / [BEST-PRACTICES.md](BEST-PRACTICES.md) — the rubric the 10 checks cite.
- `rego-security-audit-workflow.js` — the implementation (well-commented; this doc is the prose map of it).
- `audit-reports/` — a real sample report produced by running the workflow on this repo's own policies.
