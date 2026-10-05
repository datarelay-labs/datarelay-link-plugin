# Repository Engineering Rules

This repository follows the canonical Engineering System:
https://github.com/datarelay-labs/engineering-system

## Minimum context first

Always:
1. Read this `AGENTS.md`.
2. Read `.engineering/project.yaml`.

Then only when relevant:
3. For implementation/debugging/testing, read `.engineering/tests.yaml`.
4. For release/version/artifact work, read `.engineering/release.yaml`.
5. Read only the Engineering System standard/specification/ADR/runbook needed for the task.

Do not preload all standards, Wiki pages, archived changes, or historical discussions.

When explicitly resuming an existing workstream, resolve this repository first and load its single matching active AI Work Packet. Do not search other repositories or replay old chat history. Verify the actual branch/HEAD/state before acting.

## Execution rules

- **Execution profile authority:** provider/runtime selection is data in `.engineering/execution-profile.yaml`. A Work Packet is runnable only when its `EXECUTION_PROFILE` and `EXECUTION_PROFILE_REVISION` match that managed profile; legacy packet compatibility is defined only by the profile. Provider/runtime names in prose, historical comments, adapter text, or memory never grant authority. A repository-level continue/resume that resolves to one runnable packet bound to the selected profile authorizes the selected runtime to continue implementation directly; do not require an additional magic phrase or alternate-runtime handoff. Use ordinary authenticated Git/GitHub operations for normal repository work and reserve stronger trusted boundaries for effect classes classified by the execution profile or a stricter project policy.
- For ordinary authenticated GitHub Issue/PR coordination, freshly re-read the authoritative Work Packet and subject branch/HEAD immediately before the write and reject stale intent, branch, or subject state. Do not require `worker_adapter.py` or the trusted signer for those normal coordination writes. Use `python3 tools/worker_adapter.py evaluate --request-json <facts.json>` only for an effect explicitly classified by this system or a stricter project policy as a high-risk external write (for example production, destructive, credential/permission-boundary, irreversible-publication, or equivalent). For those high-risk effects proceed only on `APPLIED`; `STALE_WORKER` authorizes no write and ambiguous outcomes must be reconciled before retry.
- **Execute useful work continuously.** **Execution authority precedence:** the current explicit owner instruction for this workstream governs first, then the freshly read current ACTIVE Work Packet body, then current repository rules. Historical Issue comments, prior handoffs, chat history/memory, old Work Packet versions, and retired adapter text are evidence only and never execution authority. When the current packet is bound to the selected execution profile, do not probe, restore, wait for, or launch any alternate or retired implementation adapter. Before any implementation starts or resumes, bind the target repository once from the owner's current explicit project/repository context, then require a fresh authoritative Work Packet read and `python3 tools/context_epoch.py packet-lint --expect-target-repo <bound-owner/repo>` PASS using that same bound repository. A `TARGET_REPO_SCOPE_MISMATCH` or other BLOCK makes the packet non-runnable and forbids implementation/session launch. Cross-project handoffs, dependencies, Issue references, Atlas results, and waiting-work scheduling remain read-only context and never replace the bound target; only a new explicit owner project/repository switch may rebind it. Implement in coherent small/medium batches, validate locally with the cheapest relevant tests, and keep going while a safe authorized next action exists. Use fast CI for quick integration feedback when useful; reserve full qualification/release CI for a stable candidate. If a workstream is waiting on machine-observable CI/review/deploy or another external condition, record/yield that wait and return to repository-level scheduling; switch to the highest-priority dependency-eligible independent ACTIVE Work Packet/worktree when safe instead of polling or stopping. For a repository-level continue/resume with no branch/workstream named, choose the single trusted runnable packet marked as the current implementation lane (for example QUEUE_STATE=IMPLEMENTATION/IMPLEMENTING); yielded/waiting/deferred predecessor packets must not compete with it. When a successor starts while predecessor integration/qualification is intentionally deferred, pause/yield the predecessor instead of leaving multiple equivalent ACTIVE implementation candidates. The single-matching-ACTIVE-packet rule selects one packet for the current branch/workstream; it does not serialize unrelated repository work behind a waiting packet. Once one runnable packet is selected and authorized, a progress/status message alone is not execution: make measurable progress in the same turn and continue until a real stop condition. Once material research/discovery has resolved the design direction and the owner accepts or says to proceed/continue, first persist the accepted result in the smallest appropriate canonical spec/ADR/roadmap/contract and synchronize the Work Packet, then continue directly into implementation and deterministic validation without asking for another generic implementation confirmation; Atlas may retain derived rationale but is never the canonical execution authority. Measurable progress may be reproduction, bounded investigation that resolves a material uncertainty, deterministic validation, repository mutation, or an authorized external state transition; do not force a code/config mutation when investigation or validation is the correct next action. Stop only for a real owner decision/credential, an irreconcilable blocker, or a status-only request. A completed bounded Work Packet ends that workstream, not a repository-level continue/resume request: immediately return to roadmap/portfolio scheduling and continue the next dependency-eligible runnable workstream. For a repository-level continue request, keep this loop active until the roadmap/release objective is complete, no dependency-eligible runnable work remains, or a genuine stop condition requires owner input. Do not return control merely because one PR, packet, test phase, or bounded outcome completed.
1. Classify the change and identify affected domains/contracts/security/operations.
2. For material design-bearing changes, apply the canonical `standards/DESIGN.md` minimal design gate before implementation.
3. Inspect relevant implementation and tests.
4. Make the smallest correct change.
5. Run the cheapest affected deterministic tests first.
6. PR validation should stay fast; do not run a full release suite merely because code changed.
7. Do not duplicate an equivalent native project CI gate.
8. A known blocking deterministic failure stops expensive downstream qualification.
9. Bug fixes require durable regression coverage whenever practical.
10. Never weaken a valid test merely to obtain PASS.
11. Before merge or terminal completion, inspect machine-observable PR review feedback. Fix and revalidate every actionable review finding, or explicitly disposition it with concise evidence when it is non-actionable, out of scope, or incorrect. Do not treat COMMENTED/advisory review state as automatic PASS.
12. Never claim release readiness without exact executable evidence.
13. Never reuse qualification evidence from a different source HEAD.

If the user reports an outage, degraded service, failed upgrade, data-loss risk, or other production-impacting symptom, switch to the canonical `standards/OPERATIONS.md` incident lifecycle. Preserve evidence before mutation and do not perform destructive/irreversible recovery without explicit approval unless an approved runbook authorizes it.

If mandatory engineering context is missing or contradictory, stop implementation and report the configuration defect instead of guessing.

When the user explicitly asks to apply/adopt/bootstrap the Engineering System to this repository, use the canonical `standards/ADOPTION.md` workflow: inventory first, classify existing rules, discover project-native tests/CI, preserve stricter project invariants, use deterministic bootstrap for missing common surfaces, and qualify the adoption before reporting PASS. If this repository is already pinned to an older managed Engineering System version, use the fail-closed managed upgrade workflow instead of rerunning initial bootstrap.

Tool-specific adapters must not weaken these rules.

## Project-specific rules

1. This repository is the optional ChatGPT Plus / Agent Plugins + MCP relay layer for DataRelay Link.
2. Do not modify `datarelay-labs/datarelay-link` from work in this repository.
3. The relay must not invent tools, cache authorization decisions, or reinterpret DRLink AI Access outcomes.
4. Never commit OAuth secrets, upstream tokens, or DRLink private keys; never log Authorization headers.

## ChatGPT implementation and audit contract

ChatGPT Chat is the default implementer for this repository when the authenticated active Work Packet authorizes the exact repository/worktree/branch/scope.

Before mutation, the external authenticated GitHub coordinator must verify the current Work Packet, author permission, repository, worktree, branch, exact HEAD, intent revision, change risk, and `IMPLEMENTER=CHATGPT_CHAT`. The worker-writable repository copy of `python3 tools/implementation_preflight.py check` is never mutation authority. Use the helper source from the immutable pinned Engineering System baseline through the isolated trusted launcher, capture the no-follow worktree identity, and require `IMPLEMENTATION_LOCAL_BINDING=PASS` with `MUTATION_AUTHORITY=NO`.

ChatGPT Chat performs implementation, deterministic testing, and terminal audit. Terminal PASS requires current exact-HEAD evidence, required CI/review state, and disposition of actionable findings; self-report alone is never sufficient. HIGH/CRITICAL or production/security-sensitive work requires deeper machine evidence and any applicable human approval. Codex or another independent reviewer is optional defense-in-depth/escalation, not a default completion dependency.
