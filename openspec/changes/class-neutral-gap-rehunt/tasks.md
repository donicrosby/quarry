# Tasks: class-neutral-gap-rehunt

## 1. Spec delta
- [ ] 1.1 Add spec deltas under `specs/coverage-ledger-and-gapfill/spec.md` and `specs/hunt-stage/spec.md`
- [ ] 1.2 `openspec validate class-neutral-gap-rehunt --strict` passes

## 2. Implementation
- [ ] 2.1 Gap classification: ledger distinguishes `class_gap` (zero candidates, or all refuted/dropped) from `module_gap` (RED→GREEN)
- [ ] 2.2 Class re-hunt queueing: a `class_gap` spawns a class-scoped hunt task (class prompt template, bounded rounds) (RED→GREEN)
- [ ] 2.3 Ordering: class re-hunts run before free-form investigations within a gapfill round (RED→GREEN)
- [ ] 2.4 Free-form investigations still fire for module gaps; no regression to existing gapfill behavior (regression test)
- [ ] 2.5 Gap events record gap kind and resolution path in the manifest

## 3. Verification
- [ ] 3.1 Unit tests green (new + regression), ruff/pyright clean
- [ ] 3.2 Integration: fixture where a focus class ends hunt with all-refuted candidates → gapfill re-hunts the class
- [ ] 3.3 Interaction test with class-coverage-floor (if landed): floor handles zero-candidate, gapfill handles all-refuted, no double-spawn

## 4. Landing
- [ ] 4.1 Conventional commit, push, CI green
- [ ] 4.2 `openspec archive class-neutral-gap-rehunt --yes`
