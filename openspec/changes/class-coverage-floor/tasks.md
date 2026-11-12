# Tasks: class-coverage-floor

## 1. Spec delta
- [ ] 1.1 Add spec deltas under `specs/coverage-ledger-and-gapfill/spec.md` and `specs/hunt-stage/spec.md`
- [ ] 1.2 `openspec validate class-coverage-floor --strict` passes

## 2. Implementation
- [ ] 2.1 Coverage check: after final hunt round, compute per-requested-class candidate counts from ledger (RED: test with a scan fixture where a focus class has zero candidates)
- [ ] 2.2 Forced hunt pass: construct class-scoped hunt task, bounded rounds (default 1, config key), provenance tag `forced_class_hunt` (RED→GREEN)
- [ ] 2.3 Wire forced pass into workflow before validation stage; candidates enter normal pipeline (RED→GREEN)
- [ ] 2.4 Emit `class_coverage_floor` event into scan manifest per forced class (RED→GREEN)
- [ ] 2.5 Report marks `coverage: forced_hunt_exhausted` for classes still at zero after forced pass (RED→GREEN)

## 3. Verification
- [ ] 3.1 Unit tests green (new + regression), ruff/pyright clean
- [ ] 3.2 Integration: scan fixture with a hobbled hunt model for one class → forced pass fires, event recorded
- [ ] 3.3 No forced pass when all focus classes have ≥1 candidate (no cost regression on the happy path)

## 4. Landing
- [ ] 4.1 Conventional commit, push, CI green
- [ ] 4.2 `openspec archive class-coverage-floor --yes`
