# Change: class-neutral-gap-rehunt

## Why

Gapfill currently routes *all* under-coverage recovery through free-form model-proposed investigations ("explore module X"). That works for module coverage, but a class-shaped gap — a requested vulnerability class with thin or zero signal — is only recoverable if the model happens to notice and correctly phrase it, and it has repeatedly not done so (run `ebdafaba`: ssrf never re-queued).

Class gaps should be first-class, computable from the ledger, and recoverable by re-queueing the class's own hunt round rather than hoping a model writes the right free-text investigation.

## What Changes

- Gapfill computes **class-shaped gaps** deterministically from the coverage ledger: requested class with zero candidates, or candidates all refuted/dropped with no survivors (class effectively unexamined at promotion time).
- A class gap resolves to a **class-scoped re-hunt** (the class's prompt template, bounded rounds) instead of — or ahead of — free-form investigation proposals.
- Free-form exploratory investigations remain for module/coverage gaps that are not class-shaped; the ledger distinguishes the two gap kinds.
- Ordering: class re-hunts run before free-form investigations within a gapfill round, since class gaps are directly actionable and cheaper to scope.
- Interplay with `class-coverage-floor`: the floor guarantees a first forced pass for zero-candidate classes; this change makes gapfill's *subsequent* recovery class-aware too. If the floor lands first, gapfill consumes its results; the two are complementary, and this change does not depend on the floor.

## Impact

- **Specs**: `coverage-ledger-and-gapfill` (ADDED requirements; MODIFIED none — gap kinds extend the ledger), `hunt-stage` (ADDED requirement for class re-hunt task construction, shared shape with the floor's forced pass).
- **Code**: `src/quarry_activities/gapfill.py` (gap classification + class re-hunt queueing), coverage ledger gains a gap-kind field.
- **Cost**: bounded by existing gapfill round limits; class re-hunts replace some free-form investigations rather than adding budget.
- **Non-goals**: per-class sink sweeps (deterministic detection aids); changing the gapfill round cap; making free-form investigations smarter.
