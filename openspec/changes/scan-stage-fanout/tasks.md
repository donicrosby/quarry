# scan-stage-fanout Tasks

## 1. Validate fan-out

- [ ] 1.1 Add `validate_max_concurrent` to `RunScanInput` (default 8) and `ScanDefaults`
- [ ] 1.2 Write failing concurrency test: 6 candidates, cap 8, completes below serial floor
- [ ] 1.3 Write failing tests: cap enforcement (limit 2), failure isolation
      (`validate.failed` + scan continues), event order = candidate order
- [ ] 1.4 Replace serial validate loop in `run_scan.py` with semaphore + gather;
      budget check inside the dispatch closure
- [ ] 1.5 Wire `scan_defaults.validate_max_concurrent` through `routers/scans.py`

## 2. Tracer fan-out

- [ ] 2.1 Add `trace_max_concurrent` to `RunScanInput` (default 4)
- [ ] 2.2 Failing tests: verdict events in finding order, per-finding failure isolation, cap
- [ ] 2.3 Gather per-finding trace dispatches in the TRACER stage; re-ranking applied
      post-gather in finding order

## 3. Calibrate fan-out + docs

- [ ] 3.1 Add `calibrate_max_concurrent` to `RunScanInput` (default 4)
- [ ] 3.2 Failing tests: `finding.calibrated` in finding order, failure keeps raw severity, cap
- [ ] 3.3 Gather calibrations at the validated-findings call site
- [ ] 3.4 README "Tuning scan concurrency" section documenting all four knobs

## 4. Inventory (pre-hunt sweep) class-parallelism

- [ ] 4.1 Add `dynamic_validate_max_concurrent` to `ScanDefaults` (default 8), replace
      the hardcoded value in `routers/scans.py`
- [ ] 4.2 Failing tests: inventory overlap across classes under semaphore; no duplicate
      candidate registration per fingerprint; config default resolution
- [ ] 4.3 Overlap the discover→hunt→register chain across classes; assert fingerprint
      dedupe holds

## 5. Integration + verification (orchestrator)

- [ ] 5.1 Merge all slices on integration branch; full unit suite pass count == sum of slices
- [ ] 5.2 `openspec validate scan-stage-fanout --strict`
- [ ] 5.3 PR, CI green, merge
- 5.4 Mock-panel e2e smoke asserting fan-out events present (before paid run)
- 5.5 Paid verification scan on `examples/vulnerable-fastapi`; verify from DB:
      detection vs promotion as separate numbers, cost telemetry nonzero, wall-clock
      delta vs the 39-min baseline
