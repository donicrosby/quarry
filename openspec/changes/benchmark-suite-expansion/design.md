## Fixture inventory matrix (task 2.1)

The huntable-vs-benchmarkable matrix is **generated, not hand-maintained**.
`quarry benchmark inventory` reads the filesystem directly — `prompts/hunt/*.j2`
for hunt-template presence and `tests/golden/ground_truth/*.json` for ground-truth
counts — and prints one row per `VulnerabilityClass`. Hand-copying the matrix into
this document would let it drift from what the harness actually scores, so this
section points at the command instead of duplicating its output as prose.

Source of truth:

```bash
uv run quarry benchmark inventory
```

Snapshot (regenerate with the command above; the `benchmark-gate` CI job runs it
on every change):

```text
class                        huntable  ground_truth
secrets                      True      1
idor                         True      4
command_injection            True      5
ssrf                         True      1
sql_injection                True      1
xss                          True      1
file_upload                  True      1
path_traversal               True      2
open_redirect                True      1
ssti                         True      1
insecure_deserialization     True      1
xxe                          True      0
ldap_injection               True      0
mass_assignment              True      0
auth                         True      1
security_misconfiguration    True      0
insecure_design              True      0
weak_crypto                  True      1
total_classes=18 huntable=18 benchmarkable=13
```

The invariant this guards: a class with `hunt_template=True` but
`ground_truth_count=0` is **huntable but not benchmarkable** — it can be hunted
but nothing scores it. `test_benchmark_inventory.py`, `test_benchmark_web_fixtures.py`
and `test_benchmark_planted_fixtures.py` fail closed when a ground-truth entry
exists without a reachable sink at the location it names.

## Planted-regression target (task 2.3)

`examples/vulnerable-planted/` is a deliberately vulnerable FastAPI target whose
flaws are authored for this repo (not drawn from any published benchmark), paired
with `tests/golden/ground_truth/vulnerable-planted.json`. Its `data/` seed files
are committed so the `/files` path-traversal route has something to read.

Verification is executable, not asserted:

- `tests/unit/test_benchmark_planted_fixtures.py` — every planted ground-truth
  entry maps to a served route whose handler actually fires (traversal escapes
  `DATA_DIR`, command injection runs a shell metacharacter, MD5 is unsalted, the
  admin route leaks internal state, and `pickle.loads` executes an attacker blob);
  plus `_benchmark_local_command` scores the planted manifest to recall 1.0.
- `tests/integration/test_benchmark_planted_target.py` — launches the target via
  the same launcher `quarry target start` uses (`start_local_target`) and
  exercises every sink over real HTTP.
