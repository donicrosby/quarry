# vulnerable-planted

Deliberately vulnerable FastAPI fixture used as a **regression detector**.

Its seeded flaws are authored for this repository and are not published in any
benchmark or public dataset, so a model cannot recall them from training data.
When a harness change stops detecting one of them, `quarry benchmark local`
reports the recall drop here first.

Ground truth: `tests/golden/ground_truth/vulnerable-planted.json` (kept outside
this directory on purpose so the scanned agents cannot read the answer key).

Run it:

```bash
quarry target start examples/vulnerable-planted
quarry benchmark local --repo examples/vulnerable-planted \
  --ground-truth tests/golden/ground_truth/vulnerable-planted.json
```
