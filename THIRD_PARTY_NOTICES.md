# Third-Party Notices

This file collects attribution and license notices for third-party content
that Quarry incorporates. It complements the per-file attribution headers
carried by the affected prompt templates (see `prompts/`).

## Mantis security-review skills (Apache-2.0), via Keygraph Shannon 3.0

Portions of Quarry's prompt content are adapted from the Mantis
security-review skills, licensed under the Apache License, Version 2.0,
as incorporated in Keygraph Shannon 3.0's static analysis engine.

The following Quarry prompt templates derive from that material
(each carries an attribution header in-file):

- `prompts/calibrate/calibrate.1.0.0.j2` — severity-calibration rule catalogue
- `prompts/recon/knowledge_base.1.0.0.j2` — knowledge-base recon guidance
- `prompts/validate/refute.1.0.0.j2` — negative-constraint checklist
  (adversarial-validation refuter)
- `prompts/gapfill/gapfill.1.0.0.j2` — exploratory-investigation planning
- `prompts/task/explore.1.0.0.j2` — unconstrained exploratory investigation
  task framing

Apache License, Version 2.0, January 2004 — full text:
https://www.apache.org/licenses/LICENSE-2.0

   Copyright [Mantis security-review skills authors]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

## Reference designs

Quarry's design draws on the following public reference designs and
benchmarks (named per `openspec/config.yaml`): Cloudflare Glasswing,
Microsoft MDASH, Keygraph Shannon, and the CyberGym benchmark. This file's
attribution requirements are governed by `openspec/config.yaml`.
