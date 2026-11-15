"""quarry_replay — direct-activity prompt-replay harness.

Replays ONE agentic stage against a prior scan's persisted state, bypassing
the Temporal workflow: input resolvers reconstruct the activity's call
arguments from the scan DB + artifact store, a runner invokes the activity
function directly under a resolved panel, and every model invocation is
recorded with a replay marker so replay spend never pollutes scan provenance.
Replay is read-only against the scan's recorded state.
"""

from __future__ import annotations
