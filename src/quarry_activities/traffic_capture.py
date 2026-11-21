"""Worker-side activity consuming B10 canary callbacks into the capture index.

``sandbox-exec`` returns ``SandboxExecCapture.canary_callbacks`` (safe fields
only, in memory). This activity is the write side: the workflow forwards the
returned callbacks here after the capture completes, and the activity inserts
one capture-index row per callback with ``canary_callback=True`` and the
originating ``hunt_task_id``. The canary listener itself never writes SQLite.

The capture root is resolved from :class:`~quarry.config.QuarrySettings` on the
worker, so the activity's input carries only the callbacks and the hunt task id.
"""

from __future__ import annotations

from temporalio import activity

from quarry.config import QuarrySettings
from quarry_activities.inputs import IngestCanaryCallbacksInput
from quarry_traffic.canary import ingest_canary_callbacks
from quarry_traffic.capture_index import CaptureIndex, capture_index_path


@activity.defn(name="ingest-canary-callbacks")
def ingest_canary_callbacks_activity(inp: IngestCanaryCallbacksInput) -> int:
    """Write the callbacks into the capture index; return the row count."""
    settings = QuarrySettings()
    index = CaptureIndex(capture_index_path(settings.traffic_capture_root))
    try:
        return ingest_canary_callbacks(
            inp.callbacks,
            hunt_task_id=inp.hunt_task_id,
            index=index,
        )
    finally:
        index.close()
