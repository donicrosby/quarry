"""Minimal workflow used to smoke-test the Temporal test fixtures.

Kept in its own module (not ``conftest.py``) so Temporal's workflow sandbox can
reimport it without pulling in pytest machinery.
"""

from pydantic import BaseModel, ConfigDict
from temporalio import workflow


class PingInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    message: str


@workflow.defn
class PingWorkflow:
    @workflow.run
    async def run(self, inp: PingInput) -> str:
        return inp.message
