"""Atomic per-scan credibility budget counters (credibility-economics).

Two counters per scan live in the existing SQLite persistence store: one for
deterministic probe units, one for paid debater calls. Each decrement is a
single ``UPDATE … SET value = value - 1 RETURNING value`` statement, so it is
atomic against concurrent cascade evaluations for the same scan, and gating
fires when the RETURNING value is negative (the counter was already zero) — at
which point the decrement is undone with ``UPDATE … SET value = value + 1``.

Counters are seeded once at scan start with ``INSERT … ON CONFLICT DO NOTHING``,
so a resumed scan reads the persisted value instead of re-granting budget: the
configured cap is a hard ceiling that survives a Temporal workflow failure.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Integer, String, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, mapped_column

from quarry_persistence.db import Base, create_sqlite_engine, session_scope

__all__ = [
    "MODEL_COUNTER_NAME",
    "PROBE_COUNTER_NAME",
    "CredibilityCounterRecord",
    "InProcessBudgetCounter",
    "SqliteBudgetCounter",
    "initialize_credibility_counters",
]

# Counter row names. The scan id is part of the key, so one row pair per scan.
PROBE_COUNTER_NAME = "credibility_probe"
MODEL_COUNTER_NAME = "credibility_model"


class CredibilityCounterRecord(Base):
    """One named per-scan counter row."""

    __tablename__ = "credibility_counters"

    scan_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    name: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    value: Mapped[int] = mapped_column(Integer, nullable=False)


class SqliteBudgetCounter:
    """An atomic budget counter backed by one SQLite row.

    ``take`` consumes one unit and returns False when the budget is exhausted
    (restoring the counter so it never goes negative). ``unlimited`` bypasses the
    ceiling entirely — it is only ever set from an explicit
    ``unlimited = true`` opt-in per counter, never inferred from a zero cap.
    """

    def __init__(
        self,
        engine: Engine,
        scan_id: str,
        name: str,
        *,
        unlimited: bool = False,
    ) -> None:
        self.engine = engine
        self.scan_id = scan_id
        self.name = name
        self.unlimited = unlimited

    def initialize(self, cap: int) -> None:
        """Seed the counter at *cap* if it does not exist yet (idempotent).

        ``ON CONFLICT DO NOTHING`` is what makes a resumed scan keep its
        persisted value: the seed never overwrites an existing row, so the hard
        ceiling is not re-granted on resume.
        """
        with session_scope(self.engine) as session:
            session.execute(
                text(
                    "INSERT INTO credibility_counters (scan_id, name, value) "
                    "VALUES (:scan_id, :name, :value) "
                    "ON CONFLICT (scan_id, name) DO NOTHING"
                ),
                {"scan_id": self.scan_id, "name": self.name, "value": max(0, cap)},
            )

    def value(self) -> int | None:
        """The persisted counter value, or None when the counter was never seeded."""
        with session_scope(self.engine) as session:
            row = session.execute(
                text(
                    "SELECT value FROM credibility_counters "
                    "WHERE scan_id = :scan_id AND name = :name"
                ),
                {"scan_id": self.scan_id, "name": self.name},
            ).first()
        return None if row is None else int(row[0])

    def take(self) -> bool:
        """Atomically consume one unit; False when the budget is exhausted.

        Returns False when the counter was already zero (post-decrement value
        negative) and restores it, or when the counter was never seeded — the
        fail-closed direction, since an unseeded counter has no budget to grant.
        """
        if self.unlimited:
            return True
        with session_scope(self.engine) as session:
            row = session.execute(
                text(
                    "UPDATE credibility_counters SET value = value - 1 "
                    "WHERE scan_id = :scan_id AND name = :name "
                    "RETURNING value"
                ),
                {"scan_id": self.scan_id, "name": self.name},
            ).first()
            if row is None:
                return False
            if int(row[0]) < 0:
                # Gate fired: the counter was zero, so undo the decrement.
                session.execute(
                    text(
                        "UPDATE credibility_counters SET value = value + 1 "
                        "WHERE scan_id = :scan_id AND name = :name"
                    ),
                    {"scan_id": self.scan_id, "name": self.name},
                )
                return False
        return True


def initialize_credibility_counters(
    *,
    db_path: Path | str | None,
    scan_id: str,
    probe_budget: int,
    model_budget: int,
) -> None:
    """Seed both counters for *scan_id* (idempotent across resume)."""
    engine = create_sqlite_engine(db_path)
    Base.metadata.create_all(engine)
    SqliteBudgetCounter(engine, scan_id, PROBE_COUNTER_NAME).initialize(probe_budget)
    SqliteBudgetCounter(engine, scan_id, MODEL_COUNTER_NAME).initialize(model_budget)


class InProcessBudgetCounter:
    """Process-local budget counter for callers with no persistence store.

    Used when the cascade runs without a ``db_path`` (direct calls and unit
    tests). It implements the same ``take`` contract as
    :class:`SqliteBudgetCounter`; the persisted SQLite counters are always used
    when a database path is available, so scan-resume ceilings stay durable.
    """

    def __init__(self, cap: int, *, unlimited: bool = False) -> None:
        self.cap = max(0, cap)
        self.remaining = max(0, cap)
        self.unlimited = unlimited

    def take(self) -> bool:
        if self.unlimited:
            return True
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True
