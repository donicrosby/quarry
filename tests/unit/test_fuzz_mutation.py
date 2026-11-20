"""Unit tests for the fuzz mutation engine (C5 fuzzing-harness, tasks.md 3).

Written RED first: every strategy must be exercised, the dictionary payloads
must reach the input, and the same seed must reproduce the same sequence.
"""

from __future__ import annotations

from quarry_activities.fuzz import (
    DEFAULT_DICTIONARY,
    MUTATION_STRATEGIES,
    generate_mutants,
)


class TestStrategyCoverage:
    def test_each_strategy_is_applied(self) -> None:
        records = generate_mutants("seed-input", count=8, seed=1)
        applied = {record.strategy for record in records}
        assert applied == set(MUTATION_STRATEGIES)

    def test_run_indices_are_contiguous(self) -> None:
        records = generate_mutants("seed-input", count=5, seed=1)
        assert [record.run_index for record in records] == [0, 1, 2, 3, 4]

    def test_budget_of_zero_produces_nothing(self) -> None:
        assert generate_mutants("seed-input", count=0, seed=1) == []

    def test_negative_budget_produces_nothing(self) -> None:
        assert generate_mutants("seed-input", count=-3, seed=1) == []


class TestDictionary:
    def test_default_dictionary_carries_format_and_traversal_payloads(self) -> None:
        assert any("%s" in token for token in DEFAULT_DICTIONARY)
        assert any("../" in token for token in DEFAULT_DICTIONARY)

    def test_dictionary_payloads_reach_the_input(self) -> None:
        # A single dictionary-strategy run uses the whole default dictionary as
        # its token pool; over enough runs every token must appear.
        records = [
            generate_mutants("base", count=4, seed=index)[3].mutated_input for index in range(400)
        ]
        joined = "\n".join(records)
        assert "%s%s%s%s" in joined
        assert "../../../etc/passwd" in joined

    def test_custom_dictionary_replaces_the_default(self) -> None:
        records = generate_mutants("base", count=4, seed=3, dictionary=("CUSTOM_TOKEN",))
        assert "CUSTOM_TOKEN" in records[3].mutated_input

    def test_no_embedded_nul_ever_reaches_an_invocation(self) -> None:
        # execve rejects an embedded NUL in argv, so the engine must drop it.
        for index in range(200):
            records = generate_mutants("A\x00B", count=4, seed=index)
            assert all("\x00" not in record.mutated_input for record in records)


class TestDeterminism:
    def test_same_seed_same_ordered_sequence(self) -> None:
        first = generate_mutants("echo hello", count=32, seed=99)
        second = generate_mutants("echo hello", count=32, seed=99)
        assert [r.mutated_input for r in first] == [r.mutated_input for r in second]
        assert [r.strategy for r in first] == [r.strategy for r in second]

    def test_different_seed_changes_the_sequence(self) -> None:
        first = generate_mutants("echo hello", count=32, seed=1)
        second = generate_mutants("echo hello", count=32, seed=2)
        assert [r.mutated_input for r in first] != [r.mutated_input for r in second]

    def test_bit_flip_changes_exactly_one_input(self) -> None:
        records = generate_mutants("ABCDEFGH", count=1, seed=5)
        record = records[0]
        assert record.strategy == "bit_flip"
        assert record.mutated_input != "ABCDEFGH"

    def test_byte_insert_grows_the_input(self) -> None:
        records = generate_mutants("ABCD", count=2, seed=5)
        insert = records[1]
        assert insert.strategy == "byte_insert"
        assert len(insert.mutated_input) == len("ABCD") + 1

    def test_byte_delete_shrinks_the_input(self) -> None:
        records = generate_mutants("ABCD", count=3, seed=5)
        delete = records[2]
        assert delete.strategy == "byte_delete"
        assert len(delete.mutated_input) == len("ABCD") - 1

    def test_ops_on_empty_input_are_safe(self) -> None:
        records = generate_mutants("", count=8, seed=5)
        assert len(records) == 8
        assert all(isinstance(r.mutated_input, str) for r in records)
