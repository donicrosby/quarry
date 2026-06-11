"""TDD: per-role max_iterations config + scan_seed wiring."""

from __future__ import annotations

import uuid

from quarry.panel_config import ScanDefaultsConfig
from quarry_workflows.run_scan import RunScanInput

# ---------------------------------------------------------------------------
# ScanDefaultsConfig schema
# ---------------------------------------------------------------------------


class TestScanDefaultsSchema:
    def test_has_validate_max_iterations(self) -> None:
        cfg = ScanDefaultsConfig()
        assert hasattr(cfg, "validate_max_iterations")
        assert isinstance(cfg.validate_max_iterations, int)
        assert cfg.validate_max_iterations > 0

    def test_has_gapfill_max_iterations(self) -> None:
        cfg = ScanDefaultsConfig()
        assert hasattr(cfg, "gapfill_max_iterations")
        assert isinstance(cfg.gapfill_max_iterations, int)
        assert cfg.gapfill_max_iterations > 0

    def test_has_recon_max_iterations(self) -> None:
        cfg = ScanDefaultsConfig()
        assert hasattr(cfg, "recon_max_iterations")
        assert isinstance(cfg.recon_max_iterations, int)
        assert cfg.recon_max_iterations > 0

    def test_has_dedup_max_iterations(self) -> None:
        cfg = ScanDefaultsConfig()
        assert hasattr(cfg, "dedup_max_iterations")
        assert isinstance(cfg.dedup_max_iterations, int)
        assert cfg.dedup_max_iterations > 0

    def test_has_seed_field_defaulting_to_none(self) -> None:
        cfg = ScanDefaultsConfig()
        assert hasattr(cfg, "seed")
        assert cfg.seed is None

    def test_seed_can_be_set(self) -> None:
        cfg = ScanDefaultsConfig(seed=42)
        assert cfg.seed == 42

    def test_defaults_match_current_activity_defaults(self) -> None:
        """Defaults must not change existing behaviour for scans that omit config."""
        cfg = ScanDefaultsConfig()
        assert cfg.validate_max_iterations == 20
        assert cfg.gapfill_max_iterations == 20
        assert cfg.recon_max_iterations == 40
        assert cfg.dedup_max_iterations == 8
        assert cfg.hunt_max_iterations == 12


# ---------------------------------------------------------------------------
# RunScanInput schema
# ---------------------------------------------------------------------------


class TestRunScanInputSchema:
    def test_has_validate_max_iterations(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert hasattr(inp, "validate_max_iterations")

    def test_has_gapfill_max_iterations(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert hasattr(inp, "gapfill_max_iterations")

    def test_has_recon_max_iterations(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert hasattr(inp, "recon_max_iterations")

    def test_has_dedup_max_iterations(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert hasattr(inp, "dedup_max_iterations")

    def test_has_scan_seed_defaulting_to_none(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert hasattr(inp, "scan_seed")
        assert inp.scan_seed is None


# ---------------------------------------------------------------------------
# Seed derivation
# ---------------------------------------------------------------------------


class TestSeedDerivation:
    def test_seed_derived_from_scan_id_is_deterministic(self) -> None:
        from quarry_activities.seed import derive_seed

        scan_id = str(uuid.uuid4())
        assert derive_seed(scan_id) == derive_seed(scan_id)

    def test_seed_derived_from_different_scan_ids_differ(self) -> None:
        from quarry_activities.seed import derive_seed

        s1 = str(uuid.uuid4())
        s2 = str(uuid.uuid4())
        assert derive_seed(s1) != derive_seed(s2)

    def test_derived_seed_is_positive_int(self) -> None:
        from quarry_activities.seed import derive_seed

        seed = derive_seed(str(uuid.uuid4()))
        assert isinstance(seed, int)
        assert seed >= 0

    def test_pinned_seed_takes_priority_over_derived(self) -> None:
        from quarry_activities.seed import resolve_seed

        scan_id = str(uuid.uuid4())
        assert resolve_seed(pinned=42, scan_id=scan_id) == 42

    def test_none_pinned_seed_falls_back_to_derived(self) -> None:
        from quarry_activities.seed import derive_seed, resolve_seed

        scan_id = str(uuid.uuid4())
        assert resolve_seed(pinned=None, scan_id=scan_id) == derive_seed(scan_id)


# ---------------------------------------------------------------------------
# LiteLLMClient seed forwarding
# ---------------------------------------------------------------------------


class TestLiteLLMClientSeed:
    def test_litellm_client_accepts_seed(self) -> None:
        from quarry_models.litellm_client import LiteLLMModelClient

        client = LiteLLMModelClient(seed=42)
        assert client.seed == 42

    def test_litellm_client_default_seed_is_none(self) -> None:
        from quarry_models.litellm_client import LiteLLMModelClient

        client = LiteLLMModelClient()
        assert client.seed is None

    def test_build_model_client_forwards_seed_to_litellm(self) -> None:
        from quarry.schemas import Provider
        from quarry_models.factory import build_model_client
        from quarry_models.litellm_client import LiteLLMModelClient

        client = build_model_client(Provider.LITELLM, seed=99)
        assert isinstance(client, LiteLLMModelClient)
        assert client.seed == 99
