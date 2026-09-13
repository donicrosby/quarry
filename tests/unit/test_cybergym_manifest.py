"""Tests for CyberGym manifest parsing, subset selection, materialization."""

from __future__ import annotations

import tarfile
import zlib
from collections.abc import Callable
from io import BytesIO
from pathlib import Path

import pytest

from quarry_benchmark.cybergym import (
    OFFICIAL_SUBSET_10,
    MaterializedTask,
    hf_url,
    image_names,
    level_files,
    load_manifest,
    materialize,
    runner_command,
    select_project,
    select_subset,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cybergym" / "mini_tasks.json"


class TestLoadManifest:
    def test_loads_all_tasks(self) -> None:
        tasks = load_manifest(FIXTURE)
        assert [t.task_id for t in tasks] == [
            "arvo:1065",
            "oss-fuzz:42535201",
            "arvo:999999",
        ]

    def test_parses_fields(self) -> None:
        task = load_manifest(FIXTURE)[0]
        assert task.project_name == "file"
        assert task.project_language == "c"
        assert task.vulnerability_description.startswith("A bug in glibc")

    def test_rejects_entry_missing_task_difficulty(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(
            '[{"task_id": "arvo:1", "project_name": "x", '
            '"project_homepage": "h", "project_main_repo": "r", '
            '"project_language": "c", "vulnerability_description": "d"}]',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="task_difficulty"):
            load_manifest(bad)

    def test_rejects_non_list(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError, match="JSON array"):
            load_manifest(bad)


class TestSubsetSelection:
    def test_official_subset_10_exact(self) -> None:
        assert OFFICIAL_SUBSET_10 == [
            "arvo:47101",
            "arvo:3938",
            "arvo:24993",
            "arvo:1065",
            "arvo:10400",
            "arvo:368",
            "oss-fuzz:42535201",
            "oss-fuzz:42535468",
            "oss-fuzz:370689421",
            "oss-fuzz:385167047",
        ]

    def test_select_subset_filters_and_preserves_manifest_order(self) -> None:
        tasks = load_manifest(FIXTURE)
        picked = select_subset(tasks, ["arvo:999999", "arvo:1065"])
        assert [t.task_id for t in picked] == ["arvo:1065", "arvo:999999"]

    def test_select_subset_unknown_id_raises(self) -> None:
        tasks = load_manifest(FIXTURE)
        with pytest.raises(ValueError, match="arvo:404"):
            select_subset(tasks, ["arvo:1065", "arvo:404"])

    def test_select_project_case_insensitive(self) -> None:
        tasks = load_manifest(FIXTURE)
        assert [t.task_id for t in select_project(tasks, "FILE")] == ["arvo:1065"]

    def test_select_project_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="no-such-project"):
            select_project(load_manifest(FIXTURE), "no-such-project")


class TestLevelFiles:
    def test_level0_is_repo_only(self) -> None:
        task = load_manifest(FIXTURE)[0]
        assert level_files(task, "level0") == ["data/arvo/1065/repo-vul.tar.gz"]

    def test_level1_adds_description(self) -> None:
        task = load_manifest(FIXTURE)[0]
        assert level_files(task, "level1") == [
            "data/arvo/1065/repo-vul.tar.gz",
            "data/arvo/1065/description.txt",
        ]

    def test_unknown_level_raises(self) -> None:
        task = load_manifest(FIXTURE)[0]
        with pytest.raises(ValueError, match="level4"):
            level_files(task, "level4")


class TestImagesAndCommands:
    def test_arvo_images(self) -> None:
        assert image_names("arvo:1065") == ("n132/arvo:1065-vul", "n132/arvo:1065-fix")

    def test_oss_fuzz_images(self) -> None:
        assert image_names("oss-fuzz:42535201") == (
            "cybergym/oss-fuzz:42535201-vul",
            "cybergym/oss-fuzz:42535201-fix",
        )

    def test_runner_command_per_source(self) -> None:
        assert runner_command("arvo:1065") == ["/bin/arvo"]
        assert runner_command("oss-fuzz:42535201") == ["/usr/local/bin/run_poc"]

    @pytest.mark.parametrize(
        "bad",
        ["arvo:abc", "oss-fuzz:", "evil/1065", "n132/arvo:1065", "", "arvo:1065-vul"],
    )
    def test_task_id_injection_guard(self, bad: str) -> None:
        with pytest.raises(ValueError, match="task id"):
            image_names(bad)


class TestHfUrl:
    def test_url_shape(self) -> None:
        assert hf_url("arvo:1065", "repo-vul.tar.gz") == (
            "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/"
            "data/arvo/1065/repo-vul.tar.gz"
        )

    def test_url_rejects_slash_in_filename(self) -> None:
        with pytest.raises(ValueError, match="filename"):
            hf_url("arvo:1065", "../escape.tar.gz")


def _tar_bytes(name: str, content: bytes) -> bytes:
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tar.addfile(info, BytesIO(content))
    return buf.getvalue()


Fetch = Callable[[str], bytes]


def _fake_fetch(files: dict[str, bytes]) -> Fetch:
    def fetch(url: str) -> bytes:
        for path, content in files.items():
            suffix = path.replace("data/", "").replace("/", "/")
            if url.endswith("/" + path) or url.endswith(suffix):
                return content
        raise AssertionError(f"unexpected fetch: {url}")

    return fetch


class TestMaterialize:
    def test_materializes_level1_repo_and_description(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        repo_tar = _tar_bytes("src/file.c", b"int main(){}\n")
        files = {
            "data/arvo/1065/repo-vul.tar.gz": repo_tar,
            "data/arvo/1065/description.txt": b"buffer overflow in parser",
        }
        mat = materialize(task, "level1", tmp_path, fetch=_fake_fetch(files))
        assert isinstance(mat, MaterializedTask)
        assert mat.repo_dir.is_dir()
        assert (mat.repo_dir / "src" / "file.c").read_bytes() == b"int main(){}\n"
        assert mat.description_path is not None
        assert mat.description_path.read_text(encoding="utf-8") == "buffer overflow in parser"
        # downloaded archives stay inside the task dir for provenance
        task_dir = tmp_path / "arvo:1065"
        assert (task_dir / "repo-vul.tar.gz").is_file()

    def test_level0_has_no_description(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        files = {"data/arvo/1065/repo-vul.tar.gz": _tar_bytes("a.c", b"x")}
        mat = materialize(task, "level0", tmp_path, fetch=_fake_fetch(files))
        assert mat.description_path is None

    def test_skips_existing_downloads(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        calls: list[str] = []

        def fetch(url: str) -> bytes:
            calls.append(url)
            return _tar_bytes("a.c", b"x")

        # first materialize downloads
        materialize(task, "level0", tmp_path, fetch=fetch)
        assert len(calls) == 1
        task_dir = tmp_path / "arvo:1065"
        # make the cached tarball different to prove it is NOT re-fetched
        (task_dir / "repo-vul.tar.gz").write_bytes(_tar_bytes("cached.c", b"y"))
        mat = materialize(task, "level0", tmp_path, fetch=fetch)
        assert calls == [calls[0]]
        assert (mat.repo_dir / "cached.c").read_bytes() == b"y"

    def test_rejects_absolute_member_paths(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        evil = _tar_bytes("/etc/passwd", b"pwn")
        files = {"data/arvo/1065/repo-vul.tar.gz": evil}
        with pytest.raises(ValueError, match="absolute"):
            materialize(task, "level0", tmp_path, fetch=_fake_fetch(files))

    def test_rejects_dot_dot_member_paths(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        evil = _tar_bytes("../evil.c", b"pwn")
        files = {"data/arvo/1065/repo-vul.tar.gz": evil}
        with pytest.raises(ValueError, match="traversal"):
            materialize(task, "level0", tmp_path, fetch=_fake_fetch(files))

    def test_empty_download_raises(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        files = {"data/arvo/1065/repo-vul.tar.gz": b""}
        with pytest.raises(ValueError, match="empty"):
            materialize(task, "level0", tmp_path, fetch=_fake_fetch(files))

    def test_garbage_tarball_raises(self, tmp_path: Path) -> None:
        task = load_manifest(FIXTURE)[0]
        files = {"data/arvo/1065/repo-vul.tar.gz": zlib.compress(b"not a tar")}
        with pytest.raises(ValueError, match="tar"):
            materialize(task, "level0", tmp_path, fetch=_fake_fetch(files))
