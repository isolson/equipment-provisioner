from pathlib import Path

from scripts import check_bench_evidence
from scripts.check_bench_evidence import RAW_FILES, check_all, check_one, evidence_dir


def _args(repo_root, raw_root, repo_only=True):
    repo_root_value = str(repo_root)
    raw_root_value = str(raw_root)
    repo_only_value = repo_only

    class Args:
        all = False
        vendor = "tachyon"
        model = "TNA-303L-65"
        firmware = "1.15.1-rev-8541"
        repo_root = repo_root_value
        raw_root = raw_root_value
        repo_only = repo_only_value

    return Args()


def _manifest(role="SM"):
    return (
        "vendor: tachyon\n"
        "config_role: %s\n"
        "artifact_purpose: process-evidence\n"
        "reusable_template: false\n"
        "canonical_template_status: not-included\n" % role
    )


def test_evidence_dir_uses_stable_components(tmp_path):
    path = evidence_dir(tmp_path, "Tachyon", "TNA-303L-65", "1.15.1 rev 8541")
    assert path == tmp_path / "tachyon" / "TNA-303L-65" / "1.15.1_rev_8541"


def test_repo_only_requires_manifest_and_redacted_fixtures(tmp_path):
    args = _args(tmp_path / "repo", tmp_path / "raw")
    assert check_one(args) == 1

    directory = evidence_dir(Path(args.repo_root), args.vendor, args.model, args.firmware)
    directory.mkdir(parents=True)
    (directory / "manifest.yaml").write_text(_manifest(), encoding="utf-8")
    (directory / "no-config.structure.json").write_text("{}\n", encoding="utf-8")
    (directory / "known-good.structure.json").write_text("{}\n", encoding="utf-8")
    assert check_one(args) == 0


def test_repo_only_requires_manifest_config_role(tmp_path):
    args = _args(tmp_path / "repo", tmp_path / "raw")
    directory = evidence_dir(Path(args.repo_root), args.vendor, args.model, args.firmware)
    directory.mkdir(parents=True)
    (directory / "manifest.yaml").write_text("vendor: tachyon\n", encoding="utf-8")
    (directory / "no-config.structure.json").write_text("{}\n", encoding="utf-8")
    (directory / "known-good.structure.json").write_text("{}\n", encoding="utf-8")

    assert check_one(args) == 1


def test_all_checks_committed_evidence(tmp_path):
    repo_root = tmp_path / "repo"
    directory = evidence_dir(repo_root, "tachyon", "TNA-303L-65", "1.15.1-rev-8541")
    directory.mkdir(parents=True)
    (directory / "manifest.yaml").write_text(_manifest(), encoding="utf-8")
    (directory / "no-config.structure.json").write_text("{}\n", encoding="utf-8")
    (directory / "known-good.structure.json").write_text("{}\n", encoding="utf-8")

    repo_root_value = str(repo_root)

    class Args:
        repo_root = repo_root_value

    assert check_all(Args()) == 0


def test_raw_evidence_requires_private_permissions(tmp_path):
    args = _args(tmp_path / "repo", tmp_path / "raw", repo_only=False)
    repo_directory = evidence_dir(Path(args.repo_root), args.vendor, args.model, args.firmware)
    repo_directory.mkdir(parents=True)
    (repo_directory / "manifest.yaml").write_text(_manifest(), encoding="utf-8")
    (repo_directory / "no-config.structure.json").write_text("{}\n", encoding="utf-8")
    (repo_directory / "known-good.structure.json").write_text("{}\n", encoding="utf-8")

    raw_directory = evidence_dir(Path(args.raw_root), args.vendor, args.model, args.firmware)
    raw_directory.mkdir(parents=True)
    for name in RAW_FILES:
        (raw_directory / name).write_text("placeholder\n", encoding="utf-8")
        (raw_directory / name).chmod(0o600)
    raw_directory.chmod(0o755)

    assert check_one(args) == 1


def test_combined_workflow_can_cover_upgrade_and_config_apply(tmp_path):
    args = _args(tmp_path / "repo", tmp_path / "raw", repo_only=False)
    repo_directory = evidence_dir(Path(args.repo_root), args.vendor, args.model, args.firmware)
    repo_directory.mkdir(parents=True)
    (repo_directory / "manifest.yaml").write_text(_manifest(), encoding="utf-8")
    (repo_directory / "no-config.structure.json").write_text("{}\n", encoding="utf-8")
    (repo_directory / "known-good.structure.json").write_text("{}\n", encoding="utf-8")

    raw_root = Path(args.raw_root)
    raw_root.mkdir(mode=0o700)
    raw_directory = evidence_dir(raw_root, args.vendor, args.model, args.firmware)
    raw_directory.mkdir(parents=True, mode=0o700)
    (raw_directory / "workflow.har").write_text("capture\n", encoding="utf-8")
    (raw_directory / "no-config.device-backup.json").write_text("backup\n", encoding="utf-8")
    (raw_directory / "known-good.device-backup.json").write_text("backup\n", encoding="utf-8")
    for path in raw_directory.iterdir():
        path.chmod(0o600)

    assert check_one(args) == 0


def test_manifest_transitions_are_validated(tmp_path):
    directory = tmp_path / "cambium" / "ePMP_4518" / "5.11.1"
    directory.mkdir(parents=True)
    (directory / "known-good.structure.json").write_text("{}")
    (directory / "no-config.structure.json").write_text("{}")
    good = _manifest() + "transitions:\n  - {from: fresh, to: sm, result: success}\n  - {from: ap, to: sm, result: success}\n"
    (directory / "manifest.yaml").write_text(good)
    assert check_bench_evidence.check_manifest(directory / "manifest.yaml") is None
    bad = _manifest() + "transitions:\n  - {from: sm, to: mesh, result: success}\n"
    (directory / "manifest.yaml").write_text(bad)
    assert "from/to" in check_bench_evidence.check_manifest(directory / "manifest.yaml")
    bad = _manifest() + "transitions:\n  - {from: sm, to: ap, result: maybe}\n"
    (directory / "manifest.yaml").write_text(bad)
    assert "result" in check_bench_evidence.check_manifest(directory / "manifest.yaml")


def test_declared_missing_no_config_backup_relaxes_the_fixture_requirement(tmp_path, monkeypatch):
    directory = tmp_path / "cambium" / "ePMP_4518" / "5.11.1"
    directory.mkdir(parents=True)
    (directory / "known-good.structure.json").write_text("{}")
    (directory / "manifest.yaml").write_text(_manifest() + "no_config_backup: missing\n")
    monkeypatch.setattr(
        "sys.argv",
        ["check_bench_evidence.py", "--repo-only", "--repo-root", str(tmp_path),
         "--vendor", "cambium", "--model", "ePMP 4518", "--firmware", "5.11.1"],
    )
    assert check_bench_evidence.main() == 0
    (directory / "manifest.yaml").write_text(_manifest())
    assert check_bench_evidence.main() == 1
