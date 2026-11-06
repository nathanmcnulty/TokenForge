"""Stage the checked-in empty-observation fixture; never read operational state."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import zipfile


def stage(output, source, run_id, attempt):
    if not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("exact source commit required")
    if any(not re.fullmatch(r"[1-9][0-9]{0,18}", n) for n in (run_id, attempt)):
        raise ValueError("numeric run identity required")
    fixture = Path(__file__).resolve().parent.parent / "tests/fixtures/publication/public-canary"
    names = {"manifest.json", "coverage.json", "flows.json", "recipe.json",
             "review.md", "scopes.json", "validation.json"}
    entries = list(fixture.iterdir())
    if ({p.name for p in entries} != names
            or any(p.is_symlink() or not p.is_file() for p in entries)):
        raise ValueError("public fixture membership changed")
    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("new absolute output directory required")
    output.mkdir(mode=0o700)
    manifest = json.loads((fixture / "manifest.json").read_text())
    for name in sorted(names - {"manifest.json"}):
        data = (fixture / name).read_bytes()
        expected = next(row["Sha256"] for row in manifest["Files"] if row["Path"] == name)
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("public fixture digest changed")
        with (output / name).open("xb") as stream:
            stream.write(data)
    manifest.update(SourceCommit=source, ProducerRunId=run_id, ProducerAttempt=attempt)
    with (output / "manifest.json").open("x") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    # The official artifact ZIP must not carry arbitrary producer timestamps/modes.
    for path in output.iterdir():
        path.chmod(0o600)
        os.utime(path, (315532800, 315532800))  # 1980-01-01 UTC, ZIP epoch.


def verify_archive(archive, expected_directory, source, run_id, attempt):
    """Fixture-only oracle: compare ALL original bytes, not extracted membership."""
    archive = Path(archive)
    if archive.is_symlink() or not archive.is_file() or not 0 < archive.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("bounded regular original archive required")
    stage(expected_directory, source, run_id, attempt)
    oracle = Path(__file__).resolve().parent.parent / "tests/fixtures/publication/MutateSealerZip.py"
    spec = importlib.util.spec_from_file_location("zip_oracle", oracle)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = archive.read_bytes()
    with zipfile.ZipFile(io.BytesIO(actual)) as container:
        order = [entry.filename for entry in container.infolist()]
    expected = module.canonical_from_directory(expected_directory, official=True, order=order)
    if actual != expected:
        raise ValueError("original archive differs from complete public fixture profile")
    return {"SchemaVersion": 1, "SyntheticFixtureOnly": True,
            "OriginalArchiveSha256": hashlib.sha256(actual).hexdigest(),
            "CandidateHash": hashlib.sha256((Path(expected_directory) / "manifest.json").read_bytes()).hexdigest(),
            "Bytes": len(actual), "ArchiveProfile": "GitHubStoredOriginalZipV2",
            "EntryOrder": order,
            "CompleteOriginalBytesValidated": True, "ProductionApprovalEstablished": False}


if __name__ == "__main__":
    context = (os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"])
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-archive":
        print(json.dumps(verify_archive(sys.argv[2], sys.argv[3], *context)))
    elif len(sys.argv) == 2:
        stage(sys.argv[1], *context)
    else:
        raise ValueError("expected new staging directory, or --verify-archive archive new-directory")
