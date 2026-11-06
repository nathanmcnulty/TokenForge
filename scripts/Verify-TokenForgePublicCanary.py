"""Verify a real service artifact against only the reviewed public fixture.

This premerge compatibility check cannot approve a production candidate.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "nathanmcnulty/TokenForge"
REPOSITORY_ID = 1402673320
BRANCH = "codex/issue113-publication-acceptance"


def api(route):
    result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/{route}"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError("bounded GitHub metadata request refused")
    return json.loads(result.stdout)


def verify(artifact_id, output, source=None, run_id=None, attempt=None):
    if not re.fullmatch(r"[1-9][0-9]{0,18}", artifact_id):
        raise ValueError("numeric artifact identity required")
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or os.environ["GITHUB_REF"] != f"refs/heads/{BRANCH}":
        raise ValueError("only the explicitly approved synthetic branch is supported")
    source = source or os.environ["GITHUB_SHA"]
    run_id = run_id or os.environ["GITHUB_RUN_ID"]
    attempt = attempt or os.environ["GITHUB_RUN_ATTEMPT"]
    if not re.fullmatch(r"[a-f0-9]{40}", source) or any(not re.fullmatch(r"[1-9][0-9]{0,18}", n) for n in (run_id, attempt)):
        raise ValueError("exact producer context required")
    run = api(f"actions/runs/{run_id}")
    if (run["head_sha"] != source or str(run["run_attempt"]) != attempt
            or run["repository"]["id"] != REPOSITORY_ID or run["head_repository"]["id"] != REPOSITORY_ID
            or run["head_branch"] != BRANCH or run["path"] != ".github/workflows/ci.yml"
            or run["event"] != "workflow_dispatch" or run["status"] not in ("in_progress", "completed")
            or (run["status"] == "completed" and run["conclusion"] != "success")):
        raise ValueError("producer context mismatch")
    artifact = api(f"actions/artifacts/{artifact_id}")
    if (str(artifact["id"]) != artifact_id or artifact["expired"] is not False
            or artifact["name"] != f"tokenforge-synthetic-public-canary-{run_id}-{attempt}"
            or not 0 < artifact["size_in_bytes"] <= 8 * 1024 * 1024
            or artifact["workflow_run"]["id"] != int(run_id)
            or artifact["workflow_run"]["head_sha"] != source
            or artifact["workflow_run"]["repository_id"] != REPOSITORY_ID
            or artifact["workflow_run"]["head_repository_id"] != REPOSITORY_ID):
        raise ValueError("original artifact identity mismatch")
    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError("new absolute evidence directory required")
    output.mkdir(mode=0o700)
    original = output / "candidate.zip"
    with original.open("xb") as stream:
        result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"],
                                stdout=stream, stderr=subprocess.PIPE, timeout=30)
    if result.returncode or original.stat().st_size != artifact["size_in_bytes"]:
        raise ValueError("original service size mismatch")
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    if artifact["digest"] != "sha256:" + digest:
        raise ValueError("original service digest/size mismatch")
    spec = importlib.util.spec_from_file_location("canary", Path(__file__).with_name("New-TokenForgePublicCanary.py"))
    canary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(canary)
    report = canary.verify_archive(original, output / "expected", source, run_id, attempt)
    # Prove that a hidden suffix is refused before any signing step can run.
    changed = output / "tampered.zip"
    changed.write_bytes(original.read_bytes() + b"SYNTHETIC_METADATA_MARKER")
    try:
        canary.verify_archive(changed, output / "negative-expected", source, run_id, attempt)
    except ValueError:
        report["HiddenSuffixRejected"] = True
    else:
        raise ValueError("hidden suffix was accepted")
    if api(f"actions/artifacts/{artifact_id}") != artifact:
        raise ValueError("artifact changed during validation")
    report.update(ArtifactId=artifact_id, SourceCommit=source, ProducerRunId=run_id, ProducerAttempt=attempt)
    (output / "subject.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    if len(sys.argv) not in (3, 6):
        raise ValueError("expected artifact/output and optional exact producer source/run/attempt")
    print(json.dumps(verify(*sys.argv[1:])))
