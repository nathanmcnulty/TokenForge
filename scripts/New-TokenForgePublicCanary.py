"""Stage the checked-in empty-observation fixture; never read operational state."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys


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


if __name__ == "__main__":
    stage(sys.argv[1], os.environ["GITHUB_SHA"], os.environ["GITHUB_RUN_ID"],
          os.environ["GITHUB_RUN_ATTEMPT"])
