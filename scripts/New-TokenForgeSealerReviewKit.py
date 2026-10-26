"""Build a local, immutable-source Linux review kit; no build/install/network/auth.

This is a review/test kit, not a release package or new native-runtime build.
"""
import argparse
import gzip
import hashlib
import io
import os
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

PINS = {
    "local-package-manifest.json": "8295f2508bc95d67c1ce61904cd3a4bba5a7ccac0f8d30af8ef34066eff383c9",
    "tokenforge": "987c863bc92f29de27ff812ad360cd1be1a8bde0fda6080f465827dbb6eb99db",
    "src/TokenForge/lib/net8.0/TokenForge.Credentials.dll": "30d5d1268223c806e8c6d26fd138ef2f1db58dd23f067f59ac38387e2d7bad32",
}
RUNTIME_SOURCE = "0a1704d057417e58b92fd5eac8c546541d3f7ec2"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def create_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def make_kit(repo, commit, runtime, target, archive):
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == "0" * 40:
        raise ValueError("exact source commit required")
    for path in (repo, runtime, target.parent, archive.parent):
        if not path.is_absolute() or path.resolve() != path or not path.is_dir():
            raise ValueError("existing unlinked absolute parent required")
    if target.exists() or target.is_symlink() or archive.exists() or archive.is_symlink():
        raise ValueError("new destinations required")
    files = {}
    for name, expected in PINS.items():
        path = runtime / name
        if path.resolve() != path or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("runtime input refused")
        files[name] = path.read_bytes()
        if digest(files[name]) != expected:
            raise ValueError("exact runtime pin mismatch")
    baseline = json.loads(files["local-package-manifest.json"])
    if baseline["sourceRevision"] != RUNTIME_SOURCE:
        raise ValueError("runtime source mismatch")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
           "GIT_ALLOW_PROTOCOL": "", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": "",
           "GIT_CONFIG_KEY_1": "protocol.allow", "GIT_CONFIG_VALUE_1": "never"}
    # Read literal blobs, not a checkout/archive: no attributes, substitutions,
    # filters or hooks may alter the exact-source input.
    tree = subprocess.run(["/usr/bin/git", "-C", str(repo), "ls-tree", "-r", "-l", "-z", commit],
                          env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30, check=True).stdout
    if len(tree) > 2 * 1024 * 1024:
        raise ValueError("source tree bound")
    entries = []
    seen = set()
    for line in tree.split(b"\0"):
        if not line:
            continue
        meta, name = line.split(b"\t", 1)
        mode, kind, oid, length = meta.split()
        name = name.decode("utf-8", errors="strict")
        relative = Path(name)
        if (mode not in (b"100644", b"100755") or kind != b"blob"
                or not re.fullmatch(rb"[a-f0-9]{40}", oid) or not length.isdigit()
                or relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts or name in seen):
            raise ValueError("source member refused")
        seen.add(name)
        entries.append((name, mode, oid, int(length)))
    if not entries or len(entries) > 4096 or sum(row[3] for row in entries) > 32 * 1024 * 1024:
        raise ValueError("source member bound")
    expected_sources = dict(baseline["nativeInputs"])
    expected_sources.update({name: value for name, value in baseline["files"].items()
                             if name.startswith("src/TokenForge/")
                             and name != "src/TokenForge/lib/net8.0/TokenForge.Credentials.dll"})
    build_inputs = {"global.json", "scripts/Build-TokenForgeCredentials.ps1",
                    "scripts/Build-TokenForgeNative.ps1", "scripts/Copy-TokenForgePackageSource.ps1"}
    actual_sources = {name for name, _, _, _ in entries
                      if name.startswith(("native/", "src/TokenForge/")) or name in build_inputs}
    if actual_sources != set(expected_sources):
        raise ValueError("native/module/build input file set changed; new runtime build required")
    required = {"scripts/TokenForgeSealerZip.ps1", "scripts/TokenForgeSealer.ps1", "scripts/TokenForgeSealerPolicy.ps1",
                "scripts/Invoke-TokenForgeSealer.ps1", "publication/zip-profile.json", "tests/Sealer.Tests.ps1"}
    if not required.issubset(seen):
        raise ValueError("canonical sealer source closure missing")
    content = subprocess.run(["/usr/bin/git", "-C", str(repo), "cat-file", "--batch"],
                             env=env, input=b"".join(row[2] + b"\n" for row in entries),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True).stdout
    if len(content) > 33 * 1024 * 1024:
        raise ValueError("source content bound")
    target.mkdir(mode=0o700)
    created_archive = False
    try:
        source = io.BytesIO(content)
        for name, mode, oid, size in entries:
            if source.readline() != oid + b" blob " + str(size).encode("ascii") + b"\n":
                raise ValueError("source blob header")
            payload = source.read(size)
            if len(payload) != size or source.read(1) != b"\n":
                raise ValueError("source blob bound")
            if hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + payload).hexdigest().encode("ascii") != oid:
                raise ValueError("source blob identity")
            if name in expected_sources and digest(payload) != expected_sources[name]:
                raise ValueError("native/module/build input changed; new runtime build required")
            dest = target / name
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with create_file(dest) as out:
                out.write(payload)
            dest.chmod(0o700 if mode == b"100755" else 0o600)
        if source.read(1):
            raise ValueError("source batch trailing data")
        for name in ("tokenforge", "src/TokenForge/lib/net8.0/TokenForge.Credentials.dll"):
            path = target / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with create_file(path) as out:
                out.write(files[name])
            path.chmod(0o700 if name == "tokenforge" else 0o600)
        manifest = {"schemaVersion": 1, "kind": "TokenForgeOfflineSealerReviewKit", "releasePackage": False,
                    "sourceCommit": commit, "runtimeSource": RUNTIME_SOURCE, "runtimePins": PINS,
                    "nativeAndModuleInputsBoundToPinnedManifest": True, "nativeRebuilt": False, "operationalPolicyEmissionAllowed": False, "hostedActivationAllowed": False,
                    "filesSha256": {str(p.relative_to(target)): digest(p.read_bytes())
                                    for p in sorted(target.rglob("*")) if p.is_file()}}
        with create_file(target / "review-kit-manifest.json") as out:
            out.write((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
        (target / "review-kit-manifest.json").chmod(0o600)
        with create_file(archive) as output:
            created_archive = True
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w") as tar:
                    for path in sorted(target.rglob("*")):
                        info = tar.gettarinfo(str(path), arcname=str(path.relative_to(target)))
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        if path.is_file():
                            with path.open("rb") as data:
                                tar.addfile(info, data)
                        else:
                            tar.addfile(info)
        archive.chmod(0o600)
        return {"kind": manifest["kind"], "sourceCommit": commit, "runtimeSource": RUNTIME_SOURCE,
                "manifestSha256": digest((target / "review-kit-manifest.json").read_bytes()),
                "archiveSha256": digest(archive.read_bytes()), "archiveBytes": archive.stat().st_size,
                "files": len(manifest["filesSha256"]), "nativeRebuilt": False}
    except BaseException:
        shutil.rmtree(target)
        if created_archive:
            archive.unlink()
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "commit", "runtime", "target", "archive"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        result = make_kit(Path(args.repo), args.commit, Path(args.runtime), Path(args.target), Path(args.archive))
    except Exception:
        raise SystemExit("Review kit creation refused; no fallback or existing-output overwrite.")
    print(json.dumps(result))
