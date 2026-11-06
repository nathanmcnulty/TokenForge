"""Verify the synthetic canary with pinned existing tools, offline and credential-free."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

VERIFIER_SHA256 = "b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d"
ROOT_SHA256 = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"


def copy_bound(source, target, maximum, expected=None, executable=False):
    source = Path(source).resolve(strict=True)
    if not source.is_file() or not 0 < source.stat().st_size <= maximum:
        raise ValueError("bounded regular verifier input required")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > maximum or (expected is not None and digest != expected):
        raise ValueError("pinned verifier input mismatch")
    with target.open("xb") as stream:
        stream.write(data)
    target.chmod(0o500 if executable else 0o600)
    return digest


def verify(directory, bundle):
    if sys.platform != "linux" or os.environ["GITHUB_REPOSITORY"] != "nathanmcnulty/TokenForge" or os.environ["GITHUB_REF"] != "refs/heads/codex/issue113-publication-acceptance":
        raise ValueError("approved Linux synthetic context required")
    directory = Path(directory)
    scratch = directory / "offline-verifier"
    scratch.mkdir(mode=0o700)
    executable = scratch / "gh"
    copy_bound(shutil.which("gh"), executable, 128 * 1024 * 1024, VERIFIER_SHA256, executable=True)
    root = Path(__file__).resolve().parent.parent / "tests/fixtures/attestation/provisioned-root.jsonl"
    copy_bound(root, scratch / "root.jsonl", 256 * 1024, ROOT_SHA256)
    copy_bound(bundle, scratch / "bundle.jsonl", 4 * 1024 * 1024)
    copy_bound(bundle, directory / "bundle.jsonl", 4 * 1024 * 1024)
    subject = json.loads((directory / "subject.json").read_text())
    copy_bound(directory / "candidate.zip", scratch / "candidate.zip", 8 * 1024 * 1024,
               subject["OriginalArchiveSha256"])
    copy_bound(directory / "tampered.zip", scratch / "tampered.zip", 8 * 1024 * 1024)
    source = os.environ["GITHUB_SHA"]
    user = pwd.getpwuid(os.getuid()).pw_name
    # Root creates only an ephemeral network namespace, then drops to the runner.
    # No sysctl/policy change or installation is needed. The verifier gets no token,
    # inherited configuration, proxy, stdin or external network route.
    prefix = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=2s", "45s",
              "/usr/bin/unshare", "--net", "/usr/sbin/runuser", "-u", user, "--",
              "/usr/bin/env", "-i", f"HOME={scratch}", f"GH_CONFIG_DIR={scratch}",
              "PATH=/usr/bin:/bin", "GH_HOST=github.com", "GH_PROMPT_DISABLED=1", str(executable)]
    common = ["--bundle", str(scratch / "bundle.jsonl"), "--custom-trusted-root", str(scratch / "root.jsonl"),
              "--repo", "nathanmcnulty/TokenForge", "--signer-workflow", "nathanmcnulty/TokenForge/.github/workflows/ci.yml",
              "--signer-digest", source, "--source-digest", source, "--source-ref", os.environ["GITHUB_REF"],
              "--deny-self-hosted-runners", "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
              "--limit", "1", "--format", "json"]
    results = []
    for name, expected in (("candidate.zip", 0), ("tampered.zip", None)):
        result = subprocess.run(prefix + ["attestation", "verify", str(scratch / name)] + common,
                                env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=50)
        if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 64 * 1024:
            raise ValueError("verifier output bound")
        label = "verification" if expected == 0 else "tampered-verification"
        (directory / (label + ".json")).write_bytes(result.stdout)
        (directory / (label + ".log")).write_bytes(result.stderr)
        if (expected == 0 and result.returncode != 0) or (expected is None and result.returncode != 1):
            raise ValueError("signature verification outcome mismatch")
        results.append({"Archive": name, "ActualExitCode": result.returncode})
    report = {"Synthetic": True, "OfflineNetworkNamespace": True, "CredentialFreeVerifier": True,
              "VerifierSha256": VERIFIER_SHA256, "TrustRootSha256": ROOT_SHA256,
              "Checks": results, "ProductionApprovalEstablished": False}
    (directory / "verification-checks.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    print(json.dumps(verify(sys.argv[1], sys.argv[2])))
