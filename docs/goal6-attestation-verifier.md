# Goal 6 pinned offline attestation verifier

GitHub CLI `2.103.2` is installed privately at `.cache/goal6-attestation/installed/gh-v2.103.2/gh` in the isolated implementation workspace. The system `/bin/gh` remains `2.46.0`; no PATH/profile or system package change was made. Use the exact installed path, not ambient `gh`. No production policy, sealer, workflow, privilege or publication connection was provisioned.

## Exact pin and provisioning

| Input | Revision or SHA256 |
|---|---|
| CLI source | `4f2cfe92e3499f8581bf39db77e0a1431fa7b55c`, tag `v2.103.2` |
| Linux x64 archive | `62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8` |
| Official checksum file | `414d6009dc7f9f936d70831af818d1a32aa0ff07a77646861efd207356a36b2d` |
| Installed executable | `cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e` |
| Provisioned root snapshot | `65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c` |

The [fixture manifest](../tests/fixtures/attestation/manifest.json) pins the release URL, archive size/member, all public fixture hashes, source identities and root retrieval time. Download provenance is the [official release](https://github.com/cli/cli/releases/tag/v2.103.2). Archive bytes matched both the release API SHA256 and the separately downloaded official checksum file. Only the expected regular `gh_2.103.2_linux_amd64/bin/gh` member was read from the archive, bounded to 128 MiB, written to a new private directory, rehashed and set to mode `0500`. No archive paths were blindly extracted and nothing existing was overwritten.

For a fresh installation, retrieve the exact archive and checksum file named in the manifest anonymously over HTTPS, verify both hashes and the archive's checksum entry, then extract only that regular member to a new private destination. Recheck the executable hash before use. Do not silently upgrade or substitute another architecture. The accepted archive is retained at `.cache/goal6-attestation/gh_2.103.2_linux_amd64.tar.gz`; the executable is not committed to Git.

Public roots were provisioned online using `gh attestation trusted-root` in a fresh empty HOME/config directory and cleared environment, with no account credential. This uses the pinned CLI's configured TUF trust bootstrap. The resulting Sigstore/GitHub root snapshot is saved and hash-pinned; full TUF metadata replay material is not retained. Root provisioning was distinct from offline verification. Future root refreshes require a new reviewed hash/time; there is no network refresh or download fallback during tests.

Release API metadata, checksums and executable share the GitHub HTTPS distribution trust boundary. The signed release verification below is additional evidence, not an independent binary/compiler bootstrap proof. No reproducible build, current revocation, OCSP/CRL or current repository/owner identity claim is made from these static bundles and roots.

## Real signed offline gates

All verification processes run in a Linux user/network namespace (`unshare -Urn`), with cleared environment, empty private HOME/config and closed stdin. No account credential, ambient GitHub configuration or authentication flow is used. The existing production process helper copies and verifies the executable before execution; direct CLI test cases also use a verified private copy. Test artifacts are hashed only, never executed/imported.

Three genuine signed cases pass with exact repository, signer workflow/commit, source commit/ref, GitHub OIDC issuer and hosted-runner constraints:

| Case | Evidence and limit |
|---|---|
| GitHub Sigstore same-repository upstream fixture | The unchanged adapter's actual process boundary and complete CLI flags succeed. Real certificate fields and witnessed timestamp parse correctly. The stricter production policy rejects its mutable workflow URI. |
| Sigstore Public Good reusable-workflow fixture | Explicit cross-repository signer verification succeeds, including full signer commit and source/run binding. Production policy still rejects the cross-repository sealer. |
| Installed CLI Linux archive | Signed release provenance binds repo ID `212613049` and exact source `4f2cfe92e3499f8581bf39db77e0a1431fa7b55c`; exactly one of 21 subjects matches the pinned archive digest. This is not a single-subject TokenForge candidate. |

Negative cases change artifact bytes, DSSE signature, certificate, signed payload, certificate presence, trust domain, repository, source/ref and signer workflow/commit. Each is refused by the real verifier. Existing synthetic adapter tests retain duplicate-output/missing-timestamp, immutable repository ID, run/attempt, actor/permission and certificate-versus-predicate checks. They remain synthetic policy tests, not signed operational TokenForge evidence.

An initial reusable verification omitted the explicit cross-repository signer and failed closed. An initial same-repository invocation used an incorrect repository name and also failed closed. Correct certificate-derived identities then passed; production rules were not relaxed. The public API returned compressed bundle download locations rather than inline bundles; the saved signed bundle was downloaded anonymously and bounded/Snappy-decoded before verification. No temporary signed download URL is published in evidence.

## Reproduce locally

Use a fresh PowerShell process, the unchanged accepted Linux package and existing pinned archive/executable:

```powershell
pwsh -NoProfile -File scripts/Invoke-TokenForgeLocalValidation.ps1 `
  -Preset Attestation `
  -NativeExecutable .cache/goal6/accepted-package/linux-x64/tokenforge `
  -AttestationVerifierPath .cache/goal6-attestation/installed/gh-v2.103.2/gh `
  -AttestationReleaseArchive .cache/goal6-attestation/gh_2.103.2_linux_amd64.tar.gz `
  -ReportPath <new-report-path>
```

Run the command itself inside `unshare -Urn` for external network isolation; each verifier child is also isolated. The runner installs/downloads/authenticates nothing. Missing or mismatched inputs fail setup/container validation; the Attestation preset cannot silently skip its real verifier cases. Other runner presets clear the external-verifier environment to prevent incidental execution. A broad direct Pester run without an explicit verifier path skips the `ExternalVerifier` group and must not be reported as this gate.

The [acceptance receipt](goal6-attestation-verifier-validation.json) records final results, exact source/package inputs, installation paths, independent review and remaining gates. No native/module/package-builder or publication implementation changed. Existing package/core and writer results are reused as historical proofs, not rerun unchanged. The current verifier/fixtures/tests are source/workspace assets, outside the previously accepted package.

## Remaining Goal 6 gates

The installed tool and real signed-bundle compatibility blocker is resolved for this pin and these fixtures. A same-repository immutable reusable sealer for TokenForge, independently approved operational policy and a genuine single-subject TokenForge candidate remain unprovisioned. None of these upstream fixtures can establish that operational sealing contract. The [writer checkpoint](goal6-publication-writer.md) still needs separately authorized GitHub permission/ruleset, exact-old CAS, publication and lost-ack recovery proof.

No authentication, protected credential access, tenant change, Actions enablement/dispatch, real publication, remote push, PR or merge occurred. Public anonymous downloads/API reads were used only to provision verifier/provenance/root/test inputs. Hosted execution, authentication and publication each retain their separate approval boundaries. Full Goal 6 and production/publication readiness remain incomplete.

Primary references: [offline verification and certificate semantics](https://cli.github.com/manual/gh_attestation_verify), [root provisioning](https://cli.github.com/manual/gh_attestation_trusted-root), [pinned upstream source](https://github.com/cli/cli/tree/4f2cfe92e3499f8581bf39db77e0a1431fa7b55c/pkg/cmd/attestation).
