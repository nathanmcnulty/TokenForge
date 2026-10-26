# Native releases

The current declared release-candidate scope is **Linux x64 offline only**. A local candidate is not a published release; its exact source, package hashes and completed checks belong in its acceptance receipt. No candidate preparation authorizes Actions, authentication, publication, a PR or a merge. Follow the packaged [operator runbook](goal6-operator-runbook.md) for installation and state lifecycle.

Versioned releases provide durable downloads beyond the one-day native CI artifacts. Each release contains the complete self-contained CLI package, its PowerShell adapters, and documentation. Extract the entire archive; some commands still need the bundled files and PowerShell 7.6+. No authentication state, passkeys, cookies, tokens, or tenant research snapshots belong in a release.

The naming table below also records historical/available build targets. Only Linux x64 is in the current candidate support set.

| Platform | Architecture | Archive |
| --- | --- | --- |
| Windows | x64 | `TokenForge-VERSION-win-x64.zip` |
| Windows | ARM64 | `TokenForge-VERSION-win-arm64.zip` |
| Linux | x64 | `TokenForge-VERSION-linux-x64.tar.gz` |
| Linux | ARM64 | `TokenForge-VERSION-linux-arm64.tar.gz` |
| macOS | Intel | `TokenForge-VERSION-osx-x64.tar.gz` |
| macOS | Apple Silicon | `TokenForge-VERSION-osx-arm64.tar.gz` |

Download from [GitHub Releases](https://github.com/nathanmcnulty/TokenForge/releases). Check the release version and source commit before installing. Unix archives preserve executable permissions. Windows uses ZIP archives. Windows and Linux support the documented OS-backed key stores; macOS currently uses passphrase storage. Native browser profile login, explicit software-passkey profile login and explicit Memory-profile software-passkey token acquisition do not require PowerShell. Passkey enrollment, implicit passkey login and some research commands still use the PowerShell adapters; see [native CLI coverage](native-cli.md).

## Checking a download

`SHA256SUMS` and `release-manifest.json` list archive hashes. A hash detects changed bytes only when you trust the expected hash. An offline local candidate uses its independently reviewed local source/package receipt; it must not claim GitHub provenance that was never created. For an explicitly published release that includes [GitHub build provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), verification can be performed separately with a current GitHub CLI:

```sh
gh attestation verify TokenForge-VERSION-linux-x64.tar.gz \
  --repo nathanmcnulty/TokenForge \
  --signer-workflow nathanmcnulty/TokenForge/.github/workflows/release.yml \
  --source-digest SOURCE_COMMIT --source-ref refs/heads/main
```

Inspect the verified provenance and compare its source revision with the release's documented source commit. These attestations identify the GitHub workflow and source used for packaging; they do not establish that the code has no vulnerabilities. They are separate from Windows Authenticode and macOS Developer ID signing/notarization, which are not supplied by this workflow. Historical matching-architecture reports remain dated evidence. Current Linux x64 candidate checks are synthetic/offline and do not establish live account authentication or support for other platforms.

## Maintaining releases

Hosted Actions are currently disabled at repository level to protect the runner budget. Workflows have no push, pull-request, tag or scheduled triggers. Do not enable or dispatch them without an explicit user instruction. Validation and packaging are Linux x64 only during this development phase; use local checks by default.

After explicit approval to use hosted compute, **Release packages** can run manually on `main`. The default `publish=false` builds, extracts, smoke-tests, and verifies the Linux x64 package without creating tags, attestations, or releases. The verifier transports only the manifest and checksums. Temporary release artifacts retain one day; published release assets remain available independently of that retention.

Use `publish=true` only for a new module version. The source must still be the exact current `main` commit after building, and both main-branch validation workflows must have succeeded for that commit, including both manual Linux gates (`test (ubuntu-latest)` and `native (ubuntu-latest, linux-x64)`). The builders require a Git checkout and Git on PATH, and use SDK 10.0.401 with locked dependencies. Both builders copy module source only from tracked files. The PowerShell module builder also selects tracked manifests and Markdown documentation; the native builder keeps explicit guide, example and operator-script lists, including the bounded status/recovery/candidate dependencies. Developer test runners and CI collection workers are not implied package contents. Untracked credentials, additional local notes and build caches are excluded. Source links, control characters and case-colliding paths fail packaging. This boundary does not sanitize tracked contents; review source and use repo secrets for CI credentials. The Linux job runs the shared core checks and launches its extracted executable; the extracted module must import too. The verifier requires exactly the explicitly selected runtime archive and matching version/source/hash receipt. The validator retains its six-runtime default for verification of historical releases; the current workflow explicitly selects Linux x64.

Only the publisher receives release-writing, attestation, and OIDC permissions. It does not receive the Nora passkey or checkpoint key. It revalidates the package set, generates and verifies provenance, creates a draft release with the assets, and publishes the draft. Existing exact version tags, releases, and drafts cause failure; the workflow never replaces an existing release or uses asset overwrite. A partial failure may leave a draft/tag for deliberate maintainer recovery. Do not rerun publication expecting it to overwrite that state. Increment the coordinated runtime/module version markers before a new version, as covered by the credential bootstrap checks.

OS signing and notarization remain future work requiring platform identities and separate validation. Building releases does not add macOS Keychain support or remove the remaining PowerShell dependencies.
