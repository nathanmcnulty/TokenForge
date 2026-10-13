# Native releases

Versioned releases provide durable downloads beyond the one-day native CI artifacts. Each release contains the complete self-contained CLI package, its PowerShell adapters, and documentation. Extract the entire archive; some commands still need the bundled files and PowerShell 7.4+. No authentication state, passkeys, cookies, tokens, or tenant research snapshots belong in a release.

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

`SHA256SUMS` and `release-manifest.json` list archive hashes. A hash detects changed bytes only when you trust the expected hash. Each archive and the manifest also have [GitHub build provenance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations). With a current GitHub CLI:

```sh
gh attestation verify TokenForge-VERSION-linux-x64.tar.gz \
  --repo nathanmcnulty/TokenForge \
  --signer-workflow nathanmcnulty/TokenForge/.github/workflows/release.yml \
  --source-digest SOURCE_COMMIT --source-ref refs/heads/main
```

Inspect the verified provenance and compare its source revision with the release's documented source commit. These attestations identify the GitHub workflow and source used for packaging; they do not establish that the code has no vulnerabilities. They are separate from Windows Authenticode and macOS Developer ID signing/notarization, which are not supplied by this workflow. The six matching-architecture core and extracted-package checks are synthetic validation, not six-platform live account authentication.

## Maintaining releases

Run **Release packages** manually on `main`. The default `publish=false` builds, extracts, smoke-tests, and verifies all six packages without creating tags, attestations, or releases. Pull requests changing the release workflow or asset validator run the same read-only packaging route. The verifier transports only the manifest and checksums, avoiding a second copy of the six archives. Temporary release artifacts retain one day; published release assets remain available independently of that retention.

Use `publish=true` only for a new module version. The source must still be the exact current `main` commit after building, and both main-branch validation workflows must have succeeded for that commit, including all nine named platform gates (three PowerShell OS jobs and six native OS/architecture jobs). The builder uses SDK 10.0.401 and locked dependencies. Each architecture runs the shared core checks and launches its extracted executable; the extracted module must import too. The verifier requires exactly six archives and their matching version/source/hash receipts.

Only the publisher receives release-writing, attestation, and OIDC permissions. It does not receive the Nora passkey or checkpoint key. It revalidates the package set, generates and verifies provenance, creates a draft release with the assets, and publishes the draft. Existing exact version tags, releases, and drafts cause failure; the workflow never replaces an existing release or uses asset overwrite. A partial failure may leave a draft/tag for deliberate maintainer recovery. Do not rerun publication expecting it to overwrite that state. Increment the coordinated runtime/module version markers before a new version, as covered by the credential bootstrap checks.

OS signing and notarization remain future work requiring platform identities and separate validation. Building releases does not add macOS Keychain support or remove the remaining PowerShell dependencies.
