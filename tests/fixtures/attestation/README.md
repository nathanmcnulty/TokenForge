# Public signed attestation fixtures

These are public upstream test data and public release provenance, not TokenForge account/session data. None of the artifact contents is executed, installed as a Python package or imported by these tests.

`manifest.json` pins GitHub CLI `v2.103.2`, source `4f2cfe92e3499f8581bf39db77e0a1431fa7b55c`, the Linux x64 release archive/executable and the eight data/license files. Source files were retrieved from that exact commit and independently checked against its Git blob IDs. `UPSTREAM-LICENSE` is the CLI project's MIT license covering its published test fixtures.

- `reusable-artifact` and `reusable-bundle.json`: genuine upstream Sigstore Public Good fixture. Source repository is `malancas/attest-demo`; certified reusable signer is in `github/artifact-attestations-workflows`, pinned to a full commit.
- `same-repo-artifact.whl` and `same-repo-bundle.json`: genuine upstream GitHub Sigstore fixture. Certified source/signer repository is `actions/attest-demo`, with workflow URI at `refs/heads/main`. The certificate records its historical visibility as private, but these exact bytes are now published publicly by the upstream CLI test suite.
- `public-good-root.json`: upstream public-good-only root used as an unrelated trust-domain negative for the GitHub fixture.
- `provisioned-root.jsonl`: separately provisioned public Sigstore/GitHub root snapshot from a fresh empty-environment `gh attestation trusted-root`, with hash/time in the manifest. Root metadata was fetched online anonymously before the network-isolated verification phase. TUF metadata replay material is not archived here.
- `cli-release-bundle.json`: public CLI release's user-initiated workflow attestation, retrieved anonymously through the public attestation API, downloaded and Snappy-decoded. It covers 21 release subjects, including the exact Linux x64 archive. No temporary signed download URL is retained in these fixtures.

Signature validity is tested through the real pinned verifier without networking. These are deliberately not accepted as TokenForge production candidates: mutable signer URI, cross-repository sealer and multiple subjects remain outside the unchanged policy. Do not edit a certified field to manufacture a positive production-policy case.

The initial executable trust bootstrap remains the GitHub HTTPS distribution boundary: release API digest, checksum file and executable are not independent trust anchors. Verification of its own signed release provenance is additional consistency/integrity evidence, not an independently reproduced compiler/toolchain proof. Static roots and witnessed signing times do not establish current revocation status or live repository permissions.
