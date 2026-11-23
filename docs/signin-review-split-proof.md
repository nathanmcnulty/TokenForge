# Synthetic proof of the split-job handoff

The [inert workflow template](../examples/signin-review/handoff-proof.yml) models the candidate handoff using synthetic AppIds and an in-memory issue fixture. Both jobs have only `contents: read` for their SHA-pinned source checkout. The reader and writer request no OIDC or issue access in this synthetic workflow. The executable has no Azure sign-in, Graph request, actual issue transport or artifact upload. No schedule, fork trigger or dispatch input is defined.

The only cross-job value is fixed-size base64 ciphertext wired directly from `needs.collect.outputs.ciphertext` into the writer environment. The surrounding runner may expose that ciphertext in debug logs. The writer independently checks the trusted repository, ref, event, source SHA, exact synthetic workflow path, run and attempt, plus the reviewed catalog pin. It validates both the first synthetic queue update and a second no-new submission without printing IDs or counts. [GitHub job outputs](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idoutputs)

Both jobs verify the SHA-256 of the exact upstream Linux amd64 `age` v1.3.2 archive before using its binary. The native temporary proof identity belongs only to the writer environment. For a separately approved hosted proof, reserve that environment to the literal `main` branch with no tags and bind the approved temporary identity there. Provide only its public recipient to the reader. This branch makes no key or environment changes. End-to-end hosted log visibility still needs verification with synthetic data. [age release](https://github.com/FiloSottile/age/releases/tag/v1.3.2)

Run the offline process-level proof on Linux with Python 3.11 or later, PyYAML, `age` and `age-keygen` on PATH.

```sh
python3 -B tests/SignInSplitJobProof.test.py
```
