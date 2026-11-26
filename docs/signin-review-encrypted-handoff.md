# Candidate handoff between separate GitHub jobs

The claim-only workflow is separate from this offline prototype. This branch adds no workflow entry point, key configuration, upload, audit call, or issue update.

## Evidence from the runner

The GitHub runner's output-file handler includes the entire output value in step-debug logging. The job-completion client also passes job output values to the GitHub service. The documented workflow-job REST response does not list outputs. That API shape does not establish confidentiality. Use neither plaintext candidate outputs nor the candidate file as an artifact. [Runner output-file handler](https://github.com/actions/runner/blob/main/src/Runner.Worker/FileCommandManager.cs#L299-L319) · [Runner job completion](https://github.com/actions/runner/blob/main/src/Runner.Worker/JobRunner.cs#L293-L302) · [Workflow jobs API](https://docs.github.com/en/rest/actions/workflow-jobs)

## Proposed boundary

- The reader keeps `contents: read` and `id-token: write`. It receives one approved public `age` X25519 recipient. After complete Graph traversal, it validates the envelope and encrypts it. Emit one fixed-size ciphertext, including for a valid run with zero candidates. Keep the raw envelope and candidate counts out of workflow output and logging.
- Use only ciphertext as the cross-job value. Base64 can carry it in a single job output below GitHub's one-megabyte job output limit, even if debug logging renders it. No candidate artifact is required. The envelope fields, AppIds and counts stay inside the encryption. GitHub still exposes ordinary workflow timing and status. [GitHub job outputs](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idoutputs)
- The writer retains `issues: write` only and receives the decryption identity in a separate environment restricted to literal `main`. Use a dedicated `age` identity. It is separate from Entra credentials. In the prototype it reaches the child process through an anonymous pipe and stays out of arguments, child environment, files and logs. Only the writer decrypts and applies the reviewed exact-issue deduplication before publication. The protected writer derives the expected repository, immutable repository ID, ref, event, source SHA, workflow ref, run and attempt from its own GitHub runner context. Both jobs use the exact reviewed catalog pin `8bdce9ca411c340284c4df76d70924365db6ae14` from source. The writer never takes the expected pin or workflow identity from reader outputs.

The first production run remains reproducible at source commit `d3c588e8744314c800ec93fc650efee1182241af` and catalog commit `d9955781a7130793a5bba178a1b1aa1cf4003439`. [First production run](https://github.com/nathanmcnulty/TokenForge/actions/runs/45298089599)
- `age` supplies confidentiality and ciphertext integrity. The public recipient permits anyone to create a ciphertext. Sender trust must therefore come from the reviewed same-run upstream reader and fixed output binding. Never accept ciphertext from workflow inputs, files supplied by users, other runs, artifacts selected by name across runs, or issue content. Bind the ciphertext only from `needs.collect.outputs` into an environment value or other inert input. Do not interpolate it into shell source. Validate every expected identity field after decryption. Rerun all jobs after a retry so the run attempt matches on both sides. Serialize the writer for the exact reserved issue. Failed validation, failed traversal and missing data stop the issue update.
- The fixed-length frame uses a four-byte length, the validated JSON and zero padding. Use the native `age` implementation from a pinned signed source. Pin and verify the native executable checksum for the chosen installation. Approve both environments, protect main, verify the exact writer and its secret exposure, and run a synthetic two-job proof of artifact-free ciphertext binding and distinct credentials before activating any collector. Do not undo the existing split of Graph access and issue-write access. [age format](https://age-encryption.org/v1)

Local synthetic test on Linux with Python 3.11 or later, `age` and `age-keygen` on PATH.

```sh
python3 -B tests/SignInEncryptedHandoff.test.py
```
