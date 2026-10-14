# Hosted compute policy

Use local Linux checks by default. Do not compile or test Windows, macOS, or additional architectures unless the user explicitly requests it.

GitHub Actions are intentionally disabled and manual-only to protect the monthly runner budget. Do not enable, dispatch, rerun, or add automatic workflow triggers without a new explicit user instruction to use hosted runners. An existing autonomous goal or general permission to commit, push, merge, or release does not authorize hosted compute.

Commit and push scoped changes after appropriate local checks. Do not require cross-platform hosted gates for routine milestones in this development phase.
