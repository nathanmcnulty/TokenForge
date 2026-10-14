# Hosted compute policy

Use local Linux checks by default. Do not compile or test Windows, macOS, or additional architectures unless the user explicitly requests it.

GitHub Actions are intentionally disabled and manual-only to protect the monthly runner budget. Do not enable, dispatch, rerun, or add automatic workflow triggers without a new explicit user instruction to use hosted runners. An existing autonomous goal or general permission to commit, push, merge, or release does not authorize hosted compute.

Commit and push scoped changes after appropriate local checks. Do not require cross-platform hosted gates for routine milestones in this development phase.

# Efficient local work

Use deterministic scripts and structured summaries for routine validation. Select the smallest preset that covers the changed behavior; run a broad suite only when changes or unresolved failures justify it. Reuse successful checks when their inputs and artifacts are unchanged. Do not rebuild or repeat checks just to obtain another green result.

Use Maximum reasoning (`max`) when delegating to Luna. Prefer Luna for bounded mechanical implementation and routine checks with clear inputs and acceptance criteria. Use Sol for security reviews, architectural decisions, and failures that need deeper investigation. Delegate only when authorized by the user or these instructions, and give agents narrow file ownership.

The local validation runner is `scripts/Invoke-TokenForgeLocalValidation.ps1`. It never builds, installs dependencies, dispatches Actions, or performs live authentication. Weekly is a focused report/recipe/bootstrap check; Native is the broader Linux package check; ReleaseGuards checks release validators. Invoke it in a fresh PowerShell process with an existing trusted Linux package when required.
