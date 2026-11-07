# PR #128: runtime identity and zero-terminal history correction

This supersedes the runtime-initialization and history-edge qualification in [the original assessment record](administrator-assessment-validation.md). That record and its receipts remain historical; its 206 passes are not relabeled as results for these rebuilt binaries.

## Behavior and operator instruction

Public-health initialization retains all three previously approved executable/DLL pairs and adds only the newly rebuilt whole pair. Disk pins are still checked first. A shared BCL-only guard then verifies an existing loaded assembly before module import and checks again after loading. Direct bundled-module initialization uses the same guard before reuse and after loading.

The guard compares the loaded assembly's name/version, default load context and immutable module version ID against PE metadata, hashes both the expected DLL and the actual loaded-location file, rejects linked/missing/replaced files, and checks that exported TokenForge types resolve to that assembly. Hash and PE metadata come from held read streams; pathname hashes are rechecked to detect replacement of an open inode. Identical copies at different locations are permitted only when their bytes and module identity agree. This is loaded-module/disk identity binding, not cryptographic attestation against hostile code already executing in the process.

If verification fails, **start a fresh PowerShell process and use the complete reviewed package**. Do not try to repair a reused process by replacing its DLL or reimporting another version. Source-only initialization without a bundled DLL retains its existing source-compilation behavior; a source-compiled preload cannot satisfy a bundled-runtime check.

`ProjectHistory` now parses and fully validates supplied or default history before iterating terminal records. A journal with zero terminal records cannot return malformed history unchanged. Omitted history still inherits the validated frozen base; valid explicit history remains supported. Projection does not issue requests or change primary journal bytes.

## Exact package and compilation identities

| Identity | Value |
| --- | --- |
| Reviewed implementation / package source | `b1c43b88872b4227169d2d87b6c0e3137a8e9963` |
| Native and credential compilation source | `121c2b4f45bb345ff0377e761d847ed60b0c5b5d` |
| Linux x64 archive SHA-256 | `d1720aabeab1e568666ea805155a000329bf916a36ab0cc710cc894c7b5cc93d` |
| Archive bytes | `33659988` |
| Manifest SHA-256 | `32edd21927266283e1325598e43eb578d7fd5b5319f2c4c4d6389bf464c26cd7` |
| Executable SHA-256 | `21e1f3c5b8005fae99dae2290d9bfdee8a080402c1346175f3ad80712efc79b1` |
| Credential DLL SHA-256 | `14a12d434306eace18ca14195ef682c92ea9c79e7ceb3b16f0c0707c4006c789` |
| Original build receipt SHA-256 | `e7797481034c393b597fbfec563d33e7f64cece2db16d19a7aafd39ed1cfc4ed` |
| Source-overlay receipt SHA-256 | `0f4ff6504f51bd2f3eb190a668a797a947300a98503bb838599e58526106eea4` |

Both binaries were rebuilt locally for Linux x64 using the existing SDK 10.0.401 and previously locked/restored assets, with `-NoRestore`. No install/download fallback or hosted compute was used. Restore inputs are unchanged. The final pin-script overlay changes no compilation input: all 101 complete input hashes agree between compilation and package source. The original 173-file build output/receipt is immutable; the separate derivative stage/receipt changes only the public-health pin script and binds its parent receipt.

An initial package attempt correctly refused the original build staging tree after the pin script changed. Its raw refusal is retained. The corrected explicit overlay passed the existing strict validator; no provenance validator was relaxed and no incompatible older compiled input was carried forward.

The actual archive/extraction contains 187 safe members: 175 regular files, 12 directories, 174 payload entries and 172 source mappings. Every payload hash/size, mapping and compilation input was checked. The credential inventory contains 49 inputs including inherited `native/Directory.Build.props`. Relative to the prior 9c02b2a package, exactly one payload was added (`Core/Assert-CredentialAssembly.ps1`) and none removed. The qualification-document commit is distinct from the archive source and changes no mapped payload or compilation input.

## Focused results

**180 distinct passing cases**, including 23 added regressions and 157 pre-existing cases executed. No full-suite or cross-platform claim. Early source-history six and initial real-assembly twelve overlap the final runs and are not counted again.

| Receipt group | Actual result |
| --- | --- |
| Extracted-payload focused checks | 137 passed: refresh 67, ARM 18, native refresh 3, public health 37, real-assembly process cases 12; zero failures/skips |
| Source/bootstrap checks using the rebuilt pair | 27 passed: credential bootstrap 7 and public-health independent cases 20; zero failures/skips |
| Additional native history and packaging guards | 16 passed: four new actual executable history cases and 12 provenance guards; four unrelated cases not run |

Each of the twelve real-assembly cases runs in a separate fresh PowerShell process using genuine DLLs that both report 0.48.0. Cases cover old-to-new and new-to-old preloads, full source compilation before bundled loading, a fresh valid pair, repeated valid initialization, identical copies and atomic same-location replacement. Both health and direct-module boundaries are covered. Health mismatch cases call the actual fixture entry point and verify zero module-import calls and no output directory. No identity/hash mock supplies those results. The separate synthetic pair tests exercise only the allowlist gate and correctly refuse dummy bytes at real assembly verification.

Six zero-terminal history cases cover malformed JSON/schema, forbidden fields, valid empty history and valid nonempty supplied/frozen history through core and PowerShell boundaries. Four additional cases invoke the rebuilt native `refresh project` command with invalid and valid history; failures produce no history payload and all cases preserve primary journal bytes. Existing nonempty-terminal and frozen-history regressions passed in the 67-case refresh run.

The actual accepted historical-manifest fixture was supplied for the compilation-inventory refusal test. The older 0a17 baseline fixture is unavailable and its separate case was not run; it is not claimed as passed or reused. The test harness adds selected source tests/synthetic fixtures alongside a byte-verified extracted payload; these additions are not archive members.

## Reuse, review and limits

The prior live assessment and its raw receipts remain intact at their original source/package identities. No authentication, tenant request, live write experiment, scheduler, Actions activation, release, merge or issue closure was performed for this correction. Binaries and raw receipts remain local. Existing unaffected historical results remain component evidence, not a new all-green run or live acceptance of the rebuilt pair. Keep #113/#115/#116 open for their outstanding production acceptance.

Independent source review accepted the shared guard and history fix before the build. Final acceptance additionally inspects the actual archive, extracted files, complete build/overlay provenance and real-process test receipts. Linux x64 is the only platform compiled/tested. In-place mutation of memory by hostile same-process code is outside this guard's trust boundary; the same-location regression uses atomic file replacement so the loaded old image remains intact for a reliable identity comparison.
