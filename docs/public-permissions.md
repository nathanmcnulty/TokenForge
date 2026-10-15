# Public permission definitions

Permission definitions describe what an API exposes. They do not say which clients have consent, which tokens an account can obtain, or whether an API will accept a token.

TokenForge can save Microsoft Graph's [public permission descriptions](https://github.com/microsoftgraph/microsoft-graph-devx-content/tree/master/permissions) as a compact JSON snapshot. This first source covers Graph only. It requires PowerShell 7.4+, no account, native package, TokenForge module, or model quota.

```powershell
./scripts/Save-TokenForgeGraphPermissions.ps1 `
    -OutputPath ./graph-permissions-b9a67f1.json

# A bounded summary, without printing every definition.
./scripts/Get-TokenForgePublicPermission.ps1 -Path ./graph-permissions-b9a67f1.json

# Names are case-sensitive; the same name may exist in both kinds.
./scripts/Get-TokenForgePublicPermission.ps1 -Path ./graph-permissions-b9a67f1.json `
    -Value User.Read -PermissionType Delegated
```

Use `-Id` to find a permission GUID or `-PermissionType Application` to select application definitions. Omitting all filters returns counts and provenance. Definitions preserve the source's IDs, values, enabled/admin flags, allowed member types, nullable descriptions, and omitted fields. In particular, application definitions do not consistently have `isAdmin=true`; TokenForge does not reinterpret this flag as evidence of consent.

The default source is pinned to commit `b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a`. To collect another revision, review its source and pass its full 40-character commit to `-SourceCommit`, using a new output filename. The tool always fetches the same path in Microsoft's public repository. It does not accept a tenant inventory or alternate URL. Unexpected schemas stop collection rather than silently dropping fields.

## Format and publication

Each file describes one resource, identified by `ResourceId`; join that ID to `applications.json` at read time. `Permissions.delegatedScopesList` and `Permissions.applicationScopesList` retain Microsoft's field names and separate identity namespaces. Definitions are sorted by value and ID. Provenance is stored once per snapshot, avoiding repeated source metadata on every permission. No tenant or client-consent record is included.

`Source` records the repository, path, full commit, and SHA-256 of the original downloaded bytes. `RetrievedAt` is the collection time, not the source's modification date or a publisher signature. `Evidence=PublicSourceDefinitions` distinguishes this data from issued-token observations. The pinned default contains 598 delegated definitions and 534 application definitions; this is not a claim of every Graph permission or every Entra resource.

Output is UTF-8 compact JSON, limited to 4 MiB. Downloads use a fixed HTTPS endpoint, no redirects, no cookies or credentials, a 30-second deadline, and a streamed size bound. Reads reject duplicate JSON fields, unknown attributes, malformed types, duplicate IDs/values within a permission kind, invalid text, and linked paths. An output is published atomically from a temporary file and never overwrites an existing path. `-WhatIf` performs no download or write.

Keep immutable snapshots under commit-specific names when publishing. Reproduce them with the importer and compare the raw-source hash; a structurally valid file alone does not authenticate its provenance. Preserve the source's MIT license and attribution alongside redistributed definitions. The existing CI publisher does not generate or stage this new dataset automatically. Additional resource sources and automated publication remain future work.
