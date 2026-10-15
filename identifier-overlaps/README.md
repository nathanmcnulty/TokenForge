# Public identifier overlaps

The [Graph comparison](graph-b9a67f126ee5-catalog-94b4e7dcef8f.json) matches 1,046 of the catalog's 5,455 identifiers to 1,047 public permission definitions: 549 delegated and 498 application permissions. One identifier occurs in both permission kinds.

An overlap identifies a public permission definition. It does not prove application identity, ownership, consent, token support, or that no application uses the same ID. Unmatched identifiers remain unknown. The catalog is retained unchanged.

This immutable report uses catalog Git blob `94b4e7dcef8f7a01cbf9198c8302a593dbfbbd06` and the [Graph definitions pinned to b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a](../api-definitions/graph/b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a.json). Input provenance and compact validated-document hashes are stored once in the report. They are consistency checks, not publisher signatures.

Reproduce it offline with [Compare-TokenForgePermissionIdentifiers.ps1](https://github.com/nathanmcnulty/TokenForge/blob/main/scripts/Compare-TokenForgePermissionIdentifiers.ps1), both input files, and `-IncludeMatches`. See the [usage guide](https://github.com/nathanmcnulty/TokenForge/blob/main/docs/public-permissions.md#compare-identifiers-with-the-application-catalog). No account or model is required. The tool validates the full public catalog, including history, before returning output. Publication is manual and does not advance with later catalog changes.

The file is 140,594 bytes; its SHA-256 is `d3da44ec371cd656525f77874d06f058ad3a06edfaac09572883f6eeeca77556`. Definitions retain the upstream [MIT attribution](../api-definitions/graph/LICENSE).
