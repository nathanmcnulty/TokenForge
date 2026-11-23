# Catalog downloads

These are immutable snapshots of the public application catalog. Download a `.json.gz` file and decompress it with a standard gzip tool. The JSON retains the catalog schema, all attributes, sources, dates, and history.

The filename identifies the source Git blob. Its adjacent manifest records the source commit, catalog date, application count, byte sizes, and SHA-256 hashes. `ContentSha256` covers the decompressed compact JSON; `CompressedSha256` covers the downloaded gzip file.

The first snapshot contains 5,455 applications and is about 1.8 MB compressed, compared with 31.9 MB for the readable source. It was validated against every value in that source.

Snapshots are generated explicitly; they are not a rolling latest download. Inspect `CatalogUpdatedAt` and `SourceCommit`, or use the [current readable catalog](../applications.json). Public metadata and scope observations do not establish complete token-flow coverage or universal consent.

## Historical reviewed snapshot

[Download 5470 metadata identifiers](applications-367800fbbec592511415422ec4e3f27ce370ec60.json.gz) · [Manifest](applications-367800fbbec592511415422ec4e3f27ce370ec60.manifest.json) · [Classification changes](applications-367800fbbec592511415422ec4e3f27ce370ec60.changes.md).

The source ledger preserves historical IDs, observations and versions. Fifteen additions retain their actual evidence strength: nine documentation-only and six single-source Graph claims; none is a verified application. Earlier downloads remain immutable.

## Historical reviewed snapshot

[Download](applications-53d3c52efa10287470047158c8d39eeef4fc9b5b.json.gz) · [Manifest](applications-53d3c52efa10287470047158c8d39eeef4fc9b5b.manifest.json) · [Classification changes](applications-53d3c52efa10287470047158c8d39eeef4fc9b5b.changes.md). Public metadata identifiers retain their recorded evidence strength; they are not verified apps.

## Current reviewed snapshot

[Download](applications-97d222338b9e05af7b8dd0c81fe9cab2c1deef96.json.gz) · [Manifest](applications-97d222338b9e05af7b8dd0c81fe9cab2c1deef96.manifest.json) · [Catalog changes](applications-97d222338b9e05af7b8dd0c81fe9cab2c1deef96.changes.md).
