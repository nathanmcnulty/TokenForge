# Catalog downloads

These are immutable snapshots of the public application catalog. Download a `.json.gz` file and decompress it with a standard gzip tool. The JSON retains the catalog schema, all attributes, sources, dates, and history.

The filename identifies the source Git blob. Its adjacent manifest records the source commit, catalog date, application count, byte sizes, and SHA-256 hashes. `ContentSha256` covers the decompressed compact JSON; `CompressedSha256` covers the downloaded gzip file.

The first snapshot contains 5,455 applications and is about 1.8 MB compressed, compared with 31.9 MB for the readable source. It was validated against every value in that source.

Snapshots are generated explicitly; they are not a rolling latest download. Inspect `CatalogUpdatedAt` and `SourceCommit`, or use the [current readable catalog](../applications.json). Public metadata and scope observations do not establish complete token-flow coverage or universal consent.
