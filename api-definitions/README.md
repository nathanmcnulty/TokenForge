# Public API permission definitions

These snapshots describe permissions listed in public sources. They do not establish client consent, token availability, API acceptance, or complete coverage of an API.

| Resource | Source revision | Delegated | Application | Snapshot |
| --- | --- | ---: | ---: | --- |
| Microsoft Graph (`00000003-0000-0000-c000-000000000000`) | `b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a` | 598 | 534 | [Compact JSON](graph/b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a.json) |

The Graph snapshot was collected from Microsoft's [public permission descriptions](https://github.com/microsoftgraph/microsoft-graph-devx-content/blob/b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a/permissions/permissions-descriptions.json). Its raw-source SHA-256 is `0afc5904f4c9e4fc278645532f452ea03032f25b2831a84c1d1cb4da437f366b`; the compact snapshot is 559,348 bytes. Every source field value was independently compared after collection. Source content is redistributed under its [MIT license](graph/LICENSE).

Join `ResourceId` to the application catalog. Delegated and application definitions retain separate identity namespaces, including overlapping names or IDs. Provenance is stored once per file. `RetrievedAt` records collection time, not source modification time or a publisher signature. These are immutable revision snapshots; this directory does not promise the newest source data or definitions for every cataloged application.

Use the importer and offline query tool on TokenForge's `main` branch; see the [public permissions guide](https://github.com/nathanmcnulty/TokenForge/blob/main/docs/public-permissions.md). The existing CI publisher does not generate this dataset automatically.
