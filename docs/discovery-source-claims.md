# Discovery source claims: implementation in progress

Discovery currently selects a display name and a published owner hint while recording
which sources contributed. Different values from other sources can be lost. The new
shared claim policy preserves normalized, source-attributed values and computes conflicts.
It is a foundation for catalog v2; discovery commands, persistence, migration and public
export have not yet been connected to it. This feature is not released.

For example, two sources naming the same application differently produce two name claims
and a `Name` conflict. Two nonempty, different owner GUIDs produce an `OwnerTenantId`
conflict. A missing value is not a contradiction; an app-ID placeholder is not a competing
name. GUIDs are canonicalized, while names and scope strings retain case. Claims are
sorted and identical claims are deduplicated, independently of input order.

Claims project known public fields only: name, owner hint, public-client and family hints,
callbacks, preferred callback, grant/resource/scope declarations, resource-candidate hint
and identifier URIs. Unknown fields and opaque source objects are excluded. Claim counts,
strings, arrays and parser depth are bounded. Display names preserve C1 characters
found in historical source-encoding artifacts; C0/DEL terminal controls and malformed
UTF-16 remain rejected. Normalization and validation reject unknown
nested fields, duplicate JSON keys, malformed text and credential-bearing URI userinfo.
Serialized output is bounded too, including Unicode escaping. Scope limits apply to
the merged scope set for each resource, so splitting grants cannot bypass the limit.
Source locations also reject queries and fragments. The existing public-export policy
must additionally require approved public source locations for every current and
historical claim; local labels and paths accepted by the policy are not publishable.

These are source claims, not verified ownership, tenant consent or supported-flow proof.
Conflicts do not choose an owner or grant permission. Existing selected-field precedence
will remain explicit during integration. A source claim is not signed or authenticated
by this metadata model.

Observation time belongs to the containing metadata record's first/last dates and run
snapshot, outside the content hash. A timestamp-only refresh should update observations
without adding a history version. A changed alternative claim should add a version even
when the selected display name stays the same.

Catalog v2 integration still requires:

- v1/v2 JSON reading, with existing v1 record hashes and history preserved;
- transactional SQLite format migration, no migration during read-only access, and
  rollback on malformed data or a failed migration;
- strict current and historical claim validation on import and export;
- paired canonical `SourceClaims` and recomputed `MetadataConflicts`, with neither required
  on legacy records that have no claims;
- discovery and weekly publication wiring, bounded real-source validation, and native/
  PowerShell parity checks.

The shared policy is implemented in `DiscoverySourceClaims.cs` and compiled into the
credential library used by both callers. Synthetic checks cover projection, ordering,
conflicts, case-sensitive scopes, bounds, invalid shapes and exclusion of credential fields.

An offline check of the existing published snapshot (SHA-256
`83f49938273dc6dd82f4b770e8cad62048db1908c6b1b6ed662c08e387f9328a`)
projects all 5,455 discovery records and checks canonical round-trip stability. This
checks compatibility with that cached snapshot; it does not fetch new upstream data,
recover discarded alternative claims, or establish ownership or authentication support.
The catalog and credentials are not modified by this check.
