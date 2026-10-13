# Discovery source claims

Version 0.41 is in development and has not been released. Discovery and the application
catalog use schema v2 to retain differing published names and owner hints. These claims
describe the sources; they do not establish ownership, consent or authentication support.

## What a refresh records

1. Read the ROADtools scope catalog, Microsoft app-name dataset and EntraScopes resource
   dataset. Each run records source locations and snapshot hashes.
2. Group entries by application ID. Keep the existing selected name and ownership rules:
   the scope catalog's name takes precedence; an ID placeholder can acquire a name from
   another source; the last recognized Microsoft-owner hint remains the selected hint.
3. Project supported public attributes into `SourceClaims`. Each claim identifies its
   `SourceName`, `Location` and `Evidence`. Scope strings retain case; GUIDs use canonical
   text; arrays and claims are sorted and identical values are deduplicated.
4. Compute `MetadataConflicts`. Different nonempty names produce a `Name` conflict;
   different nonempty owner GUIDs produce an `OwnerTenantId` conflict. Missing values and
   application-ID name placeholders do not create contradictions.
5. Update first/last observation dates and the run record. A changed alternative claim
   adds history even when the selected name is unchanged. A date-only refresh updates
   observations without adding a content version.

For example, an application can retain `Name: Example` while its claims name it `Example`
and `Example service`. The conflict lists both strings. It does not choose which source is
correct, change registration eligibility or grant permission to request a token.

The whitelist covers name, owner hint, public-client and family hints, callbacks,
preferred callback, declared grant/resource/scope lists, resource-candidate hint and
identifier URIs. Unknown fields and opaque source objects are excluded. New source
attributes need an explicit schema and validation change. Original field names are
mapped into this common vocabulary rather than storing source objects wholesale.

## Inspect it

```powershell
Update-TokenForgeDiscovery -Path "$state/discovery.json" `
  -MetadataPath "$state/applications.json"

$catalog = Get-TokenForgeApplicationMetadata "$state/applications.json"
$record = $catalog.Applications[$appId].Records['Discovery///']
$record.Attributes.SourceClaims
$record.Attributes.MetadataConflicts
```

Use an existing private `.sqlite` ledger with `-NativeExecutablePath` for source-checkout
module calls. Native packages include the executable and module together:

```sh
tokenforge catalog export --database /private/lab/applications.sqlite --app APPLICATION_GUID --current
```

## Compatibility and boundaries

Readers accept v1/v2 JSON; new writes use v2. Claim-free legacy records retain hashes and
history. Observing new claims can create the first v2 historical transition. Reading v1
does not rewrite it. SQLite upgrades its marker only inside a successful write transaction
after checking every current and historical domain. Invalid input or stored data rolls back
migration and the write together. Existing handles read the marker within each transaction
so another handle's upgrade cannot leave them stale. Older clients reject v2; update the
native executable and module together.

Both readers validate paired canonical claims and recomputed conflicts, including history.
Duplicate JSON keys, unknown nested fields, malformed text, URI userinfo, oversized input
or serialized output, and oversized merged scope sets are rejected. Display names preserve
C1 characters found in historical encoding artifacts; C0/DEL controls remain rejected.
Date-looking text stays text on supported PowerShell versions.

Local labels and paths can be stored in private metadata. Public catalog export and frozen
weekly recipes require approved `https://raw.githubusercontent.com/` source and claim
locations without userinfo, queries or fragments. Public validation checks historical
claims before applying an application/current selection. It rejects rather than redacts.

The catalog remains unencrypted diagnostic metadata. It contains no authentication state
and cannot be an ownership or consent authority. Source hashes establish consistency with
a snapshot, not that its publisher's claims are true. Migrating v1 cannot recover discarded
alternatives; a new source refresh must collect them.

## Validation status

An offline foundation check projected all 5,455 discovery records in a cached public
snapshot with stable canonical round trips. Its SHA-256 is
`83f49938273dc6dd82f4b770e8cad62048db1908c6b1b6ed662c08e387f9328a`.
It fetched no new data and changed no catalog or credentials. Integration tests add
history, literal-text, publication, legacy-hash, migration-rollback and shared-handle checks.
Current public-source, package, hosted-gate and release validation remain pending.
