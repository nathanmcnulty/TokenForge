# Import a local Sentinel sign-in aggregate

This importer uses a local aggregate file and the two catalog partitions from a pinned local Git commit. It has no Azure Monitor, Sentinel, Kusto, Microsoft Graph, or authentication entry point. Start with the [synthetic aggregate fixture](../tests/fixtures/sentinel-signin/aggregate.json).

```bash
python3 -B scripts/Import-TokenForgeSentinelSignInAggregate.py \
  --catalog-repo /path/to/discovery-data-checkout \
  --catalog-commit FULL_DATA_COMMIT \
  tests/fixtures/sentinel-signin/aggregate.json
```

## Source columns and field meaning

Use only the columns listed below. Each table has its own aggregate and its own input state.

| Azure Monitor table | Client application | Observed resource identifiers |
| --- | --- | --- |
| [SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) | `AppId` | `ResourceId`, `ResourceIdentity`, `ResourceServicePrincipalId` |
| [AADNonInteractiveUserSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs) | `AppId` | `ResourceIdentity`, `ResourceServicePrincipalId` |
| [AADServicePrincipalSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) | `AppId` | `ResourceIdentity`, `ResourceServicePrincipalId` |
| [AADManagedIdentitySignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs) | `AppId` | `ResourceIdentity`, `ResourceServicePrincipalId` |

Only an actual `AppId` can become a client application candidate. A resource GUID can be shown with an exact match to a catalog AppId for review. The original table and column labels remain in the report, and an exact match does not establish identity equivalence. `ResourceServicePrincipalId` is a service principal object identifier and is not compared to AppIds. The JWT audience remains unknown for every field.

## Aggregate file contract

The input declares `Format: TokenForgeSentinelSignInAggregate`, `SchemaVersion: 1`, and a half-open `TimeGenerated` interval with whole-second UTC `Since` and `UntilExclusive` values. For each table, supply at most one object with `Table`, `State` and `Rows`. Each row has exactly `Field`, a canonical lowercase nonzero GUID `Identifier`, and a positive integer `Count`. Supply a count of matching table records per field and GUID. Omit null or non-GUID values. Counts across fields and tables may describe the same events. The importer preserves counts per table and field and does not add them into a total event count.

The v1 interval uses the workspace arrival basis. Microsoft Entra documents `CreatedDateTime` as the sign-in occurrence time and `TimeGenerated` as when the workspace received and published the entry. A delayed entry can land in a later arrival window even though the sign-in occurred earlier. Do not supply occurrence-filtered counts under this format or treat an empty arrival window as a gap-free occurrence window. Any future occurrence report needs its own explicit time basis and must account for late arrivals, retention, and gaps. [Microsoft Entra time field guidance](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-interactive-sign-ins#timegenerated-field)

Use `Supplied` for an aggregate provided for a table, including an empty aggregate. Use `Unavailable` with an empty row list for a table with no usable result. Omitted tables appear as `NotProvided`. These describe the input, not workspace availability or query coverage. The output always marks workspace availability, table availability, and retention coverage as unknown.

The importer refuses extra fields, duplicate table or field/identifier rows, unsupported columns, and malformed input without printing a partial report. Keep any future tenant-derived aggregate and report in approved private storage outside Git. Send only the projected identifier counts, never raw log records or user, IP, event, session, or token fields.

## Readiness for future collection

Actual collection must wait until the Azure spend issue is resolved and the owner confirms the query budget, exact trusted workspace and tenant, read authorization, and intended window. Verify which tables are populated for that tenant and window, what retention applies, and whether results are complete or truncated. Validate each table separately. Do not use a permissive union that silently skips unavailable tables. Scope any future collection before projecting or aggregating and account for shared workspace ingestion. Keep that live work separate from this offline importer.

`MicrosoftServicePrincipalSignInLogs` is an optional fifth source for Microsoft application service principal sign-ins. Its schema documents `AppId`, `ResourceIdentity`, and `CreatedDateTime`. The documented `TenantId` identifies the Log Analytics workspace, and the schema does not list `AADTenantId`. Do not use `TenantId` as an Entra tenant filter or treat owner tenant fields as substitutes. The four-table importer leaves this source uncovered. After spend is restored, treat it as uncovered until the owner confirms it is already routed to the intended workspace and can be scoped to the approved tenant. This handoff neither enables routing nor queries that table. [MicrosoftServicePrincipalSignInLogs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftserviceprincipalsigninlogs)
