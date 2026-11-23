# Compare a portal sign-in export with the catalog

In the Microsoft Entra admin center, verify the signed-in account and the exact target directory. Open **Entra ID > Monitoring & health > Sign-in logs**. The preview offers standard Interactive, Non-interactive, Application (service principal), and Managed Identity downloads, plus two separate authentication-details downloads. Use only standard CSV downloads. The adapter accepts one category and one declared interval per file. Microsoft documents UTC timestamps, CSV and JSON options, and a limit of 100,000 sign-in records per file. [Microsoft Entra log downloads](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs)

The Date filter offers **Last 24 hours**, **Last 7 days**, **Last 1 month**, and **Custom time interval** in the observed portal. These are filter choices. Available history depends on retention and licensing. Use custom adjacent intervals with explicit UTC bounds. Confirm the time zone of the filter before converting its bounds to UTC. The export panel says downloads follow the current filters. Avoid filters on users, apps, or outcomes for a tenant-wide inventory. Make sure the operator records which category and interval each export covers. [Sign-in log filters](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-customize-filter-logs) · [Entra retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)

## Keep source files private

1. Use an approved local Parrot browser session. Prepare an access-restricted directory outside Git, sync, shared folders, and the default Downloads location. Verify the browser can save directly there before starting an export. Prefer a dedicated browser profile configured to ask where to save. Cancel if the browser would write to an unapproved location.
2. Start with one short Interactive interval. Download only its standard CSV. Wait for the portal and browser to finish. Record the category, requested UTC bounds, and whether the portal reported success, failure, or no clear status. Keep those safe facts only. A completed browser download alone does not prove the service exported the full interval.
3. Read the file in place with the command below. Store stdout in approved private storage and keep the raw file only as long as required by the applicable retention policy. Skip authentication-details downloads and keep all real exports and reports out of Git.

```bash
umask 077
python3 -B scripts/Import-TokenForgeEntraSignInCsv.py \
  --catalog-repo /path/to/local/catalog-checkout \
  --catalog-commit FULL_PUBLISHED_DATA_COMMIT \
  --since 2026-01-05T00:00:00Z --until 2026-01-06T00:00:00Z \
  --export-kind InteractiveUser --export-status NotRecorded \
  /private/path/window.csv > /private/path/window.aggregate.json
```

Select `NonInteractiveUser`, `ServicePrincipal`, or `ManagedIdentity` for the other standard exports. The input contract is English UTF-8 CSV, with optional BOM and unambiguous `Date (UTC)`, `Application ID`, and `Resource ID` headers. Header whitespace and case are ignored. UTC dates must be ISO formatted. A file lacking one of those fields is refused. There is no fallback from a service principal object ID to an application ID. The downloaded file schema, status transitions and field availability for each category still need to be checked using the controlled workflow. The adapter has been tested with synthetic data only.

## Read coverage and counts

The output shows pending Application IDs absent from both pinned catalog partitions, and independently aggregates the separately labeled Resource IDs. Resource matching is exact GUID equality only. The JWT audience is unknown, and sign-in outcome is not evaluated. Counts are CSV rows per ID. A grouped row may represent multiple sign-ins. The adapter does not retain user, IP, request, session, or token columns, or associate an application with a resource at the row level.

Exit code 0 means the local CSV was parsed with no detected input issue. Exit code 2 emits an aggregate with incomplete reasons when the file reaches 100,000 rows, has invalid or out-of-window values, or the operator recorded an incomplete export. Exit code 1 refuses the file or catalog and emits no report. Exact upper-bound rows are skipped to preserve half-open intervals. A below-cap or empty file, successful download, or valid UTC interval leaves provider coverage unknown. [Entra download limits and caveats](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reports-faq)

For a retained-window inventory, track each interval and category separately. Replace a capped, failed, or interrupted interval with smaller disjoint exports. Mark unavailable categories and unconfirmed intervals explicitly. Use one report per category and interval. Union pending Application IDs across reports for discovery, and avoid summing overlapping exports. Keep category and interval receipts with the private aggregates.
