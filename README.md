# SharePoint 2016 Security Posture Audit Toolkit

Read-only PowerShell scripts to audit a SharePoint **2016 on-premises** farm
from a security standpoint. Each writes a CSV. Built on the native
`Microsoft.SharePoint.PowerShell` snap-in (server-side object model).

## READ-ONLY — by design
Every script performs **only** `Get-*` cmdlets, property reads, and read-only
methods (`DoesUserHavePermissions`, `SPAudit.GetEntries`, Search `ExecuteQuery`,
recycle-bin enumeration, `Get-AD*`). None of them call `*.Update()`,
`SystemUpdate()`, `EnsureUser`, `AllowUnsafeUpdates`, `Restore/Delete/MoveTo`,
or any `New-/Set-/Remove-/Add-` cmdlet. They write nothing to SharePoint, AD,
SQL, or the farm — output is local CSV only. The Secure Store check lists
target-application *metadata* only and never reads stored credentials.

Belt-and-suspenders option for maximum assurance: run against a farm whose
content databases are set read-only at SQL level, or a restored copy. Not
required given the code is read-only, but reasonable for a formal audit.

## Prerequisites
- Run **on a farm server** in the **SharePoint 2016 Management Shell**.
- Site-collection / shell admin for 1, 2, 3, 5, 7, 8, 9; **farm admin** for 4 and 10.
- **RSAT ActiveDirectory module** for the AD-aware parts (6, 7 `-ValidateAgainstAD`, 8).
- Run off-hours; cap big scans with `-ItemScanLimitPerList`.

## Scripts

| # | Script | Covers | Needs |
|---|--------|--------|-------|
| 1 | `1-Audit-Permissions.ps1` | RBAC at web/list/**folder**/item; flags broken inheritance and AD groups | site admin |
| 2 | `2-Audit-BroadAndAnonymousAccess.ps1` | Anonymous / "Everyone" / broad grants / access requests | site admin |
| 3 | `3-Audit-VersioningAndDraftSecurity.ps1` | Draft/minor-version visibility, approval, item read/write security | site admin |
| 4 | `4-Audit-Configuration.ps1` | Web-app/site config: auth, anonymous, TLS, policies, BrowserFileHandling, lockdown, user solutions, auditing | **farm admin** |
| 5 | `5-Scan-DataClassificationKeywords.ps1` | Restricted/Confidential content; regex (SSN/card), recycle bin, stale flag | site admin (+Search for `-UseSearch`) |
| 6 | `6-Expand-ADGroups.ps1` | Recursively expands AD groups from script 1's CSV; flags disabled members | RSAT AD (no SharePoint) |
| 7 | `7-Audit-IdentityHygiene.ps1` | SP group self-join/owner risks; orphaned/disabled principals | site admin (+RSAT for `-ValidateAgainstAD`) |
| 8 | `8-Get-EffectiveAccess.ps1` | What ONE user can actually reach (assigned vs effective) | site admin + RSAT AD |
| 9 | `9-Export-AuditLogEvents.ps1` | Behavioural audit: permission changes/deletes from the audit log | site admin + auditing enabled |
| 10 | `10-Audit-FarmSecurity.ps1` | Footprint (all web apps/DBs/sites), managed accounts, AV, federation, Secure Store, add-ins | **farm admin** |

## Key parameters

### Common across all scripts
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-Verbose` | off | Per-web/per-list tracing to the console |
| `-LogFile <path>` | off | Full transcript to a file (uses `Start-Transcript`) |

### Script 1 — Permissions
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-IncludeFolders` | off | Scan folders with unique permissions (fast) |
| `-IncludeItems` | off | Scan items with unique permissions (use with caution on large libraries) |
| `-ItemScanLimitPerList <n>` | 0 (unlimited) | Stop item scan after n items per list |
| `-ExpandGroups` | off | Inline-expand SP group members into additional rows |
| `-OutputCsv <path>` | `.\SP_RBAC_Audit.csv` | Output file |

### Script 5 — Data Classification
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-Keywords <string[]>` | 16 built-in terms | Override keyword list |
| `-ScanColumnValues` | off | Scan all non-hidden column values (slower) |
| `-DataPatterns` | off | Add SSN and card-number regex matching |
| `-IncludeRecycleBin` | off | Include per-web recycle bin |
| `-StaleDays <n>` | 730 | Flag items not modified in n days |
| `-ItemScanLimitPerList <n>` | 0 (unlimited) | Cap item scan per list |
| `-UseSearch` | off | Full-text search via the Search service (needs a crawl; results are paged automatically) |

### Script 8 — Effective Access
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-LoginName <string>` | **required** | Account to check (DOMAIN\sam or claim string) |
| `-IncludeItems` | off | Descend into items/folders with unique permissions |
| `-ItemScanLimitPerList <n>` | 0 (unlimited) | Cap per list |

### Script 9 — Audit Log
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-Days <n>` | 90 | How many days back to query |
| `-IncludeViews` | off | Include view/open events (can be very high volume) |
| `-MaxEntries <n>` | 0 (no cap) | Hard cap on entries processed; script warns if the cap is hit — lower `-Days` or raise this value on busy farms |

### Script 10 — Farm Security
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ContextSiteUrl <url>` | CA site | Site used to establish the Secure Store service context |
| `-IncludeAddins` | off | Farm-wide add-in scan (crawls every web — slow) |

## Suggested run order

```powershell
$site = "https://sharepoint.contoso.com"

# Scope first — confirm this site collection is the whole footprint
.\10-Audit-FarmSecurity.ps1

# Core access picture
.\1-Audit-Permissions.ps1                -SiteUrl $site -ExpandGroups -IncludeFolders -Verbose
.\6-Expand-ADGroups.ps1                  -InputCsv .\SP_RBAC_Audit.csv      # turns AD groups into people
.\2-Audit-BroadAndAnonymousAccess.ps1    -SiteUrl $site -Verbose
.\7-Audit-IdentityHygiene.ps1            -SiteUrl $site -ValidateAgainstAD -Verbose

# Configuration + content + behaviour
.\4-Audit-Configuration.ps1              -SiteUrl $site -Verbose
.\3-Audit-VersioningAndDraftSecurity.ps1 -SiteUrl $site -Verbose
.\5-Scan-DataClassificationKeywords.ps1  -SiteUrl $site -ScanColumnValues -DataPatterns -IncludeRecycleBin -Verbose
.\9-Export-AuditLogEvents.ps1            -SiteUrl $site -Days 90 -Verbose

# Spot-check a specific account
.\8-Get-EffectiveAccess.ps1              -SiteUrl $site -LoginName "CONTOSO\jdoe" -IncludeFolders -Verbose
```

For large farms or libraries, add `-LogFile .\run.log` to any script to capture the full transcript, and use `-ItemScanLimitPerList 5000` to cap item scans.

For busy farms, run script 9 with a narrower window first to gauge volume:

```powershell
.\9-Export-AuditLogEvents.ps1 -SiteUrl $site -Days 7 -Verbose
# If entry count is manageable, extend -Days; otherwise use -MaxEntries to cap
.\9-Export-AuditLogEvents.ps1 -SiteUrl $site -Days 90 -MaxEntries 200000
```

## Turning the CSVs into a risk picture
1. **Script 2** = exposure list. Note the `ObjectUrl`s.
2. **Script 5** hits (Restricted/Confidential/SSN/card) that sit in/under a
   Script-2 object = top findings.
3. **Script 1 + 6** explain *who* and expand AD groups to real people; watch
   Full Control and disabled-account grants.
4. **Script 7** catches self-join groups and orphaned/disabled ACEs.
5. **Script 3** catches draft leaks and over-readable "private" lists.
6. **Script 4 + 10** = configuration/farm baseline (filter Script 4 to non-blank `Risk`).
7. **Script 9** shows what was actually done (permission changes, deletes).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `SharePoint snap-in not registered` | Not running in Management Shell | Run from **SharePoint 2016 Management Shell**, not plain PowerShell |
| CSV exported with 0 rows | Wrong scope, no unique perms at chosen level, or a silent filter | Add `-Verbose` to see per-web/list tracing; check the non-fatal error count at the end |
| Script 9 very slow or hangs | Too many audit entries for the date range | Lower `-Days` first; add `-MaxEntries 100000` as a hard cap |
| Script 5 `-UseSearch` returns nothing | Search service not running or content not crawled | Verify the Search Service Application is started and a crawl has run |
| Script 6 `Could not expand` warnings | RSAT not installed, or group is in a different domain/trust | Install `RSAT-AD-PowerShell`; check forest trust if cross-domain |
| Script 8 misses AD-group-based access | RSAT module missing | Install `RSAT-AD-PowerShell` on the farm server |
| `GetEntries failed` | Date range too large for available memory | Use `-Days 30` or narrower; consider running from a server with more RAM |

## Drift detection (baseline + diff)
These are point-in-time snapshots; the real value is re-running and diffing:
```powershell
Compare-Object (Import-Csv .\old\SP_RBAC_Audit.csv) (Import-Csv .\new\SP_RBAC_Audit.csv) `
  -Property SiteUrl,Scope,ObjectUrl,Principal,Permissions
```

## Handle the output securely
The CSVs are a precise map of where sensitive, over-shared data lives and who
can reach it — to an attacker that's a target list. Store and transmit them
accordingly (encrypt at rest, restrict access, delete when done).

## Known approximations / manual follow-ups
- Script 8 computes effective access from the user's resolved principal set; it
  approximates the platform's claims check — verify custom claim providers.
- Claim-string matching (scripts 2, 7, 8) is heuristic; add patterns for any
  custom trusted identity providers.
- SharePoint Designer settings and TLS/cipher (Schannel) hardening are not in
  the SP object model in a reliable way — review those in Central Admin / IIS.
- Regex data-pattern matching (script 5) runs on names/metadata, not file
  contents; use `-UseSearch` for keywords inside documents (needs a crawl).
- Script 5 `-UseSearch` pages automatically through all search results; each
  page is a new `KeywordQuery` call so avoid very broad keyword lists on large
  farms (use the narrowest useful keyword set).

## Reference scripts
- SharePoint Diary — SharePoint 2013/2016 Site Collection Permission Report:
  https://www.sharepointdiary.com/2016/02/sharepoint-site-collection-permission-report-powershell-script.html
- SharePoint Diary — Users & Groups Security Report by Permission Levels:
  https://www.sharepointdiary.com/2013/03/users-and-groups-report-based-on-permission-levels.html
- `PowershellScripts/SharePointOnline-ScriptSamples` (SP Server 2013-2016 items):
  https://github.com/PowershellScripts/SharePointOnline-ScriptSamples
