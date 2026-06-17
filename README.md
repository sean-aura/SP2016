# SharePoint 2016 Security Posture Audit Toolkit

Read-only PowerShell scripts to audit a SharePoint **2016 on-premises** farm
from a security standpoint. Each writes a CSV. Built on the native
`Microsoft.SharePoint.PowerShell` snap-in (server-side object model).

> **Code style & runtime.** All ten scripts are inline-commented to the same standard.
> Script 1 is laid out line-by-line as the readable reference; scripts 2–10 keep their
> compact one-line-per-block layout but carry explanatory comments above each non-obvious
> block — the shared helpers (`Write-Log`, `Initialize-SPSnapin`), the read-only
> `Start-SPAssignment`/`Stop-SPAssignment` object-lifetime handling, and the logic
> specific to each audit. The scripts target the **SharePoint 2016 Management Shell
> (Windows PowerShell 5)**; they use `[PSCustomObject]`/`[ordered]` and so are not
> intended to run under a literal PowerShell 2.0 engine.

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
- **RSAT ActiveDirectory module** for the AD-aware parts (6, 7 `-ValidateAgainstAD`, 8) — all three also support a no-install `-NoRSAT` fallback, see below.
- Run off-hours; cap big scans with `-ItemScanLimitPerList`.

## Scripts

| # | Script | Covers | Needs |
|---|--------|--------|-------|
| 1 | `1-Audit-Permissions.ps1` | RBAC at web/list/**folder**/item; flags broken inheritance and AD groups | site admin |
| 2 | `2-Audit-BroadAndAnonymousAccess.ps1` | Anonymous / "Everyone" / broad grants / access requests | site admin |
| 3 | `3-Audit-VersioningAndDraftSecurity.ps1` | Draft/minor-version visibility, approval, item read/write security | site admin |
| 4 | `4-Audit-Configuration.ps1` | Web-app/site config: auth, anonymous, TLS, policies, BrowserFileHandling, lockdown, user solutions, auditing | **farm admin** |
| 5 | `5-Scan-DataClassificationKeywords.ps1` | Restricted/Confidential content; regex (SSN/card), recycle bin, stale flag | site admin (+Search for `-UseSearch`) |
| 6 | `6-Expand-ADGroups.ps1` | Recursively expands AD groups from script 1's CSV; flags disabled members | RSAT AD, or `-NoRSAT` (no SharePoint) |
| 7 | `7-Audit-IdentityHygiene.ps1` | SP group self-join/owner risks; orphaned/disabled principals | site admin (+RSAT or `-NoRSAT` for `-ValidateAgainstAD`) |
| 8 | `8-Get-EffectiveAccess.ps1` | What ONE user can actually reach (assigned vs effective) | site admin + RSAT AD, or `-NoRSAT` |
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
| `-Keywords <string[]>` | NZ PSR 2022 classification labels + PII/credential terms (see script header) | Override keyword list entirely — pass your own array to replace the defaults |
| `-ScanColumnValues` | off | Scan all non-hidden column values (slower) |
| `-DataPatterns` | off | Add SSN and card-number regex matching |
| `-IncludeRecycleBin` | off | Include per-web recycle bin |
| `-StaleDays <n>` | 730 | Flag items not modified in n days |
| `-ItemScanLimitPerList <n>` | 0 (unlimited) | Cap item scan per list |
| `-UseSearch` | off | Full-text search via the Search service (needs a crawl; results are paged automatically) |

The default keyword list covers the complete **NZ Government Security Classification System (PSR 2022)**:

| Category | Keywords |
|----------|----------|
| Policy/privacy classifications | `IN-CONFIDENCE`, `SENSITIVE` |
| National security classifications | `RESTRICTED`, `CONFIDENTIAL`, `SECRET`, `TOP SECRET` |
| Endorsement markings | `NZEO`, `NEW ZEALAND EYES ONLY`, `ACCOUNTABLE MATERIAL`, `CABINET`, `BUDGET`, `APPOINTMENTS`, `HONOURS`, `LEGAL PRIVILEGE`, `EMBARGOED`, `EMBARGOED FOR RELEASE`, `COMMERCIAL`, `EVALUATIVE`, `MEDICAL`, `STAFF`, `REL TO`, `RELEASABLE TO` |
| PII / privacy / regulatory | `PII`, `Personal Information`, `Privacy Act`, `Health Information`, `Medical Record`, `NDA`, `Commercial In Confidence` |
| Credentials / security | `Password`, `Credential`, `Secret Key`, `API Key` |
| Retained legacy terms | `Internal Only`, `HIPAA`, `PCI`, `SSN` |

Source: [NZ PSR Classification System](https://www.protectivesecurity.govt.nz/classification/overview) (protectivesecurity.govt.nz, 2022 policy).

### Script 6 — Expand AD Groups
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-InputCsv <path>` | **required** | CSV from script 1/2 containing AD-group rows to expand |
| `-OutputCsv <path>` | `.\SP_AD_Expanded.csv` | Output file |
| `-NoRSAT` | off | Use ADSI (`[adsisearcher]`) instead of the RSAT ActiveDirectory module — no module install required |

### Script 7 — Identity Hygiene
| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-ValidateAgainstAD` | off | Cross-check principals against AD to flag orphaned/disabled accounts |
| `-NoRSAT` | off | When `-ValidateAgainstAD` is set, use ADSI instead of the RSAT module — no install required |
| `-GroupCsv <path>` | `.\SP_GroupHygiene.csv` | SP group self-join/owner findings output file |
| `-PrincipalCsv <path>` | `.\SP_PrincipalHygiene.csv` | Orphaned/disabled principal findings output file |

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

## Before you run

**Check execution policy first**
Scripts will fail silently or with a cryptic error if execution policy blocks them. In an elevated SharePoint 2016 Management Shell:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
```

**Run script 4 before script 9**
Script 4 reports the site's `AuditFlags`. If that comes back as `None`, script 9's output will be empty for the entire historical window — there is nothing to retroactively recover. Check auditing is enabled and allow at least one audit cycle before running script 9.

**Script 6 depends on what script 1 captured**
Script 6 expands AD groups found in script 1's CSV. If script 1 was run without `-IncludeFolders` or `-IncludeItems`, any AD group with access only at folder or item level will not appear in the CSV and script 6 will not expand it. Run script 1 with the broadest scope your time budget allows before handing off to script 6.

**No RSAT? Scripts 6, 7, and 8 all have a fallback — no `net use` workaround needed**
If `RSAT-AD-PowerShell` cannot be installed (locked-down server, no admin rights to add Windows Features, no WSUS/internet path to the feature), add `-NoRSAT` to any of the three AD-aware scripts:
```powershell
.\6-Expand-ADGroups.ps1     -InputCsv .\SP_RBAC_Audit.csv -NoRSAT -Verbose
.\7-Audit-IdentityHygiene.ps1 -SiteUrl https://sharepoint.contoso.com -ValidateAgainstAD -NoRSAT -Verbose
.\8-Get-EffectiveAccess.ps1   -SiteUrl https://sharepoint.contoso.com -LoginName "CONTOSO\jdoe" -NoRSAT
```
All three use `[adsisearcher]` (`System.DirectoryServices`), which ships with every Windows install — no module to add. Group membership and reverse (user-to-groups) lookups both use the AD `LDAP_MATCHING_RULE_IN_CHAIN` filter (OID `1.2.840.113556.1.4.1941`), the same mechanism `Get-ADGroupMember -Recursive` / `Get-ADAccountAuthorizationGroup` use internally, so results are equivalent. `net use` is unrelated — it maps drives/network shares, not AD group membership, and `net group`/`net group /domain` only return direct members (no nested-group expansion), so neither is a substitute. `-NoRSAT` is the correct workaround.
One difference worth knowing: `-NoRSAT` mode resolves `DisplayName`/`SamAccountName`/`Enabled`/group-membership directly from the LDAP query, so it doesn't need RSAT's follow-up `Get-ADUser`/`Get-ADGroup` calls — output columns are identical, just populated by a different path.

**How these scripts authenticate — there's no password prompt**
None of the ten scripts accept a `-Credential` parameter or call `Get-Credential`. They all connect using **Windows Integrated Authentication of whatever account is already running the PowerShell session** — the same identity you used to log into the farm server (or RDP session) and open the SharePoint 2016 Management Shell. SharePoint's snap-in (`Microsoft.SharePoint.PowerShell`) and AD's RSAT/ADSI calls both ride on that same Kerberos/NTLM ticket; there's no separate sign-in step and no password is ever typed into or stored by these scripts. Practically this means: run the SharePoint Management Shell "as Administrator" using an account that already has the access level the script needs (site admin for most, farm admin for scripts 4 and 10, and an AD-readable account for scripts 6, 7, and 8) — log in as that account first, then launch PowerShell from that same session.

**Script 8 is an approximation**
It resolves the target account's group memberships via a global catalog query at the time of the run. Access granted through claim providers other than Windows claims will not be reflected. Treat the output as "likely access" and verify manually for any custom claim provider environments.

**Item scan defaults are unlimited**
Scripts 1, 5, and 8 default to scanning every item in every list (`-ItemScanLimitPerList 0`). On large document libraries this can run for hours and consume significant memory. For a first run on an unknown farm use `-ItemScanLimitPerList 5000` as a safe starting point, then remove the cap once you know the volume.

**The output CSVs are sensitive**
The combined output of scripts 1, 2, 5, and 8 is a complete map of where sensitive data lives and who can reach it. Treat the files like credentials: encrypt at rest, do not transmit unprotected, and delete them when the audit is complete.

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
| Script 6 `Could not expand` warnings | RSAT not installed, or group is in a different domain/trust | Install `RSAT-AD-PowerShell`, or run with `-NoRSAT` (no install needed); check forest trust if cross-domain |
| Script 8 misses AD-group-based access | RSAT module missing | Install `RSAT-AD-PowerShell` on the farm server, or run with `-NoRSAT` (no install needed) |
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

**Claims and identity**
- `IsDomainGroup` (scripts 1, 7) is set by the Windows claims provider. Custom claim providers may not populate it, so AD group detection can be incomplete in non-standard auth configurations.
- Claim-string matching in `$broadPatterns` / `$skip` / `$idset` (scripts 2, 7, 8) targets Windows claims format (`i:0#.w|`, `c:0(.s|true`, etc.). Add patterns for any custom trusted identity providers in your environment.
- Script 8 computes effective access from the user's resolved principal set; it approximates the platform's claims evaluation — verify results for environments using custom claim providers.
- `-ExpandGroups` in script 1 expands SP group members one level only (uses `SPGroup.Users`). Nested SP groups within a SP group are not recursively expanded. AD groups within SP groups are handled by script 6 (`-Recursive`).

**Anonymous access detection (script 2)**
- `ListAnonymousMask` checks `AnonymousPermMask64 & ViewListItems`, not "mask is non-empty." Every list carries `AnonymousSearchAccessWebLists` by default purely for search-crawl scoping, with no content access granted — checking for a non-empty mask alone would flag this finding on essentially every list in the farm. The current check only fires when anonymous users can actually view content.
- `AllowEveryoneViewItems` (separate finding, `ListAnonymous`) is unrelated to the site-level anonymous setting: it only affects direct-URL access to documents/attachments and works even for authenticated users browsing straight to a file link, bypassing the normal list view permission check. Treat the two findings independently.

**Feature GUIDs**
- The `ViewFormPagesLockDown` GUID (`7c637b23-06c4-472d-9a9a-7c175762c5c4`) in script 4 is the standard SP2016 value (Scope=Site, confirmed against the SP2016 feature manifest). Verify on your farm: `Get-SPFeature -Site <url> | Where-Object { $_.DisplayName -like '*Lockdown*' }`. If the feature has a different GUID in your farm's feature store (e.g. from a non-standard deployment), update the GUID in `4-Audit-Configuration.ps1`.

**Data pattern matching (script 5)**
- Keywords are matched with boundary anchoring, not plain substring search: `STAFF`, `BUDGET`, `SECRET`, `MEDICAL`, `COMMERCIAL`, and similar common-word fragments will match `Top_Secret_Plan.docx` or `budget-2025.xlsx` (boundary = underscore/hyphen/space/start/end) but will not false-positive on `Staffing_Plan.docx`, `secretary_notes.docx`, or `medicalert.pdf`. If you supply your own `-Keywords`, the same boundary rule applies automatically. This only affects the metadata-scan path; `-UseSearch` sends keywords to SharePoint's Search service as a KQL query, which already does word-based matching and was never affected.
- SSN regex (`\d{3}-\d{2}-\d{4}`) and card-number regex (13–16 digits with optional separators) match on file names and metadata only, not file contents — use `-UseSearch` for content-level scanning.
- Both patterns can produce false positives: the SSN pattern matches any NNN-NN-NNNN number (dates, phone extensions, item codes); the card pattern is intentionally broad and has no Luhn validation.
- `-UseSearch` pages through all Search results automatically, but `TotalRows` from the Search service may be capped at a round number (500 or 1000) by the Results Provider. The script logs a warning if this is detected. For exhaustive coverage use the metadata scan (without `-UseSearch`).

**Configuration and hardening**
- SharePoint Designer settings and TLS/cipher (Schannel) hardening are not reliably accessible via the SP object model — review those in Central Admin and IIS Manager / Registry directly.
- Script 9 (`GetEntries`) loads the entire date-range result set into memory before filtering. On busy farms with auditing heavily enabled and `-IncludeViews`, this can be large. Use `-Days` to narrow the window and `-MaxEntries` as a hard cap.

**General**
- All scripts produce point-in-time snapshots. Re-run and diff against a baseline (see Drift Detection section) to catch changes.

## Reference scripts
- SharePoint Diary — SharePoint 2013/2016 Site Collection Permission Report:
  https://www.sharepointdiary.com/2016/02/sharepoint-site-collection-permission-report-powershell-script.html
- SharePoint Diary — Users & Groups Security Report by Permission Levels:
  https://www.sharepointdiary.com/2013/03/users-and-groups-report-based-on-permission-levels.html
- `PowershellScripts/SharePointOnline-ScriptSamples` (SP Server 2013-2016 items):
  https://github.com/PowershellScripts/SharePointOnline-ScriptSamples
