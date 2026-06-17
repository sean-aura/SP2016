<#
==============================================================================
 9-Export-AuditLogEvents.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: SPAudit.GetEntries() only. Never DeleteEntries/trimming/*.Update().
 Writes nothing.

 PURPOSE  Behavioural audit: permission changes, deletes, (optionally) views.
 PREREQUISITES  Auditing must have been enabled (see script 4 AuditFlags).
 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. Large date
 windows can return a lot of data; narrow -Days or set -MaxEntries if GetEntries
 is slow. GetEntries loads all matching rows into memory before filtering, so on
 busy farms with -IncludeViews use a short -Days window and set -MaxEntries.

 USAGE
   .\9-Export-AuditLogEvents.ps1 -SiteUrl https://sharepoint.contoso.com -Days 90 -Verbose
   .\9-Export-AuditLogEvents.ps1 -SiteUrl https://sharepoint.contoso.com -Days 30 -IncludeViews
   .\9-Export-AuditLogEvents.ps1 -SiteUrl https://sharepoint.contoso.com -Days 7 -MaxEntries 50000
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [int]$Days = 90,
    [switch]$IncludeViews,
    [int]$MaxEntries = 0,           # 0 = no cap; set e.g. 100000 on busy farms to avoid OOM
    [string]$OutputCsv = ".\SP_AuditLogEvents.csv",
    [string]$LogFile
)

# ErrorActionPreference=Continue: a single bad entry is logged and skipped rather than
# aborting the whole run. $script:Errors tallies those non-fatal skips.
$ErrorActionPreference='Continue'; $script:Errors=0; $script:Start=Get-Date
# --- Shared helpers (identical across every script in this toolkit) ---
# Write-Log: timestamped, leveled console output. Level 'ERROR' also increments the
# non-fatal error counter shown in the final summary; 'VERBOSE' prints only with -Verbose.
function Write-Log { param([string]$Message,[ValidateSet('INFO','OK','WARN','ERROR','VERBOSE')][string]$Level='INFO')
    $ts=(Get-Date).ToString('HH:mm:ss')
    switch ($Level){'VERBOSE'{Write-Verbose "[$ts] $Message"}'WARN'{Write-Warning "[$ts] $Message"}'ERROR'{Write-Host "[$ts] ERROR: $Message" -ForegroundColor Red;$script:Errors++}'OK'{Write-Host "[$ts] $Message" -ForegroundColor Green}default{Write-Host "[$ts] $Message" -ForegroundColor Cyan}} }
# Initialize-SPSnapin: makes the SharePoint server-side cmdlets available by loading the
# Microsoft.SharePoint.PowerShell snap-in if it is not already loaded (it is pre-loaded in
# the SharePoint 2016 Management Shell). Loading a snap-in is read-only - it only exposes
# cmdlets to the session, it does not alter the farm.
function Initialize-SPSnapin {
    if (Get-Command Get-SPSite -ErrorAction SilentlyContinue){return}
    if (-not (Get-PSSnapin -Registered -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)){throw "SharePoint snap-in not registered. Run in the SharePoint 2016 Management Shell."}
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop }

# $securityEvents: the SPAuditEventType names treated as security-relevant - group changes,
# role-definition/role-binding changes (including breaking and restoring inheritance), audit-mask
# changes, and destructive content events (delete/undelete/move/copy). Every other event type is
# only reported when -IncludeViews is set (view/open events are very high volume).
$securityEvents=@('SecGroupCreate','SecGroupDelete','SecGroupMemberAdd','SecGroupMemberDel','SecRoleDefCreate','SecRoleDefModify','SecRoleDefDelete','SecRoleDefBreakInherit','SecRoleBindBreakInherit','SecRoleBindInherit','SecRoleBindUpdate','AuditMaskChange','EventsDeleted','Delete','Undelete','Move','Copy')

$results=New-Object System.Collections.Generic.List[object]
$userCache=@{}
$site=$null
# Resolve-AuditUser: audit entries carry a numeric UserId; turn it into a login name via the
# web's SiteUsers, caching results since the same user recurs across many entries. Falls back to
# "(UserID n)" if the account can no longer be resolved (e.g. it was removed from the site).
function Resolve-AuditUser { param($web,$id)
    if ($userCache.ContainsKey($id)){ return $userCache[$id] }
    $name="(UserID $id)"
    try { $name=$web.SiteUsers.GetByID($id).LoginName } catch {}
    $userCache[$id]=$name; return $name
}

try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    # Start/Stop-SPAssignment bracket the SPSite opened below so its unmanaged memory is released
    # deterministically at the end. Memory management only - GetEntries() below is read-only.
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    Write-Log "Auditing flags on site: $($site.Audit.AuditFlags)"
    if ("$($site.Audit.AuditFlags)" -eq 'None'){ Write-Log "AuditFlags=None - the log will likely be empty for this period." WARN }

    Write-Log "Querying audit entries for the last $Days day(s)..."
    # Build a date-bounded audit query. GetEntries() loads all matching rows into memory before
    # this script filters them, so a wide window on a busy farm can be large - hence -Days/-MaxEntries.
    $query=New-Object Microsoft.SharePoint.SPAuditQuery($site)
    $query.SetRangeStart((Get-Date).AddDays(-$Days))
    $query.SetRangeEnd((Get-Date))
    $entries=$null
    try { $entries=$site.Audit.GetEntries($query) }
    catch { throw "GetEntries failed (try a smaller -Days window): $($_.Exception.Message)" }
    if ($null -eq $entries){ throw "GetEntries returned null - audit log may be unavailable on this site." }
    Write-Log "Retrieved $($entries.Count) raw entries; filtering..." VERBOSE
    if ($MaxEntries -gt 0 -and $entries.Count -ge $MaxEntries){
        Write-Log "WARNING: Entry count ($($entries.Count)) has hit -MaxEntries cap ($MaxEntries). Results are TRUNCATED - use a shorter -Days window or raise -MaxEntries." WARN
    }

    $processed=0
    foreach ($e in $entries){
        # Stop once the -MaxEntries cap (if any) is reached. Keep only security events unless
        # -IncludeViews was passed; tag each kept row Security vs Access/Other for easy filtering.
        if ($MaxEntries -gt 0 -and $processed -ge $MaxEntries){ break }
        try {
            $evt="$($e.Event)"
            $isSec=$securityEvents -contains $evt
            if (-not $isSec -and -not $IncludeViews){ continue }
            $processed++
            $results.Add([PSCustomObject]@{
                Occurred=$e.Occurred; Event=$evt; Category=$(if ($isSec){'Security'}else{'Access/Other'})
                User=Resolve-AuditUser $site.RootWeb $e.UserId; ItemType=$e.ItemType; Location=$e.DocLocation
                Machine=$e.MachineName; IPAddress=$e.MachineIp; EventData=("$($e.EventData)" -replace '\s+',' ')
            })
        } catch { Write-Log "Entry parse error: $($_.Exception.Message)" WARN }
    }

    $results | Sort-Object Occurred -Descending | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($results.Count) events (last $Days days) -> $OutputCsv" OK
    if ($results.Count -eq 0){ Write-Log "No matching entries - confirm auditing was enabled for this period." WARN }
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
