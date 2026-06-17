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

$ErrorActionPreference='Continue'; $script:Errors=0; $script:Start=Get-Date
function Write-Log { param([string]$Message,[ValidateSet('INFO','OK','WARN','ERROR','VERBOSE')][string]$Level='INFO')
    $ts=(Get-Date).ToString('HH:mm:ss')
    switch ($Level){'VERBOSE'{Write-Verbose "[$ts] $Message"}'WARN'{Write-Warning "[$ts] $Message"}'ERROR'{Write-Host "[$ts] ERROR: $Message" -ForegroundColor Red;$script:Errors++}'OK'{Write-Host "[$ts] $Message" -ForegroundColor Green}default{Write-Host "[$ts] $Message" -ForegroundColor Cyan}} }
function Initialize-SPSnapin {
    if (Get-Command Get-SPSite -ErrorAction SilentlyContinue){return}
    if (-not (Get-PSSnapin -Registered -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)){throw "SharePoint snap-in not registered. Run in the SharePoint 2016 Management Shell."}
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop }

$securityEvents=@('SecGroupCreate','SecGroupDelete','SecGroupMemberAdd','SecGroupMemberDel','SecRoleDefCreate','SecRoleDefModify','SecRoleDefDelete','SecRoleDefBreakInherit','SecRoleBindBreakInherit','SecRoleBindInherit','SecRoleBindUpdate','AuditMaskChange','EventsDeleted','Delete','Undelete','Move','Copy')

$results=New-Object System.Collections.Generic.List[object]
$userCache=@{}
$site=$null
function Resolve-AuditUser { param($web,$id)
    if ($userCache.ContainsKey($id)){ return $userCache[$id] }
    $name="(UserID $id)"
    try { $name=$web.SiteUsers.GetByID($id).LoginName } catch {}
    $userCache[$id]=$name; return $name
}

try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    Write-Log "Auditing flags on site: $($site.Audit.AuditFlags)"
    if ("$($site.Audit.AuditFlags)" -eq 'None'){ Write-Log "AuditFlags=None - the log will likely be empty for this period." WARN }

    Write-Log "Querying audit entries for the last $Days day(s)..."
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
