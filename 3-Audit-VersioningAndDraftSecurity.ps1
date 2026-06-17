<#
==============================================================================
 3-Audit-VersioningAndDraftSecurity.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: only property reads. Writes nothing to SharePoint.

 PURPOSE  Settings that change who can see/edit content across versions:
 draft visibility, content approval, item read/write security, IRM, plus
 version retention limits and force-checkout.

 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript.

 USAGE
   .\3-Audit-VersioningAndDraftSecurity.ps1 -SiteUrl https://sharepoint.contoso.com -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string]$OutputCsv = ".\SP_Versioning_Audit.csv",
    [string]$LogFile
)

# ErrorActionPreference=Continue: a failed read on one list is logged and skipped
# rather than aborting the whole run. $script:Errors tallies those non-fatal skips.
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

$results = New-Object System.Collections.Generic.List[object]
$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    # Start/Stop-SPAssignment bracket the SPSite/SPWeb objects opened below so their
    # unmanaged memory is released deterministically at the end. This is object-lifetime
    # (memory) management only - it makes no change to SharePoint content or configuration.
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop
    $webs=$site.AllWebs; $total=$webs.Count; Write-Log "Found $total web(s)."; $i=0
    foreach ($web in $webs){
        $i++
        try {
            Write-Progress -Activity "Versioning audit" -Status $web.Url -PercentComplete (($i/$total)*100)
            Write-Log "Web $i/$total : $($web.Url)" VERBOSE
            foreach ($list in $web.Lists){
                if ($list.Hidden){continue}
                try {
                    # DraftLeakRisk: minor (draft) versions are enabled AND draft visibility is
                    # 'Reader', meaning any reader can see unapproved/in-progress drafts - the
                    # common "private edits are actually public" misconfiguration. The row below
                    # captures every versioning/approval/item-security setting that governs who
                    # can see or edit content across its version history, one row per list.
                    $draftLeak = ($list.EnableMinorVersions -and "$($list.DraftVisibilityType)" -eq 'Reader')
                    $results.Add([PSCustomObject]@{
                        WebUrl=$web.Url; List=$list.Title; Url=$list.RootFolder.ServerRelativeUrl; Type=$list.BaseType
                        VersioningEnabled=$list.EnableVersioning; MajorVersionLimit=$list.MajorVersionLimit
                        MinorVersions=$list.EnableMinorVersions; MinorVersionLimit=$list.MajorWithMinorVersionsLimit
                        ForceCheckout=$list.ForceCheckout; DraftVisibility=$list.DraftVisibilityType
                        ContentApproval=$list.EnableModeration; ReadSecurity=$list.ReadSecurity
                        WriteSecurity=$list.WriteSecurity; IRM_Enabled=$list.IrmEnabled
                        HasUniquePerms=$list.HasUniqueRoleAssignments; DraftLeakRisk=$draftLeak
                    })
                } catch { Write-Log "List error '$($list.Title)': $($_.Exception.Message)" WARN }
            }
        }
        catch { Write-Log "Web error '$($web.Url)': $($_.Exception.Message)" WARN }
        finally { if ($web){$web.Dispose()} }
    }
    Write-Progress -Activity "Versioning audit" -Completed
    $results | Sort-Object WebUrl, List | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($results.Count) lists -> $OutputCsv" OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
