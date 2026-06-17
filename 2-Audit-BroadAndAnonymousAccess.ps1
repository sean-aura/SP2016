<#
==============================================================================
 2-Audit-BroadAndAnonymousAccess.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: only Get-* / property reads. Writes nothing to SharePoint.

 PURPOSE  On-prem "external sharing" exposure: anonymous access, broad claims
 (Everyone / All Authenticated Users), access requests, and unique-perm objects
 carrying any of those.

 TROUBLESHOOTING  -Verbose for tracing, -LogFile to capture a transcript.

 USAGE
   .\2-Audit-BroadAndAnonymousAccess.ps1 -SiteUrl https://sharepoint.contoso.com -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string]$OutputCsv = ".\SP_ExternalAccess_Audit.csv",
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

$broadPatterns = [ordered]@{
    'Everyone'                    = 'c:0(.s|true'
    'All Authenticated (Windows)' = 'c:0!.s|windows'
    'Authenticated Users'         = 'authenticated users'
    'Forms - All Users'           = 'c:0!.s|forms'
    'Everyone except external'    = 'spo-grid-all-users'
    'Domain Users'                = 'domain users'
}
function Get-BroadFlag {
    param([string]$login,[string]$name)
    $l=("$login").ToLower(); $n=("$name").ToLower()
    foreach ($k in $broadPatterns.Keys){ if ($l.Contains($broadPatterns[$k].ToLower()) -or $n.Contains($k.ToLower())){return $k} }
    return $null
}
$results = New-Object System.Collections.Generic.List[object]
function Add-BroadFindings {
    param($Securable,[string]$Scope,[string]$ObjectUrl,[string]$WebUrl)
    foreach ($ra in $Securable.RoleAssignments){
        $m=$ra.Member
        $roles=($ra.RoleDefinitionBindings | ForEach-Object {$_.Name}) -join '; '
        if ($roles -eq 'Limited Access' -or [string]::IsNullOrEmpty($roles)){continue}
        $flag=Get-BroadFlag -login $m.LoginName -name $m.Name
        if ($flag){ $results.Add([PSCustomObject]@{Finding='BroadPrincipal';Detail=$flag;Scope=$Scope;ObjectUrl=$ObjectUrl;WebUrl=$WebUrl;Principal=$m.Name;LoginName=$m.LoginName;Permissions=$roles}) }
    }
}

$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop
    $webs=$site.AllWebs; $total=$webs.Count; Write-Log "Found $total web(s)."; $i=0
    foreach ($web in $webs){
        $i++
        try {
            Write-Progress -Activity "External/anonymous audit" -Status $web.Url -PercentComplete (($i/$total)*100)
            Write-Log "Web $i/$total : $($web.Url)" VERBOSE
            if ("$($web.AnonymousState)" -ne 'Disabled'){
                $results.Add([PSCustomObject]@{Finding='AnonymousAccess';Detail=$web.AnonymousState;Scope='Web';ObjectUrl=$web.Url;WebUrl=$web.Url;Principal='(anonymous)';LoginName='';Permissions="AnonymousState=$($web.AnonymousState)"})
            }
            if (-not [string]::IsNullOrEmpty($web.RequestAccessEmail)){
                $results.Add([PSCustomObject]@{Finding='AccessRequestsEnabled';Detail=$web.RequestAccessEmail;Scope='Web';ObjectUrl=$web.Url;WebUrl=$web.Url;Principal='';LoginName='';Permissions='Access requests routed to this address'})
            }
            Add-BroadFindings -Securable $web -Scope 'Web' -ObjectUrl $web.Url -WebUrl $web.Url
            foreach ($list in $web.Lists){
                if ($list.Hidden){continue}
                try {
                    $lUrl=$list.RootFolder.ServerRelativeUrl
                    if ($list.AllowEveryoneViewItems){
                        $results.Add([PSCustomObject]@{Finding='ListAnonymous';Detail='AllowEveryoneViewItems';Scope='List/Library';ObjectUrl=$lUrl;WebUrl=$web.Url;Principal='(anonymous)';LoginName='';Permissions='Anonymous may view items'})
                    }
                    # Real anonymous content access requires ViewListItems in the mask. A non-empty mask alone is
                    # NOT sufficient: every list carries AnonymousSearchAccessWebLists by default (search-crawl
                    # scoping only, no content access) even when anonymous access was never enabled via the UI.
                    # Checking "-ne EmptyMask" alone would false-positive on essentially every list in the farm.
                    # Source: SPList.AnonymousPermMask64 docs + community confirmation that this flag is present
                    # by default and does not by itself grant content access.
                    if (($list.AnonymousPermMask64 -band [Microsoft.SharePoint.SPBasePermissions]::ViewListItems) -eq [Microsoft.SharePoint.SPBasePermissions]::ViewListItems){
                        $results.Add([PSCustomObject]@{Finding='ListAnonymousMask';Detail=$list.AnonymousPermMask64;Scope='List/Library';ObjectUrl=$lUrl;WebUrl=$web.Url;Principal='(anonymous)';LoginName='';Permissions="AnonymousPermMask64=$($list.AnonymousPermMask64)"})
                    }
                    if ($list.HasUniqueRoleAssignments){ Add-BroadFindings -Securable $list -Scope 'List/Library' -ObjectUrl $lUrl -WebUrl $web.Url }
                } catch { Write-Log "List error '$($list.Title)': $($_.Exception.Message)" WARN }
            }
        }
        catch { Write-Log "Web error '$($web.Url)': $($_.Exception.Message)" WARN }
        finally { if ($web){$web.Dispose()} }
    }
    Write-Progress -Activity "External/anonymous audit" -Completed
    $results | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($results.Count) findings -> $OutputCsv" OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
