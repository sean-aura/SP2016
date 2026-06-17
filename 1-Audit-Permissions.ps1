<#
==============================================================================
 1-Audit-Permissions.ps1   (SharePoint 2016 on-premises)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: only Get-* / property reads. Never *.Update(), EnsureUser,
 AllowUnsafeUpdates, or any New-/Set-/Remove-/Add- cmdlet. Output = local CSV.

 PURPOSE  WHO has WHAT across web / list-library / FOLDER / item, flagging
 broken inheritance and AD security groups (expand later with script 6).

 TROUBLESHOOTING
   Add -Verbose for per-web/per-list tracing, or -LogFile .\run1.log to capture
   a full transcript. A summary at the end reports rows collected and any
   per-object errors that were skipped (the run continues past them).

 USAGE
   .\1-Audit-Permissions.ps1 -SiteUrl https://sharepoint.contoso.com -Verbose
   .\1-Audit-Permissions.ps1 -SiteUrl https://sharepoint.contoso.com -ExpandGroups -IncludeFolders
   .\1-Audit-Permissions.ps1 -SiteUrl https://sharepoint.contoso.com -IncludeItems -ItemScanLimitPerList 5000 -LogFile .\perm.log
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string]$OutputCsv = ".\SP_RBAC_Audit.csv",
    [switch]$IncludeFolders,
    [switch]$IncludeItems,
    [int]$ItemScanLimitPerList = 0,
    [switch]$ExpandGroups,
    [string]$LogFile
)

$ErrorActionPreference = 'Continue'
$script:Errors = 0
$script:Start  = Get-Date

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','OK','WARN','ERROR','VERBOSE')][string]$Level='INFO')
    $ts = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'VERBOSE' { Write-Verbose "[$ts] $Message" }
        'WARN'    { Write-Warning "[$ts] $Message" }
        'ERROR'   { Write-Host "[$ts] ERROR: $Message" -ForegroundColor Red; $script:Errors++ }
        'OK'      { Write-Host "[$ts] $Message" -ForegroundColor Green }
        default   { Write-Host "[$ts] $Message" -ForegroundColor Cyan }
    }
}
function Initialize-SPSnapin {
    if (Get-Command Get-SPSite -ErrorAction SilentlyContinue) { return }
    if (-not (Get-PSSnapin -Registered -Name Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue)) {
        throw "SharePoint snap-in not registered. Run in the 'SharePoint 2016 Management Shell' on a farm server."
    }
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop
}
function Get-PrincipalType {
    param($member)
    if ($member -is [Microsoft.SharePoint.SPGroup]) { return 'SPGroup' }
    elseif ($member.IsDomainGroup)                   { return 'ADGroup' }
    else                                             { return 'User/Claim' }
}

$results = New-Object System.Collections.Generic.List[object]
function Add-RoleRows {
    param($Securable, [string]$Scope, [string]$ObjectUrl, [string]$SiteCol, [string]$WebUrl)
    if ($Scope -ne 'Web' -and -not $Securable.HasUniqueRoleAssignments) { return }
    foreach ($ra in $Securable.RoleAssignments) {
        $member = $ra.Member
        $roles  = ($ra.RoleDefinitionBindings | ForEach-Object { $_.Name }) -join '; '
        if ([string]::IsNullOrEmpty($roles) -or $roles -eq 'Limited Access') { continue }
        $ptype = Get-PrincipalType $member
        $results.Add([PSCustomObject]@{
            SiteUrl=$SiteCol; WebUrl=$WebUrl; Scope=$Scope; ObjectUrl=$ObjectUrl
            HasUnique=$Securable.HasUniqueRoleAssignments
            Principal=$member.Name; LoginName=$member.LoginName
            PrincipalType=$ptype; IsADGroup=($ptype -eq 'ADGroup'); Permissions=$roles
        })
        if ($ExpandGroups -and $member -is [Microsoft.SharePoint.SPGroup]) {
            foreach ($u in $member.Users) {
                $ut = Get-PrincipalType $u
                $results.Add([PSCustomObject]@{
                    SiteUrl=$SiteCol; WebUrl=$WebUrl; Scope="$Scope (SP group member)"; ObjectUrl=$ObjectUrl
                    HasUnique=$Securable.HasUniqueRoleAssignments
                    Principal="$($member.Name) > $($u.Name)"; LoginName=$u.LoginName
                    PrincipalType=$ut; IsADGroup=($ut -eq 'ADGroup'); Permissions=$roles
                })
            }
        }
    }
}

$site = $null
try {
    if ($LogFile) { try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    Start-SPAssignment -Global | Out-Null

    Write-Log "Opening site collection: $SiteUrl"
    $site = Get-SPSite $SiteUrl -ErrorAction Stop
    $webs = $site.AllWebs
    $total = $webs.Count
    Write-Log "Found $total web(s)."
    $i = 0
    foreach ($web in $webs) {
        $i++
        try {
            Write-Progress -Activity "RBAC audit" -Status "$($web.Url)" -PercentComplete (($i/$total)*100)
            Write-Log "Web $i/$total : $($web.Url)" VERBOSE
            Add-RoleRows -Securable $web -Scope 'Web' -ObjectUrl $web.Url -SiteCol $site.Url -WebUrl $web.Url

            foreach ($list in $web.Lists) {
                if ($list.Hidden) { continue }
                $scope   = if ($list.BaseType -eq [Microsoft.SharePoint.SPBaseType]::DocumentLibrary) { 'Library' } else { 'List' }
                $listUrl = $list.RootFolder.ServerRelativeUrl
                try { Add-RoleRows -Securable $list -Scope $scope -ObjectUrl $listUrl -SiteCol $site.Url -WebUrl $web.Url }
                catch { Write-Log "List perms error '$($list.Title)': $($_.Exception.Message)" WARN }

                if ($IncludeItems) {
                    try {
                        $q = New-Object Microsoft.SharePoint.SPQuery
                        $q.ViewAttributes = "Scope='RecursiveAll'"   # files AND folders, all sub-folders
                        $q.RowLimit = 2000
                        $scanned = 0; $stop = $false
                        do {
                            $batch = $list.GetItems($q)
                            foreach ($it in $batch) {
                                try {
                                    if ($it.HasUniqueRoleAssignments) {
                                        $label = if ("$($it.FileSystemObjectType)" -eq 'Folder') { "$scope folder" } else { "$scope item" }
                                        Add-RoleRows -Securable $it -Scope $label -ObjectUrl ("$($web.Url.TrimEnd('/'))/$($it.Url)") -SiteCol $site.Url -WebUrl $web.Url
                                    }
                                } catch { Write-Log "Item error in '$($list.Title)': $($_.Exception.Message)" WARN }
                                if ($ItemScanLimitPerList -gt 0 -and (++$scanned) -ge $ItemScanLimitPerList) { $stop=$true; break }
                            }
                            if ($stop) { break }
                            $q.ListItemCollectionPosition = $batch.ListItemCollectionPosition
                        } while ($null -ne $q.ListItemCollectionPosition)
                        Write-Log "  '$($list.Title)' scanned (limit $ItemScanLimitPerList)" VERBOSE
                    } catch { Write-Log "Item scan error '$($list.Title)': $($_.Exception.Message)" WARN }
                }
                elseif ($IncludeFolders) {
                    try {
                        foreach ($folder in $list.Folders) {
                            if ($folder.HasUniqueRoleAssignments) {
                                Add-RoleRows -Securable $folder -Scope "$scope folder" -ObjectUrl ("$($web.Url.TrimEnd('/'))/$($folder.Url)") -SiteCol $site.Url -WebUrl $web.Url
                            }
                        }
                    } catch { Write-Log "Folder scan error '$($list.Title)': $($_.Exception.Message)" WARN }
                }
            }
        }
        catch { Write-Log "Web error '$($web.Url)': $($_.Exception.Message)" WARN }
        finally { if ($web) { $web.Dispose() } }
    }
    Write-Progress -Activity "RBAC audit" -Completed

    $results | Sort-Object SiteUrl, Scope, ObjectUrl, Principal | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($results.Count) rows -> $OutputCsv" OK
    Write-Log "Rows where IsADGroup=True can be expanded with 6-Expand-ADGroups.ps1" OK
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" ERROR
    Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR
    Write-Verbose $_.ScriptStackTrace
}
finally {
    if ($site) { try { $site.Dispose() } catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds, $script:Errors)
    if ($LogFile) { try { Stop-Transcript | Out-Null } catch {} }
}
