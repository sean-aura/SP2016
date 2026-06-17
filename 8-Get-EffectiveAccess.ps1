<#
==============================================================================
 8-Get-EffectiveAccess.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: Get-* / property reads + read-only AD lookups. EnsureUser is
 deliberately avoided (it would provision a user). Writes nothing.

 PURPOSE  What ONE user can actually reach: resolves their principal set (account
 + transitive AD groups + SharePoint groups + authenticated/Everyone claims) and
 reports every securable (web/list/folder/item) where that set has a grant.
 This is a computed approximation of the platform's claims check - verify custom
 claim providers manually.

 REQUIRES (for AD groups): RSAT ActiveDirectory module, or use -NoRSAT for an
 ADSI-based fallback ([adsisearcher]) that needs no module install.
 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. Item scans
 are paged to avoid loading whole libraries.

 USAGE
   .\8-Get-EffectiveAccess.ps1 -SiteUrl https://sharepoint.contoso.com -LoginName "CONTOSO\jdoe" -Verbose
   .\8-Get-EffectiveAccess.ps1 -SiteUrl https://sharepoint.contoso.com -LoginName "i:0#.w|contoso\jdoe" -IncludeItems
   .\8-Get-EffectiveAccess.ps1 -SiteUrl https://sharepoint.contoso.com -LoginName "CONTOSO\jdoe" -NoRSAT
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [Parameter(Mandatory=$true)] [string]$LoginName,
    [string]$OutputCsv = ".\SP_EffectiveAccess.csv",
    [switch]$IncludeItems,
    [int]$ItemScanLimitPerList = 0,
    [switch]$NoRSAT,
    [string]$LogFile
)

# ErrorActionPreference=Continue: a failed read on one object is logged and skipped
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

# Get-Norm: normalise an identity for comparison - strip any claims prefix (up to '|') and
# lower-case it, so 'i:0#.w|CONTOSO\jdoe' and 'contoso\jdoe' compare equal in the identity set.
function Get-Norm { param([string]$s) if ([string]::IsNullOrEmpty($s)){return ''} if ($s -match '\|'){ $s=$s.Substring($s.IndexOf('|')+1) } return $s.ToLower() }

# No-RSAT equivalent of Get-ADAccountAuthorizationGroup: returns all groups (recursively,
# nested included) that the given sAMAccountName is a transitive member of, via the AD
# LDAP_MATCHING_RULE_IN_CHAIN OID (1.2.840.113556.1.4.1941) - same result, no module install.
function Get-AdsiAuthGroups { param([string]$sam)
    $root=$null; $searchRoot=$null; $userSearcher=$null; $grpSearcher=$null; $grpResults=$null
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $root=[ADSI]'LDAP://RootDSE'; $defaultNC=$root.Properties['defaultNamingContext'][0]
        $searchRoot=[ADSI]"LDAP://$defaultNC"
        $userSearcher=[adsisearcher]"(&(objectCategory=person)(objectClass=user)(sAMAccountName=$sam))"
        $userSearcher.SearchRoot=$searchRoot
        $userSearcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
        $uHit=$userSearcher.FindOne()
        if (-not $uHit){ return $out }
        $userDN=$uHit.Properties['distinguishedname'][0]

        $grpSearcher=[adsisearcher]"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$userDN))"
        $grpSearcher.SearchRoot=$searchRoot
        $grpSearcher.PageSize=1000
        $grpSearcher.PropertiesToLoad.AddRange(@('sAMAccountName','objectSid')) | Out-Null
        $grpResults=$grpSearcher.FindAll()
        foreach ($g in $grpResults){
            $samName = "$($g.Properties['samaccountname'][0])"
            if ($samName){ $out.Add([PSCustomObject]@{SamAccountName=$samName; SID=$null}) }
        }
    } finally {
        if ($grpResults){$grpResults.Dispose()}
        if ($grpSearcher){$grpSearcher.Dispose()}
        if ($userSearcher){$userSearcher.Dispose()}
        if ($searchRoot){$searchRoot.Dispose()}
        if ($root){$root.Dispose()}
    }
    return $out
}

# The effective-access calculation works by building $idset - the full set of identities that
# "are" this user for permission purposes: their own login, their transitive AD groups (resolved
# above), the SharePoint groups they belong to ($spGroupNames), and the broad claims everyone
# carries (authenticated users / Everyone). A grant counts as reaching the user if its principal
# is in that set. This mirrors, but does not replace, the platform's own claims evaluation.
$idset = New-Object System.Collections.Generic.HashSet[string]
$spGroupNames = New-Object System.Collections.Generic.HashSet[string]
$results = New-Object System.Collections.Generic.List[object]

# Test-Match: is this role-assignment member one of the user's identities? SP groups match by
# name (against $spGroupNames); everything else matches by normalised login, by the sam portion
# of DOMAIN\sam, or by display name - against $idset.
function Test-Match { param($member)
    if ($member -is [Microsoft.SharePoint.SPGroup]){ return $spGroupNames.Contains($member.Name.ToLower()) }
    $ln=Get-Norm $member.LoginName
    if ($idset.Contains($ln)){ return $true }
    if ($ln -match '\\' -and $idset.Contains((($ln -split '\\')[-1]))){ return $true }
    if ($idset.Contains(("$($member.Name)").ToLower())){ return $true }
    return $false
}
# Add-Grants: record every real permission level on $Securable held by a principal that matches
# the user. Limited Access / empty bindings are skipped (traversal plumbing, not a real grant).
function Add-Grants { param($Securable,[string]$Scope,[string]$Url,[string]$WebUrl)
    foreach ($ra in $Securable.RoleAssignments){
        $roles=($ra.RoleDefinitionBindings | ForEach-Object {$_.Name}) -join '; '
        if ($roles -eq 'Limited Access' -or [string]::IsNullOrEmpty($roles)){continue}
        if (Test-Match $ra.Member){ $results.Add([PSCustomObject]@{Scope=$Scope;ObjectUrl=$Url;WebUrl=$WebUrl;GrantedVia=$ra.Member.Name;Permissions=$roles}) }
    }
}

$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin

    # Build identifier set: seed it with the user's own login (normalised), the bare sam portion
    # if a DOMAIN\sam form was given, and the broad claims that apply to every authenticated user.
    # The transitive AD groups are then added below (via ADSI or RSAT).
    [void]$idset.Add((Get-Norm $LoginName))
    if ($LoginName -match '\\'){ [void]$idset.Add((($LoginName -split '\\')[-1]).ToLower()) }
    'c:0!.s|windows','authenticated users','c:0(.s|true','everyone' | ForEach-Object { [void]$idset.Add($_) }

    $sam = if ($LoginName -match '\\'){ ($LoginName -split '\\')[-1] } elseif ($LoginName -match '\|'){ ($LoginName.Substring($LoginName.IndexOf('|')+1) -split '\\')[-1] } else { $LoginName }
    if ($NoRSAT) {
        try {
            $g = Get-AdsiAuthGroups -sam $sam
            foreach ($x in $g){ if ($x.SamAccountName){[void]$idset.Add($x.SamAccountName.ToLower())} }
            Write-Log "Resolved $($g.Count) AD group(s) for $sam via ADSI (no RSAT)." VERBOSE
        } catch { Write-Log "ADSI group resolution failed for '$sam': $($_.Exception.Message)" WARN }
    }
    elseif (Get-Module -ListAvailable -Name ActiveDirectory){
        Import-Module ActiveDirectory -ErrorAction Stop
        try {
            $g = Get-ADAccountAuthorizationGroup -Identity $sam -ErrorAction Stop
            foreach ($x in $g){ if ($x.SamAccountName){[void]$idset.Add($x.SamAccountName.ToLower())}; if ($x.SID){[void]$idset.Add($x.SID.Value.ToLower())} }
            Write-Log "Resolved $($g.Count) AD group(s) for $sam." VERBOSE
        } catch { Write-Log "AD group resolution failed for '$sam': $($_.Exception.Message)" WARN }
    } else { Write-Log "ActiveDirectory module not found - AD-group-based access will be missed. Use -NoRSAT for a no-install fallback." WARN }

    # Start/Stop-SPAssignment bracket the SPSite/SPWeb objects opened below so their unmanaged
    # memory is released deterministically at the end. Memory management only - no farm change.
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    # SP groups the user belongs to: record the name of every SharePoint group that lists the
    # target user as a member, so grants made to those groups are recognised as reaching the user.
    $targetNorm=Get-Norm $LoginName
    foreach ($grp in $site.RootWeb.SiteGroups){
        try { foreach ($m in $grp.Users){ if ((Get-Norm $m.LoginName) -eq $targetNorm){ [void]$spGroupNames.Add($grp.Name.ToLower()); break } } } catch {}
    }
    Write-Log "User is in $($spGroupNames.Count) SharePoint group(s)." VERBOSE

    # Walk the whole site: check the web itself, then each non-hidden list/library, and only
    # descend into items/folders that have unique permissions (and only when -IncludeItems is set).
    # Items are paged 2000 at a time so large libraries are not loaded into memory all at once.
    $webs=$site.AllWebs; $total=$webs.Count; Write-Log "Found $total web(s)."; $i=0
    foreach ($web in $webs){
        $i++
        try {
            Write-Progress -Activity "Effective access for $LoginName" -Status $web.Url -PercentComplete (($i/$total)*100)
            Write-Log "Web $i/$total : $($web.Url)" VERBOSE
            Add-Grants -Securable $web -Scope 'Web' -Url $web.Url -WebUrl $web.Url
            foreach ($list in $web.Lists){
                if ($list.Hidden){continue}
                $scope = if ($list.BaseType -eq [Microsoft.SharePoint.SPBaseType]::DocumentLibrary){'Library'}else{'List'}
                try { if ($list.HasUniqueRoleAssignments){ Add-Grants -Securable $list -Scope $scope -Url $list.RootFolder.ServerRelativeUrl -WebUrl $web.Url } }
                catch { Write-Log "List error '$($list.Title)': $($_.Exception.Message)" WARN }
                if ($IncludeItems){
                    try {
                        $q=New-Object Microsoft.SharePoint.SPQuery; $q.ViewAttributes="Scope='RecursiveAll'"; $q.RowLimit=2000
                        $scanned=0; $stop=$false
                        do {
                            $batch=$list.GetItems($q)
                            foreach ($it in $batch){
                                try { if ($it.HasUniqueRoleAssignments){ $label=if ("$($it.FileSystemObjectType)" -eq 'Folder'){"$scope folder"}else{"$scope item"}; Add-Grants -Securable $it -Scope $label -Url ("$($web.Url.TrimEnd('/'))/$($it.Url)") -WebUrl $web.Url } }
                                catch { Write-Log "Item error in '$($list.Title)': $($_.Exception.Message)" WARN }
                                if ($ItemScanLimitPerList -gt 0 -and (++$scanned) -ge $ItemScanLimitPerList){ $stop=$true; break }
                            }
                            if ($stop){ break }
                            $q.ListItemCollectionPosition=$batch.ListItemCollectionPosition
                        } while ($null -ne $q.ListItemCollectionPosition)
                    } catch { Write-Log "Item scan error '$($list.Title)': $($_.Exception.Message)" WARN }
                }
            }
        }
        catch { Write-Log "Web error '$($web.Url)': $($_.Exception.Message)" WARN }
        finally { if ($web){$web.Dispose()} }
    }
    Write-Progress -Activity "Effective access" -Completed
    $results | Sort-Object Scope, ObjectUrl | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "$LoginName has $($results.Count) grant(s) -> $OutputCsv" OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
