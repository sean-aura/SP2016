<#
==============================================================================
 7-Audit-IdentityHygiene.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: Get-* / property reads + read-only AD lookups. No EnsureUser,
 no *.Update(). Writes nothing.

 PURPOSE
   (A) SharePoint GROUP hygiene - self-join / members-can-edit / owner risks.
   (B) ORPHANED / DISABLED principals still holding access (needs -ValidateAgainstAD).

 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. AD lookups
 use Get-ADUser/Get-ADGroup -Identity (SID or sAMAccountName) with per-principal
 error isolation. Add -NoRSAT to use ADSI ([adsisearcher]) instead of the RSAT
 ActiveDirectory module for the same lookups - no module install required.

 USAGE
   .\7-Audit-IdentityHygiene.ps1 -SiteUrl https://sharepoint.contoso.com -ValidateAgainstAD -Verbose
   .\7-Audit-IdentityHygiene.ps1 -SiteUrl https://sharepoint.contoso.com -ValidateAgainstAD -NoRSAT -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string]$GroupCsv     = ".\SP_GroupHygiene.csv",
    [string]$PrincipalCsv = ".\SP_PrincipalHygiene.csv",
    [switch]$ValidateAgainstAD,
    [switch]$NoRSAT,
    [string]$LogFile
)

# ErrorActionPreference=Continue: a failed read on one group/principal is logged and skipped
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

# $skip / Test-SkipPrincipal: built-in and service principals (the Everyone/Authenticated
# claims, NT AUTHORITY, SHAREPOINT\system, the search/data-access accounts, the add-in token)
# that are not real directory accounts - skip them so they are never flagged as ORPHANED.
# These fragments target Windows-claims format; extend $skip for custom identity providers.
$skip=@('c:0(.s|true','c:0!.s|windows','c:0-.f|','nt authority','sharepoint\system','spdataaccess','app@sharepoint')
function Test-SkipPrincipal { param([string]$login) $l=("$login").ToLower(); foreach ($p in $skip){ if ($l.Contains($p)){return $true} }; return $false }
# Resolve-Identity: reduce a SharePoint LoginName to the bare identity AD lookups expect
# (strip claims prefix up to '|', pass a raw SID through, take the sam portion of DOMAIN\sam).
function Resolve-Identity { param([string]$login)
    $s=$login; if ($s -match '\|'){ $s=$s.Substring($s.IndexOf('|')+1) }
    if ($s -match '^s-1-'){ return $s }; if ($s -match '\\'){ return ($s -split '\\')[-1] }; return $s }
function Get-AdStatus { param([string]$id)
    # Returns: ACTIVE / DISABLED / ORPHANED   (read-only)
    try { $u=Get-ADUser -Identity $id -Properties Enabled -ErrorAction Stop; return $(if ($u.Enabled){'ACTIVE'}else{'DISABLED'}) } catch {}
    try { $g=Get-ADGroup -Identity $id -ErrorAction Stop; if ($g){ return 'ACTIVE' } } catch {}
    return 'ORPHANED'
}
function Get-AdStatusAdsi { param([string]$id)
    # No-RSAT equivalent of Get-AdStatus, using [adsisearcher] (System.DirectoryServices).
    $root=$null; $searchRoot=$null; $searcher=$null
    try {
        $root=[ADSI]'LDAP://RootDSE'; $defaultNC=$root.Properties['defaultNamingContext'][0]
        $searchRoot=[ADSI]"LDAP://$defaultNC"
        $searcher=[adsisearcher]"(&(|(objectCategory=user)(objectCategory=group))(sAMAccountName=$id))"
        $searcher.SearchRoot=$searchRoot
        $searcher.PropertiesToLoad.AddRange(@('objectCategory','userAccountControl')) | Out-Null
        $hit=$searcher.FindOne()
        if (-not $hit){ return 'ORPHANED' }
        $cat="$($hit.Properties['objectcategory'][0])"
        if ($cat -match '^CN=Group'){ return 'ACTIVE' }   # groups have no disabled state
        $uac=[int]$hit.Properties['useraccountcontrol'][0]
        return $(if ($uac -band 2){'DISABLED'}else{'ACTIVE'})
    } catch { return 'ORPHANED' }
    finally { if ($searcher){$searcher.Dispose()}; if ($searchRoot){$searchRoot.Dispose()}; if ($root){$root.Dispose()} }
}

$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin

    $adOk=$false
    if ($ValidateAgainstAD){
        if ($NoRSAT) { $adOk=$true; Write-Log "Using ADSI ([adsisearcher]) for AD validation - no RSAT module required." }
        elseif (Get-Module -ListAvailable -Name ActiveDirectory){ Import-Module ActiveDirectory -ErrorAction Stop; $adOk=$true; Write-Log "ActiveDirectory module loaded." }
        else { Write-Log "ActiveDirectory module not found - skipping AD validation. Use -NoRSAT for a no-install fallback." WARN }
    }

    # Start/Stop-SPAssignment bracket the SPSite/SPWeb objects opened below so their unmanaged
    # memory is released deterministically at the end. Memory management only - the SP reads and
    # AD lookups in this script are all read-only.
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    # ---- (A) Group hygiene ----
    # For each SharePoint group, flag the membership-control settings that let users add
    # themselves or others without an admin: SELF-JOIN (requests auto-accepted),
    # MEMBERS-CAN-EDIT (members can change the membership), REQUEST-TO-JOIN (join requests on).
    $groupRows=New-Object System.Collections.Generic.List[object]
    foreach ($g in $site.RootWeb.SiteGroups){
        try {
            $risks=@()
            if ($g.AutoAcceptRequestToJoinLeave){ $risks+='SELF-JOIN' }
            if ($g.AllowMembersEditMembership){ $risks+='MEMBERS-CAN-EDIT' }
            if ($g.AllowRequestToJoinLeave){ $risks+='REQUEST-TO-JOIN' }
            $owner = try { $g.Owner.Name } catch { '(unknown)' }
            $groupRows.Add([PSCustomObject]@{Group=$g.Name;Owner=$owner;Members=$g.Users.Count;AutoAccept=$g.AutoAcceptRequestToJoinLeave;MembersCanEdit=$g.AllowMembersEditMembership;RequestToJoin=$g.AllowRequestToJoinLeave;OnlyMembersSeeMembership=$g.OnlyAllowMembersViewMembership;GroupRisk=($risks -join '; ')})
        } catch { Write-Log "Group error '$($g.Name)': $($_.Exception.Message)" WARN }
    }
    $groupRows | Sort-Object GroupRisk -Descending | Export-Csv $GroupCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Group hygiene -> $GroupCsv ($($groupRows.Count) groups)" OK

    # ---- (B) Principal hygiene ----
    # Walk every principal that holds access in the site. With -ValidateAgainstAD (and AD reachable),
    # cross-check each domain principal against AD and classify it ACTIVE / DISABLED / ORPHANED, so
    # disabled or deleted accounts that still carry access are surfaced. Built-in/service principals
    # are skipped (Test-SkipPrincipal); without AD validation the status is left as 'NotChecked'.
    $prinRows=New-Object System.Collections.Generic.List[object]
    $users=$site.RootWeb.SiteUsers; $tot=$users.Count; $n=0
    foreach ($u in $users){
        $n++
        Write-Progress -Activity "Principal hygiene" -Status $u.LoginName -PercentComplete (($n/[math]::Max($tot,1))*100)
        try {
            $status='NotChecked'; $enabled=''
            $isDomain = $u.IsDomainGroup -or ($u.LoginName -match '\\' -or $u.LoginName -match '\|')
            if ($adOk -and $isDomain -and -not (Test-SkipPrincipal $u.LoginName)){
                $status = if ($NoRSAT) { Get-AdStatusAdsi (Resolve-Identity $u.LoginName) } else { Get-AdStatus (Resolve-Identity $u.LoginName) }
                if ($status -eq 'DISABLED'){ $enabled=$false } elseif ($status -eq 'ACTIVE'){ $enabled=$true }
            }
            $prinRows.Add([PSCustomObject]@{Principal=$u.Name;LoginName=$u.LoginName;IsDomainGroup=$u.IsDomainGroup;IsSiteAdmin=$u.IsSiteAdmin;PrincipalStatus=$status;Enabled=$enabled})
        } catch { Write-Log "Principal error '$($u.LoginName)': $($_.Exception.Message)" WARN }
    }
    Write-Progress -Activity "Principal hygiene" -Completed
    $prinRows | Sort-Object PrincipalStatus | Export-Csv $PrincipalCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Principal hygiene -> $PrincipalCsv ($($prinRows.Count) principals)" OK
    if (-not $adOk){ Write-Log "Add -ValidateAgainstAD (RSAT) to detect ORPHANED/DISABLED accounts." OK }
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
