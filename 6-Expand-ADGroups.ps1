<#
==============================================================================
 6-Expand-ADGroups.ps1   (read-only)
------------------------------------------------------------------------------
 READ-ONLY: touches SharePoint not at all. Reads a CSV from script 1/2 and
 queries AD only via read operations. Writes nothing.

 PURPOSE  Expand AD security groups in the permission report to their actual
 (transitive/nested) user members, flagging disabled accounts.

 TWO MODES
   Default        Uses the RSAT ActiveDirectory module (Get-ADGroup /
                   Get-ADGroupMember -Recursive / Get-ADUser). Most complete
                   output (DisplayName, SamAccountName, Enabled state).
   -NoRSAT        No RSAT install required. Uses [adsisearcher] (System.
                   DirectoryServices, built into .NET/PowerShell) with the AD
                   LDAP_MATCHING_RULE_IN_CHAIN OID (1.2.840.113556.1.4.1941) to
                   resolve nested group membership recursively in a single
                   query - same transitive result as Get-ADGroupMember
                   -Recursive, no module install. Slightly slower per group on
                   very large/deep OUs since AD walks the full chain; for most
                   farm-sized groups the difference is not noticeable.
                   Use this when you cannot install RSAT-AD-PowerShell (locked-
                   down servers, no internet/WSUS path to the feature, no
                   admin rights to add Windows features) but can still run
                   PowerShell as a domain-authenticated user with read access
                   to AD - which is normally the case if you can log into the
                   farm server itself.

 TROUBLESHOOTING  -Verbose to see each group resolved; -LogFile for a transcript.
   Large groups (>5000 members) may hit AD's default page size - such groups are
   reported with a note rather than silently truncated. -NoRSAT mode auto-pages.

 USAGE
   .\6-Expand-ADGroups.ps1 -InputCsv .\SP_RBAC_Audit.csv -Verbose
   .\6-Expand-ADGroups.ps1 -InputCsv .\SP_RBAC_Audit.csv -NoRSAT -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputCsv,
    [string]$OutputCsv = ".\SP_AD_Expanded.csv",
    [string]$LogFile,
    [switch]$NoRSAT
)

$ErrorActionPreference='Continue'; $script:Errors=0; $script:Start=Get-Date
function Write-Log { param([string]$Message,[ValidateSet('INFO','OK','WARN','ERROR','VERBOSE')][string]$Level='INFO')
    $ts=(Get-Date).ToString('HH:mm:ss')
    switch ($Level){'VERBOSE'{Write-Verbose "[$ts] $Message"}'WARN'{Write-Warning "[$ts] $Message"}'ERROR'{Write-Host "[$ts] ERROR: $Message" -ForegroundColor Red;$script:Errors++}'OK'{Write-Host "[$ts] $Message" -ForegroundColor Green}default{Write-Host "[$ts] $Message" -ForegroundColor Cyan}} }

function Resolve-Identity { param([string]$login)
    $s=$login
    if ($s -match '\|'){ $s=$s.Substring($s.IndexOf('|')+1) }
    if ($s -match '^s-1-'){ return $s }
    if ($s -match '\\'){ return ($s -split '\\')[-1] }
    return $s
}

# ---- ADSI (no-RSAT) helpers ----
# Resolve a sAMAccountName to its distinguishedName via the domain's default
# naming context - no RSAT, just System.DirectoryServices (always present).
function Get-AdsiDN { param([string]$sam)
    $root = [ADSI]'LDAP://RootDSE'
    $defaultNC = $root.Properties['defaultNamingContext'][0]
    $searchRoot = [ADSI]"LDAP://$defaultNC"
    $searcher = [adsisearcher]"(&(|(objectCategory=group)(objectCategory=user))(sAMAccountName=$sam))"
    $searcher.SearchRoot = $searchRoot
    $searcher.PropertiesToLoad.AddRange(@('distinguishedName','objectCategory')) | Out-Null
    try {
        $hit = $searcher.FindOne()
        if (-not $hit){ throw "No AD object found for sAMAccountName '$sam'" }
        return $hit.Properties['distinguishedname'][0]
    } finally {
        $searcher.Dispose(); $searchRoot.Dispose(); $root.Dispose()
    }
}

# Recursively-resolved (LDAP_MATCHING_RULE_IN_CHAIN) user members of a group,
# identified by DN. Mirrors Get-ADGroupMember -Recursive without RSAT.
function Get-AdsiGroupMemberRecursive { param([string]$groupDN)
    $root = [ADSI]'LDAP://RootDSE'
    $defaultNC = $root.Properties['defaultNamingContext'][0]
    $searchRoot = [ADSI]"LDAP://$defaultNC"
    $filter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$groupDN))"
    $searcher = [adsisearcher]$filter
    $searcher.SearchRoot = $searchRoot
    $searcher.PageSize = 1000   # auto-pages past AD's default 1000/1500-row cap
    $searcher.PropertiesToLoad.AddRange(@('sAMAccountName','displayName','userAccountControl','objectSid')) | Out-Null
    $members = New-Object System.Collections.Generic.List[object]
    $results = $null
    try {
        $results = $searcher.FindAll()
        foreach ($r in $results){
            $uac = [int]$r.Properties['userAccountControl'][0]
            $disabled = [bool]($uac -band 2)   # ADS_UF_ACCOUNTDISABLE bit
            $members.Add([PSCustomObject]@{
                SamAccountName = "$($r.Properties['samaccountname'][0])"
                DisplayName    = "$($r.Properties['displayname'][0])"
                Enabled        = -not $disabled
            })
        }
    } finally {
        if ($results){ $results.Dispose() }
        $searcher.Dispose(); $searchRoot.Dispose(); $root.Dispose()
    }
    return $members
}

$out = New-Object System.Collections.Generic.List[object]
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }

    if (-not (Test-Path $InputCsv)){ throw "Input CSV not found: $InputCsv" }
    if ($NoRSAT) {
        Write-Log "Running in -NoRSAT mode (ADSI / LDAP_MATCHING_RULE_IN_CHAIN). No module install required." OK
    } else {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)){ throw "ActiveDirectory module not found. Install RSAT-AD-PowerShell, then re-run, or use -NoRSAT for an ADSI-based fallback that needs no install." }
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    $rows = Import-Csv $InputCsv
    $adRows = $rows | Where-Object { $_.IsADGroup -eq 'True' -or $_.PrincipalType -eq 'ADGroup' }
    Write-Log "Found $($adRows.Count) AD-group row(s) to expand."
    if (-not $adRows){ Write-Log "Nothing to expand." OK; return }

    $cache=@{}; $n=0; $tot=$adRows.Count
    foreach ($r in $adRows){
        $n++
        Write-Progress -Activity "Expanding AD groups" -Status $r.Principal -PercentComplete (($n/$tot)*100)
        $key=$r.LoginName
        if (-not $cache.ContainsKey($key)){
            $members=@()
            $id=Resolve-Identity $r.LoginName
            try {
                if ($NoRSAT) {
                    $groupDN = Get-AdsiDN -sam $id
                    $members = Get-AdsiGroupMemberRecursive -groupDN $groupDN
                } else {
                    $grp=Get-ADGroup -Identity $id -ErrorAction Stop
                    $members=Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
                }
                Write-Log "Expanded '$($r.Principal)' -> $($members.Count) user(s)" VERBOSE
            } catch {
                Write-Log "Could not expand '$($r.Principal)' ($id): $($_.Exception.Message)" WARN
                $out.Add([PSCustomObject]@{ObjectUrl=$r.ObjectUrl;Scope=$r.Scope;Permissions=$r.Permissions;ADGroup=$r.Principal;Member='';MemberSam='';Enabled='';Note="Could not expand: $($_.Exception.Message)"})
                $cache[$key]=@(); continue
            }
            $cache[$key]=$members
        }
        foreach ($m in $cache[$key]){
            if ($NoRSAT) {
                # ADSI path already resolved DisplayName/SamAccountName/Enabled directly - no extra lookup needed.
                $enabled=$m.Enabled; $display=$m.DisplayName; $sam=$m.SamAccountName
            } else {
                $enabled=$null; $display=$m.Name; $sam=$m.SamAccountName
                try { $u=Get-ADUser -Identity $m.SID -Properties Enabled,DisplayName -ErrorAction Stop; $enabled=$u.Enabled; $display=$u.DisplayName; $sam=$u.SamAccountName } catch {}
            }
            $out.Add([PSCustomObject]@{ObjectUrl=$r.ObjectUrl;Scope=$r.Scope;Permissions=$r.Permissions;ADGroup=$r.Principal;Member=$display;MemberSam=$sam;Enabled=$enabled;Note=$(if ($enabled -eq $false){'DISABLED account still has access via group'}else{''})})
        }
    }
    Write-Progress -Activity "Expanding AD groups" -Completed
    $out | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    $disabled=($out | Where-Object { $_.Enabled -eq $false }).Count
    Write-Log "Exported $($out.Count) effective grants -> $OutputCsv ($disabled via disabled accounts)" OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
