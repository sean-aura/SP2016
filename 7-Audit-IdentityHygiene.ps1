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
 error isolation.

 USAGE
   .\7-Audit-IdentityHygiene.ps1 -SiteUrl https://sharepoint.contoso.com -ValidateAgainstAD -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string]$GroupCsv     = ".\SP_GroupHygiene.csv",
    [string]$PrincipalCsv = ".\SP_PrincipalHygiene.csv",
    [switch]$ValidateAgainstAD,
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

$skip=@('c:0(.s|true','c:0!.s|windows','c:0-.f|','nt authority','sharepoint\system','spdataaccess','app@sharepoint')
function Test-SkipPrincipal { param([string]$login) $l=("$login").ToLower(); foreach ($p in $skip){ if ($l.Contains($p)){return $true} }; return $false }
function Resolve-Identity { param([string]$login)
    $s=$login; if ($s -match '\|'){ $s=$s.Substring($s.IndexOf('|')+1) }
    if ($s -match '^s-1-'){ return $s }; if ($s -match '\\'){ return ($s -split '\\')[-1] }; return $s }
function Get-AdStatus { param([string]$id)
    # Returns: ACTIVE / DISABLED / ORPHANED   (read-only)
    try { $u=Get-ADUser -Identity $id -Properties Enabled -ErrorAction Stop; return $(if ($u.Enabled){'ACTIVE'}else{'DISABLED'}) } catch {}
    try { $g=Get-ADGroup -Identity $id -ErrorAction Stop; if ($g){ return 'ACTIVE' } } catch {}
    return 'ORPHANED'
}

$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin

    $adOk=$false
    if ($ValidateAgainstAD){
        if (Get-Module -ListAvailable -Name ActiveDirectory){ Import-Module ActiveDirectory -ErrorAction Stop; $adOk=$true; Write-Log "ActiveDirectory module loaded." }
        else { Write-Log "ActiveDirectory module not found - skipping AD validation." WARN }
    }

    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    # ---- (A) Group hygiene ----
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
    $prinRows=New-Object System.Collections.Generic.List[object]
    $users=$site.RootWeb.SiteUsers; $tot=$users.Count; $n=0
    foreach ($u in $users){
        $n++
        Write-Progress -Activity "Principal hygiene" -Status $u.LoginName -PercentComplete (($n/[math]::Max($tot,1))*100)
        try {
            $status='NotChecked'; $enabled=''
            $isDomain = $u.IsDomainGroup -or ($u.LoginName -match '\\' -or $u.LoginName -match '\|')
            if ($adOk -and $isDomain -and -not (Test-SkipPrincipal $u.LoginName)){
                $status=Get-AdStatus (Resolve-Identity $u.LoginName)
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
