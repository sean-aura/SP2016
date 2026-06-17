<#
==============================================================================
 6-Expand-ADGroups.ps1   (read-only)
------------------------------------------------------------------------------
 READ-ONLY: touches SharePoint not at all. Reads a CSV from script 1/2 and
 queries AD with Get-AD* only. Writes nothing.

 PURPOSE  Expand AD security groups in the permission report to their actual
 (transitive/nested) user members, flagging disabled accounts.

 REQUIRES  RSAT ActiveDirectory module.
 TROUBLESHOOTING  -Verbose to see each group resolved; -LogFile for a transcript.
   Large groups (>5000 members) may hit AD's default page size - such groups are
   reported with a note rather than silently truncated.

 USAGE
   .\6-Expand-ADGroups.ps1 -InputCsv .\SP_RBAC_Audit.csv -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputCsv,
    [string]$OutputCsv = ".\SP_AD_Expanded.csv",
    [string]$LogFile
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

$out = New-Object System.Collections.Generic.List[object]
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }

    if (-not (Test-Path $InputCsv)){ throw "Input CSV not found: $InputCsv" }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)){ throw "ActiveDirectory module not found. Install RSAT-AD-PowerShell, then re-run." }
    Import-Module ActiveDirectory -ErrorAction Stop

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
                $grp=Get-ADGroup -Identity $id -ErrorAction Stop
                $members=Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
                Write-Log "Expanded '$($r.Principal)' -> $($members.Count) user(s)" VERBOSE
            } catch {
                Write-Log "Could not expand '$($r.Principal)' ($id): $($_.Exception.Message)" WARN
                $out.Add([PSCustomObject]@{ObjectUrl=$r.ObjectUrl;Scope=$r.Scope;Permissions=$r.Permissions;ADGroup=$r.Principal;Member='';MemberSam='';Enabled='';Note="Could not expand: $($_.Exception.Message)"})
                $cache[$key]=@(); continue
            }
            $cache[$key]=$members
        }
        foreach ($m in $cache[$key]){
            $enabled=$null; $display=$m.Name; $sam=$m.SamAccountName
            try { $u=Get-ADUser -Identity $m.SID -Properties Enabled,DisplayName -ErrorAction Stop; $enabled=$u.Enabled; $display=$u.DisplayName; $sam=$u.SamAccountName } catch {}
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
