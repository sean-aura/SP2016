<#
==============================================================================
 4-Audit-Configuration.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: only Get-* / property reads. Writes nothing.

 PURPOSE  Web-application + site-collection config that affects security, each
 with a Risk note. Farm-service items are in 10-Audit-FarmSecurity.ps1.

 PREREQUISITES  Run as FARM ADMIN.
 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. Each check
 is isolated, so one failing read does not stop the rest.

 USAGE
   .\4-Audit-Configuration.ps1 -SiteUrl https://sharepoint.contoso.com -Verbose
==============================================================================
#>
[CmdletBinding()]
param(
    [string]$WebAppUrl,
    [string]$SiteUrl,
    [string]$OutputCsv = ".\SP_Config_Audit.csv",
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

$findings = New-Object System.Collections.Generic.List[object]
function Add-F { param($Area,$Setting,$Value,$Risk='') $findings.Add([PSCustomObject]@{Area=$Area;Setting=$Setting;Value="$Value";Risk=$Risk}) }
# Run a check in isolation so a missing property never aborts the script
function Invoke-Check { param([scriptblock]$Block,[string]$Name) try { & $Block } catch { Write-Log "Check '$Name' failed: $($_.Exception.Message)" WARN } }

$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin

    Invoke-Check -Name 'Farm' -Block {
        $farm = Get-SPFarm -ErrorAction Stop
        Add-F 'Farm' 'BuildVersion' $farm.BuildVersion 'Compare against the latest SP2016 CU for known CVEs'
    }

    $webApps = if ($WebAppUrl){ Get-SPWebApplication $WebAppUrl -ErrorAction Stop } else { Get-SPWebApplication -ErrorAction Stop }
    foreach ($wa in $webApps){
        $u=$wa.Url
        Write-Log "Web application: $u" VERBOSE
        Invoke-Check -Name "Claims $u" -Block { $c=$wa.UseClaimsAuthentication; Add-F 'WebApp' "ClaimsAuth: $u" $c ($(if (-not $c){'Classic-mode auth deprecated/insecure'}else{''})) }
        Invoke-Check -Name "SSC $u"    -Block { $s=$wa.SelfServiceSiteCreationEnabled; Add-F 'WebApp' "SelfServiceSiteCreation: $u" $s ($(if ($s){'Any user can create site collections'}else{''})) }
        Invoke-Check -Name "BFH $u"    -Block { $b=$wa.BrowserFileHandling; Add-F 'WebApp' "BrowserFileHandling: $u" $b ($(if ("$b" -eq 'Permissive'){'Permissive renders files inline - XSS/script risk; prefer Strict'}else{''})) }
        Invoke-Check -Name "FD $u"     -Block { $t=$wa.FormDigestSettings.Timeout.TotalMinutes; Add-F 'WebApp' "FormDigestTimeout(min): $u" $t ($(if ($t -gt 1440){'Very long form-digest timeout weakens CSRF protection'}else{''})) }
        Invoke-Check -Name "Blocked $u" -Block { Add-F 'WebApp' "BlockedFileExtensions: $u" (($wa.BlockedFileExtensions) -join ',') '' }
        Invoke-Check -Name "Anon $u"   -Block { foreach ($z in $wa.IisSettings.Keys){ $iis=$wa.IisSettings[$z]; Add-F 'WebApp' "Anonymous[$z]: $u" $iis.AllowAnonymous ($(if ($iis.AllowAnonymous){'Anonymous enabled on this zone'}else{''})) } }
        Invoke-Check -Name "TLS $u"    -Block { foreach ($au in $wa.AlternateUrls){ $sch=([uri]$au.IncomingUrl).Scheme; Add-F 'WebApp' "URL[$($au.UrlZone)]: $u" $au.IncomingUrl ($(if ($sch -ne 'https'){'Served over HTTP - credentials/data in clear'}else{''})) } }
        Invoke-Check -Name "Policy $u" -Block { foreach ($p in $wa.Policies){ $r=($p.PolicyRoleBindings | ForEach-Object {$_.Name}) -join ';'; if ($r -match 'Full Control|Full Read'){ Add-F 'WebAppPolicy' "$u" "$($p.DisplayName) [$($p.UserName)] = $r" 'Web-app-wide override - applies to every site collection' } } }
        Invoke-Check -Name "Super $u"  -Block { Add-F 'WebApp' "portalsuperuseraccount: $u" $wa.Properties['portalsuperuseraccount'] ''; Add-F 'WebApp' "portalsuperreaderaccount: $u" $wa.Properties['portalsuperreaderaccount'] '' }
    }

    if ($SiteUrl){
        Write-Log "Site collection: $SiteUrl" VERBOSE
        $site=Get-SPSite $SiteUrl -ErrorAction Stop
        Invoke-Check -Name 'Audit' -Block { $f=$site.Audit.AuditFlags; Add-F 'Site' 'AuditFlags' $f ($(if ("$f" -eq 'None'){'No auditing configured'}else{''})); Add-F 'Site' 'AuditLogTrimmingRetention(days)' $site.Audit.AuditLogTrimmingRetention '' }
        Invoke-Check -Name 'Admins' -Block { Add-F 'Site' 'SiteCollectionAdministrators' (($site.RootWeb.SiteAdministrators | ForEach-Object {$_.LoginName}) -join '; ') 'Confirm every entry is expected' }
        Invoke-Check -Name 'Lockdown' -Block { $on=$null -ne $site.Features[[Guid]'7c637b23-06c4-472d-9a9a-7c175762c5c4']; Add-F 'Site' 'ViewFormPagesLockDown' $on ($(if (-not $on){'Lockdown off - relevant if anonymous access is enabled'}else{''})) }
        Invoke-Check -Name 'UserSolutions' -Block { foreach ($us in (Get-SPUserSolution -Site $site -ErrorAction SilentlyContinue)){ Add-F 'UserSolution' $us.Name "Status=$($us.Status)" 'Sandboxed custom code - review trust/source' } }
        Invoke-Check -Name 'PermLevels' -Block {
            foreach ($rd in $site.RootWeb.RoleDefinitions){
                $bp=$rd.BasePermissions
                $high=($bp -band [Microsoft.SharePoint.SPBasePermissions]::ManagePermissions) -or ($bp -band [Microsoft.SharePoint.SPBasePermissions]::ManageWeb) -or ($bp -band [Microsoft.SharePoint.SPBasePermissions]::AddAndCustomizePages)
                if ($high){ Add-F 'PermissionLevel' $rd.Name $bp.ToString() 'Grants high-impact rights - confirm who holds this level' }
            }
        }
    }

    $findings | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($findings.Count) settings -> $OutputCsv" OK
    Write-Log "Filter to rows where Risk is not blank for the priority list." OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
