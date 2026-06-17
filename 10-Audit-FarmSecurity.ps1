<#
==============================================================================
 10-Audit-FarmSecurity.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: Get-* / property reads. No GetCredentials, no *.Update(). Writes
 nothing. (Secure Store: target-app metadata only, never stored credentials.)

 PURPOSE  Footprint (all web apps / content DBs / site collections) plus farm
 services: managed accounts, antivirus, outgoing email, federation trusts,
 Secure Store target apps, and (optional) installed add-ins.

 PREREQUISITES  Run as FARM ADMIN.
 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. Every block
 is isolated - a missing/unprovisioned service is reported, not fatal. The
 farm-wide add-in scan is OFF by default (it crawls every web); enable with
 -IncludeAddins.

 USAGE
   .\10-Audit-FarmSecurity.ps1 -Verbose
   .\10-Audit-FarmSecurity.ps1 -IncludeAddins -ContextSiteUrl https://sharepoint.contoso.com
==============================================================================
#>
[CmdletBinding()]
param(
    [string]$OutputCsv = ".\SP_FarmSecurity.csv",
    [string]$ContextSiteUrl,        # content-site URL for the Secure Store service context (recommended)
    [switch]$IncludeAddins,         # farm-wide add-in scan (slow) - off by default
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

$rows=New-Object System.Collections.Generic.List[object]
function Add-R { param($Area,$Name,$Detail,$Risk='') $rows.Add([PSCustomObject]@{Area=$Area;Name=$Name;Detail="$Detail";Risk=$Risk}) }
function Invoke-Block { param([string]$Name,[scriptblock]$Block) Write-Log "Section: $Name" VERBOSE; try { & $Block } catch { Write-Log "Section '$Name' failed: $($_.Exception.Message)" WARN; Add-R $Name 'Error' $_.Exception.Message '' } }

try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    Start-SPAssignment -Global | Out-Null

    Invoke-Block 'Footprint' {
        foreach ($wa in Get-SPWebApplication -ErrorAction Stop){
            $sites=Get-SPSite -WebApplication $wa -Limit All -ErrorAction SilentlyContinue
            Add-R 'Footprint' "WebApp: $($wa.Url)" "SiteCollections=$(@($sites).Count)" 'Confirm all are in audit scope'
            foreach ($cdb in (Get-SPContentDatabase -WebApplication $wa -ErrorAction SilentlyContinue)){ Add-R 'Footprint' "ContentDB: $($cdb.Name)" "Sites=$($cdb.CurrentSiteCount)" '' }
            foreach ($s in $sites){ try { Add-R 'Footprint' "Site: $($s.Url)" "Template=$($s.RootWeb.WebTemplate); Owner=$($s.Owner.LoginName)" '' } catch {} finally { $s.Dispose() } }
        }
    }

    Invoke-Block 'ManagedAccounts' { foreach ($ma in Get-SPManagedAccount -ErrorAction Stop){ Add-R 'ManagedAccount' $ma.UserName "AutoChangePassword=$($ma.AutomaticChange)" '' } }

    Invoke-Block 'Antivirus' {
        $av=[Microsoft.SharePoint.Administration.SPWebService]::ContentService.AntivirusSettings
        Add-R 'Antivirus' 'ScanOnUpload'   $av.UploadScanEnabled   ($(if (-not $av.UploadScanEnabled){'AV scan on upload disabled'}else{''}))
        Add-R 'Antivirus' 'ScanOnDownload' $av.DownloadScanEnabled ($(if (-not $av.DownloadScanEnabled){'AV scan on download disabled'}else{''}))
    }

    Invoke-Block 'OutgoingEmail' {
        foreach ($wa in Get-SPWebApplication -ErrorAction Stop){
            $srv = try { $wa.OutboundMailServiceInstance.Server.Address } catch { '(none)' }
            Add-R 'Email' "OutboundSMTP: $($wa.Url)" "Server=$srv; From=$($wa.OutboundMailSenderAddress)" ''
        }
    }

    Invoke-Block 'Federation' {
        $tip=Get-SPTrustedIdentityTokenIssuer -ErrorAction SilentlyContinue
        if ($tip){ foreach ($t in $tip){ Add-R 'Federation' $t.Name "SignInUrl=$($t.ProviderUri)" 'External trust - confirm expected' } } else { Add-R 'Federation' 'None' 'No trusted identity token issuers' '' }
    }

    Invoke-Block 'SecureStore' {
        $ctxSite=$null
        if ($ContextSiteUrl){ $ctxSite=Get-SPSite $ContextSiteUrl -ErrorAction Stop }
        else {
            $ca=Get-SPWebApplication -IncludeCentralAdministration | Where-Object { $_.IsAdministrationWebApplication } | Select-Object -First 1
            $ctxSite=Get-SPSite ($ca.Sites[0].Url) -ErrorAction Stop
        }
        try {
            $ctx=Get-SPServiceContext $ctxSite -ErrorAction Stop
            $apps=$null
            try { $apps=Get-SPSecureStoreApplication -ServiceContext $ctx -All -ErrorAction Stop }
            catch { $apps=Get-SPSecureStoreApplication -ServiceContext $ctx -ErrorAction Stop }
            foreach ($app in $apps){ Add-R 'SecureStore' $app.TargetApplication.ApplicationId "Type=$($app.TargetApplication.TargetApplicationType)" 'Credential vault entry - confirm who can use it' }
        } finally { if ($ctxSite){ $ctxSite.Dispose() } }
    }

    if ($IncludeAddins){
        Invoke-Block 'Add-ins' {
            foreach ($wa in Get-SPWebApplication -ErrorAction Stop){
                foreach ($s in (Get-SPSite -WebApplication $wa -Limit All -ErrorAction SilentlyContinue)){
                    try { foreach ($w in $s.AllWebs){ try { foreach ($app in (Get-SPAppInstance -Web $w -ErrorAction SilentlyContinue)){ Add-R 'Add-in' $app.Title "Web=$($w.Url); Status=$($app.Status)" 'Confirm add-in source/permissions' } } finally { $w.Dispose() } } }
                    finally { $s.Dispose() }
                }
            }
        }
    } else { Write-Log "Add-in scan skipped (use -IncludeAddins to enable; it crawls every web)." OK }

    $rows | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($rows.Count) rows -> $OutputCsv" OK
    Write-Log "TLS/cipher hardening is an IIS/Schannel concern - review separately." OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
