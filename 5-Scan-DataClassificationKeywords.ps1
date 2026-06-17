<#
==============================================================================
 5-Scan-DataClassificationKeywords.ps1   (SharePoint 2016)   [READ-ONLY]
------------------------------------------------------------------------------
 READ-ONLY: property reads + read-only Search query + read-only recycle-bin
 enumeration. Never Restore/Delete/*.Update(). Writes nothing.

 PURPOSE  Surface likely Restricted/Confidential content. Matches keywords (and
 optional SSN/card regex) in names + metadata; flags whether each hit has unique
 permissions and whether it is stale; can scan the recycle bin; -UseSearch does
 full-text inside documents via the Search service.

 TROUBLESHOOTING  -Verbose for tracing, -LogFile for a transcript. Item scans
 are paged (2000/batch) to avoid loading whole libraries into memory.

 USAGE
   .\5-Scan-DataClassificationKeywords.ps1 -SiteUrl https://sharepoint.contoso.com -ScanColumnValues -DataPatterns -IncludeRecycleBin -Verbose
   .\5-Scan-DataClassificationKeywords.ps1 -SiteUrl https://sharepoint.contoso.com -UseSearch
==============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$SiteUrl,
    [string[]]$Keywords = @('Restricted','Confidential','Secret','Top Secret','Classified',
                            'Sensitive','Protected','PII','Internal Only','NDA','Privileged',
                            'HIPAA','PCI','SSN','Password','Credential'),
    [string]$OutputCsv = ".\SP_Classification_Scan.csv",
    [switch]$ScanColumnValues,
    [switch]$DataPatterns,
    [switch]$IncludeRecycleBin,
    [int]$StaleDays = 730,
    [int]$ItemScanLimitPerList = 0,
    [switch]$UseSearch,
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

$kwPattern = ($Keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'
$dataRegex = @{ 'SSN' = '\b\d{3}-\d{2}-\d{4}\b'; 'CardNumber' = '\b(?:\d[ -]?){13,16}\b' }
function Get-PatternHits { param([string]$text)
    $hits=@()
    if ($text -and $text -match $kwPattern){ $hits += 'keyword' }
    if ($DataPatterns -and $text){ foreach ($k in $dataRegex.Keys){ if ($text -match $dataRegex[$k]){ $hits += $k } } }
    return $hits
}

$results = New-Object System.Collections.Generic.List[object]
$site=$null
try {
    if ($LogFile){ try { Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null } catch { Write-Log "Transcript off: $($_.Exception.Message)" WARN } }
    Initialize-SPSnapin
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    if ($UseSearch){
        Write-Log "Running full-text Search query (paged)..."
        try {
            $queryText=($Keywords | ForEach-Object { '"'+$_+'"' }) -join ' OR '
            $exec=New-Object Microsoft.Office.Server.Search.Query.SearchExecutor
            $pageSize=500; $startRow=0; $totalRows=[int]::MaxValue
            do {
                $kq=New-Object Microsoft.Office.Server.Search.Query.KeywordQuery($site)
                $kq.QueryText=$queryText; $kq.RowLimit=$pageSize; $kq.StartRow=$startRow; $kq.TrimDuplicates=$false
                'Title','Path','Author','LastModifiedTime' | ForEach-Object { [void]$kq.SelectProperties.Add($_) }
                $rel=$exec.ExecuteQuery($kq).Item([Microsoft.Office.Server.Search.Query.ResultType]::RelevantResults)
                if ($startRow -eq 0){ $totalRows=[int]$rel.TotalRows; Write-Log "Search: $totalRows total result(s)." VERBOSE }
                foreach ($row in $rel.Table.Rows){
                    $results.Add([PSCustomObject]@{Source='Search';List='';ItemUrl=$row['Path'];Title=$row['Title'];LastModified=$row['LastModifiedTime'];Stale='';UniquePerms='';Matches="full-text: $queryText"})
                }
                $startRow+=$pageSize
            } while ($startRow -lt $totalRows)
        } catch { Write-Log "Search query failed (is the Search service running/crawled?): $($_.Exception.Message)" WARN }
    }
    else {
        $webs=$site.AllWebs; $total=$webs.Count; Write-Log "Found $total web(s)."; $i=0
        foreach ($web in $webs){
            $i++
            try {
                Write-Progress -Activity "Classification scan" -Status $web.Url -PercentComplete (($i/$total)*100)
                Write-Log "Web $i/$total : $($web.Url)" VERBOSE
                foreach ($list in $web.Lists){
                    if ($list.Hidden){continue}
                    try {
                        $q=New-Object Microsoft.SharePoint.SPQuery
                        $q.ViewAttributes="Scope='RecursiveAll'"
                        $q.RowLimit=2000
                        $scanned=0; $stop=$false
                        do {
                            $batch=$list.GetItems($q)
                            foreach ($item in $batch){
                                try {
                                    $hits=@(); $hits += (Get-PatternHits $item.Name) | ForEach-Object { "Name:$_" }
                                    if ($ScanColumnValues){
                                        foreach ($f in $item.Fields){
                                            if ($f.Hidden -or $f.ReadOnlyField){continue}
                                            try { $v=[string]$item[$f.InternalName]; if ($v){ (Get-PatternHits $v) | ForEach-Object { $hits += "$($f.Title):$_" } } } catch {}
                                        }
                                    }
                                    if ($hits.Count -gt 0){
                                        $mod = try { [datetime]$item['Modified'] } catch { $null }
                                        $stale = if ($mod -and $mod -lt (Get-Date).AddDays(-$StaleDays)){$true}else{$false}
                                        $results.Add([PSCustomObject]@{Source='Metadata';List="$($web.Url) :: $($list.Title)";ItemUrl="$($web.Url.TrimEnd('/'))/$($item.Url)";Title=$item.Name;LastModified=$mod;Stale=$stale;UniquePerms=$item.HasUniqueRoleAssignments;Matches=($hits -join ' | ')})
                                    }
                                } catch { Write-Log "Item error in '$($list.Title)': $($_.Exception.Message)" WARN }
                                if ($ItemScanLimitPerList -gt 0 -and (++$scanned) -ge $ItemScanLimitPerList){ $stop=$true; break }
                            }
                            if ($stop){ break }
                            $q.ListItemCollectionPosition=$batch.ListItemCollectionPosition
                        } while ($null -ne $q.ListItemCollectionPosition)
                    } catch { Write-Log "List scan error '$($list.Title)': $($_.Exception.Message)" WARN }
                }

                if ($IncludeRecycleBin){
                    try {
                        foreach ($rb in $web.RecycleBin){
                            $hits=(Get-PatternHits $rb.Title)+(Get-PatternHits $rb.LeafName) | Sort-Object -Unique
                            if ($hits.Count -gt 0){
                                $results.Add([PSCustomObject]@{Source='RecycleBin';List=$rb.DirName;ItemUrl=$rb.LeafName;Title=$rb.Title;LastModified=$rb.DeletedDate;Stale='';UniquePerms='';Matches=("deleted by $($rb.DeletedByName): "+($hits -join ', '))})
                            }
                        }
                    } catch { Write-Log "Recycle bin error on '$($web.Url)': $($_.Exception.Message)" WARN }
                }
            }
            catch { Write-Log "Web error '$($web.Url)': $($_.Exception.Message)" WARN }
            finally { if ($web){$web.Dispose()} }
        }
        Write-Progress -Activity "Classification scan" -Completed
    }

    $results | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($results.Count) hits -> $OutputCsv" OK
}
catch { Write-Log "FATAL: $($_.Exception.Message)" ERROR; Write-Log "At: $($_.InvocationInfo.PositionMessage)" ERROR; Write-Verbose $_.ScriptStackTrace }
finally {
    if ($site){ try {$site.Dispose()} catch {} }
    try { Stop-SPAssignment -Global | Out-Null } catch {}
    Write-Log ("Done in {0:n1}s with {1} non-fatal error(s)." -f ((Get-Date)-$script:Start).TotalSeconds,$script:Errors)
    if ($LogFile){ try { Stop-Transcript | Out-Null } catch {} }
}
