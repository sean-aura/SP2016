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

 DEFAULT KEYWORDS cover the full NZ Government Security Classification System
 (PSR 2022): all six classification levels (IN-CONFIDENCE, SENSITIVE, RESTRICTED,
 CONFIDENTIAL, SECRET, TOP SECRET), standard endorsement markings (NZEO, CABINET,
 BUDGET, LEGAL PRIVILEGE, EMBARGOED, etc.), and common PII/credential terms.
 Override with -Keywords to use a custom list instead.

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
    [string[]]$Keywords = @(
                            # ---- NZ Government Security Classification System (PSR 2022) ----
                            # Policy and privacy classifications
                            'IN-CONFIDENCE','In Confidence',
                            'SENSITIVE',
                            # National security classifications
                            'RESTRICTED','CONFIDENTIAL','SECRET','TOP SECRET',
                            # Common endorsement markings
                            'NZEO','NEW ZEALAND EYES ONLY',
                            'ACCOUNTABLE MATERIAL',
                            'CABINET','BUDGET','APPOINTMENTS','HONOURS',
                            'LEGAL PRIVILEGE','LEGAL-PRIVILEGE',
                            'EMBARGOED','EMBARGOED FOR RELEASE',
                            'COMMERCIAL','EVALUATIVE','MEDICAL','STAFF',
                            'REL TO','RELEASABLE TO',
                            # ---- Generic / international classification terms ----
                            'Classified','Protected','Privileged',
                            # ---- PII / privacy / regulatory ----
                            'PII','Personal Information','Privacy Act',
                            'Health Information','Medical Record',
                            'NDA','Commercial In Confidence',
                            # ---- Credentials / security ----
                            'Password','Credential','Secret Key','API Key',
                            # ---- Legacy default terms retained ----
                            'Internal Only','HIPAA','PCI','SSN'
                            ),
    [string]$OutputCsv = ".\SP_Classification_Scan.csv",
    [switch]$ScanColumnValues,
    [switch]$DataPatterns,
    [switch]$IncludeRecycleBin,
    [int]$StaleDays = 730,
    [int]$ItemScanLimitPerList = 0,
    [switch]$UseSearch,
    [string]$LogFile
)

# ErrorActionPreference=Continue: a failed read on one item/list is logged and skipped
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

# $kwPattern: a single regex OR-ing every keyword, each wrapped in negative lookaround so it
# matches as a whole token. See the boundary notes immediately below for why \b is not used.
$kwPattern = ($Keywords | ForEach-Object { '(?<![A-Za-z0-9])' + [regex]::Escape($_) + '(?![A-Za-z0-9])' }) -join '|'
# Boundary notes:
# Several NZ classification keywords (STAFF, BUDGET, SECRET, MEDICAL, COMMERCIAL, EVALUATIVE) are
# common English word fragments. Standard regex \b does not help here because \b treats underscore
# as a word character, so "Top_Secret_Plan.docx" would NOT match SECRET with \b boundaries - exactly
# the opposite of what's needed for SharePoint's typical underscore/hyphen filename conventions.
# Instead each keyword is wrapped in negative lookaround requiring the character immediately before
# and after to NOT be a letter or digit. This correctly:
#   - MATCHES  "Top_Secret_Plan.docx", "budget-2025-final.xlsx", "IN-CONFIDENCE_Cabinet.docx"
#   - REJECTS  "Staffing_Plan.docx" (STAFF), "secretary_notes.docx" (SECRET), "medicalert.pdf" (MEDICAL)
# Multi-word phrases like 'TOP SECRET' still match as a literal phrase since the space is preserved
# inside the escaped keyword and only the outer edges are boundary-checked.
# Pattern notes:
# SSN regex matches NNN-NN-NNNN - may produce false positives (phone extensions, dates, etc.)
# CardNumber regex matches 13-16 digits with optional spaces/dashes - intentionally broad;
# a Luhn check would reduce false positives but adds significant complexity.
# Both patterns run on file names and metadata only, not file contents.
$dataRegex = @{ 'SSN' = '\b\d{3}-\d{2}-\d{4}\b'; 'CardNumber' = '\b(?:\d[ -]?){13,16}\b' }
# Get-PatternHits: returns the list of hit types found in $text - 'keyword' for any classification
# keyword match, plus 'SSN'/'CardNumber' when -DataPatterns is set. Returns an empty array on no hit.
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
    # Start/Stop-SPAssignment bracket the SPSite/SPWeb objects opened below so their
    # unmanaged memory is released deterministically at the end. Memory management only -
    # the recycle-bin enumeration and Search query used here are both read-only.
    Start-SPAssignment -Global | Out-Null
    Write-Log "Opening site collection: $SiteUrl"
    $site=Get-SPSite $SiteUrl -ErrorAction Stop

    if ($UseSearch){
        # PATH A - full-text via the Search service: sends the keywords as a KQL OR query, which
        # searches inside document contents (needs a running Search service and a completed crawl).
        # Results are paged in blocks of $pageSize. Search does its own word-based matching, so the
        # $kwPattern boundary logic does not apply here.
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
                if ($startRow -eq 0){
                    $totalRows=[int]$rel.TotalRows
                    Write-Log "Search: $totalRows total result(s) reported by Search." VERBOSE
                    # NOTE: SP2016 Search may cap TotalRows at the ResultsProvider limit (often 500-1000).
                    # If TotalRows equals a round number like 500, the actual corpus may be larger.
                    # Use metadata scan (without -UseSearch) for exhaustive coverage.
                    if ($totalRows -eq 500 -or $totalRows -eq 1000){
                        Write-Log "TotalRows=$totalRows may be a Search service cap - results could be truncated. Consider metadata scan for full coverage." WARN
                    }
                }
                foreach ($row in $rel.Table.Rows){
                    $results.Add([PSCustomObject]@{Source='Search';List='';ItemUrl=$row['Path'];Title=$row['Title'];LastModified=$row['LastModifiedTime'];Stale='';UniquePerms='';Matches="full-text: $queryText"})
                }
                $startRow+=$pageSize
            } while ($startRow -lt $totalRows)
        } catch { Write-Log "Search query failed (is the Search service running/crawled?): $($_.Exception.Message)" WARN }
    }
    else {
        # PATH B - metadata scan (default): walks every web/list and tests each item's Name (and,
        # with -ScanColumnValues, its non-hidden column values) against the patterns. This matches
        # names + metadata only, never file contents - use -UseSearch (Path A) for content scanning.
        $webs=$site.AllWebs; $total=$webs.Count; Write-Log "Found $total web(s)."; $i=0
        foreach ($web in $webs){
            $i++
            try {
                Write-Progress -Activity "Classification scan" -Status $web.Url -PercentComplete (($i/$total)*100)
                Write-Log "Web $i/$total : $($web.Url)" VERBOSE
                foreach ($list in $web.Lists){
                    if ($list.Hidden){continue}
                    try {
                        # Page through the list 2000 items at a time (RecursiveAll = files AND folders,
                        # all sub-folders) so a large library is never loaded into memory all at once.
                        # The loop advances via ListItemCollectionPosition until there are no more pages.
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
