<# ================== Get-VulnOps.ps1 ==================
 - Sources:
     1) CISA KEV (Known Exploited)
     2) NVD (recent CVEs, pubStartDate~pubEndDate)
     3) KISA / KRCERT pages (crawl + extract CVEs by regex)
 - Features:
     * UTF-8 console/file I/O
     * Asset/keyword matching, CSV outputs, optional Teams alert
     * Backoff retries (429/5xx), optional NVD API key
     * PS5-safe syntax
======================================================= #>

# ---------- UTF-8 baseline ----------
try { chcp 65001 > $null } catch {}
$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $utf8
[Console]::InputEncoding  = $utf8
$OutputEncoding = $utf8
$PSDefaultParameterValues['Out-File:Encoding']    = 'utf8'
$PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'
$PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]'Tls12,Tls13' } catch {}

# For querystring building on Windows PowerShell
Add-Type -AssemblyName System.Web

# ---------- Settings ----------
$SaveDir        = "C:\sec\out"
$AssetCsvPath   = "C:\sec\assets.csv"   # columns: product,version,owner
$DaysBack       = 3
$CvssMin        = 7.0                     # e.g. set 7.0 to keep only High+
$TeamsWebhook   = ""                    # leave empty to disable Teams notify
$NvdApiKey      = ""                    # optional: reduces 429
$MaxKoreaDepth  = 1                     # how deep to follow detail links per start page
$MaxKoreaPages  = 30                    # max detail pages to fetch per start page

# Keywords you care about (free-form, matched case-insensitively)
$Keywords = @(
  "weblogic","sitecore","apache http","nginx","exchange","windows server",
  "openssh","openssl","fortinet","juniper","cisco","atlassian","mssql","mysql","postgresql","redis"
)

# KISA / KRCERT starting pages (add/remove as needed)
# The script will open each page, collect detail links (href), visit them, and extract CVE IDs.
$KoreaStartPages = @(
  # KRCERT KNVD detail/list examples (adjust to your subscriptions)
  "https://knvd.krcert.or.kr/",
  "https://knvd.krcert.or.kr/resultList.do"
  # If you have specific list pages, add them too, e.g.:
  # "https://knvd.krcert.or.kr/data/secNoticeList.do",
  # "https://www.krcert.or.kr/data/secNoticeList.do"
)

# ---------- HTTP headers (봇 차단 완화) ----------
$Global:HttpHeaders = @{
  'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/VulnOps'
  'Accept'          = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  'Accept-Language' = 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'
  'Cache-Control'   = 'no-cache'
}

# HTML 페이지 대상 재시도 래퍼 (Invoke-WebRequest)
function Invoke-WebRetry {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [int]$TimeoutSec = 60,
    [int]$MaxRetry = 5
  )
  for($i=1; $i -le $MaxRetry; $i++){
    try {
      return Invoke-WebRequest -Uri $Uri -Headers $Global:HttpHeaders -TimeoutSec $TimeoutSec -MaximumRedirection 5 -UseBasicParsing
    } catch {
      $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
      if($i -ge $MaxRetry -or -not ($code -in 429,500,502,503,504)){ throw }
      $sleep = [Math]::Min(60, [Math]::Pow(2, $i) + (Get-Random -Min 0 -Max 1000)/1000.0)
      Write-Host ("[Retry {0}] HTTP {1} -> sleeping {2:0.0}s" -f $i,$code,$sleep) -ForegroundColor DarkYellow
      Start-Sleep -Seconds $sleep
    }
  }
}

# ---------- Helpers ----------
function Invoke-Http {
  param(
    [Parameter(Mandatory)] [string]$Uri,
    [int]$TimeoutSec = 60,
    [hashtable]$Headers = $null,
    [int]$MaxRetry = 5
  )
  $attempt = 0
  while ($true) {
    $attempt++
    try {
      if ($Headers) { return Invoke-RestMethod -Uri $Uri -Headers $Headers -TimeoutSec $TimeoutSec -UseBasicParsing }
      else { return Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec -UseBasicParsing }
    } catch {
      $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
      if ($attempt -ge $MaxRetry -or -not ($code -in 429,500,502,503,504)) { throw }
      $sleep = [Math]::Min(60, [Math]::Pow(2, $attempt) + (Get-Random -Min 0 -Max 1000)/1000.0)
      Write-Host ("[Retry {0}] HTTP {1} -> sleeping {2:0.0}s" -f $attempt,$code,$sleep) -ForegroundColor DarkYellow
      Start-Sleep -Seconds $sleep
    }
  }
}

function Send-Teams {
  param([string]$text)
  if([string]::IsNullOrWhiteSpace($TeamsWebhook)){ return }
  try {
    $payload = @{ text = $text } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Method Post -Uri $TeamsWebhook -Body $payload -ContentType 'application/json' | Out-Null
  } catch {
    Write-Host ("[Teams send failed] {0}" -f $_.Exception.Message) -ForegroundColor Red
  }
}

# ---------- Prep ----------
New-Item -ItemType Directory -Force -Path $SaveDir | Out-Null
if(-not (Test-Path $AssetCsvPath)){
  New-Item -ItemType Directory -Force -Path (Split-Path $AssetCsvPath) | Out-Null
@"
product,version,owner
weblogic,12.2.1.3,kim@company.com
sitecore,9.0,lee@company.com
windows server,2019,ops@company.com
apache http,2.4.57,dev@company.com
"@ | Set-Content $AssetCsvPath -Encoding utf8
  Write-Host "Asset template created: $AssetCsvPath (fill in and rerun)" -ForegroundColor Yellow
}
$Assets = if(Test-Path $AssetCsvPath){ Import-Csv $AssetCsvPath -Encoding UTF8 } else { @() }

$KeywordPattern = ($Keywords | ForEach-Object { [regex]::Escape($_) }) -join "|"

# ========== 1) CISA KEV ==========
Write-Host "`n[1/4] Fetching CISA KEV..." -ForegroundColor Cyan
$kevHits = @()
try {
  $kev = Invoke-Http -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  if($kev){
    $recent = ($kev.vulnerabilities | Sort-Object dateAdded -Descending) | Select-Object -First 400
    foreach($v in $recent){
      $text = ("{0} {1} {2}" -f $v.vendorProject, $v.products, $v.cveID)
      if($text -match $KeywordPattern){
        $owners = @()
        foreach($a in $Assets){
          $norm = ($text -replace '[^\w\s\.-]','')
          if($norm -match [regex]::Escape($a.product)){ $owners += $a.owner }
        }
        $kevHits += [pscustomobject]@{
          source = "CISA-KEV"
          cve    = $v.cveID
          name   = ("{0} - {1}" -f $v.vendorProject, $v.products).Trim()
          added  = $v.dateAdded
          due    = $v.dueDate
          cvss   = $null
          url    = "https://nvd.nist.gov/vuln/detail/$($v.cveID)"
          notes  = $v.notes
          owners = ($owners -join ", ")
        }
      }
    }
  }
} catch {
  Write-Host ("CISA KEV fetch failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

if($kevHits.Count){
  $out = Join-Path $SaveDir ("kev_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $kevHits | Sort-Object added -Descending | Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("KEV matches: {0} -> {1}" -f $kevHits.Count, $out) -ForegroundColor Green
}else{
  Write-Host "No KEV matches." -ForegroundColor Yellow
}

# ========== 2) NVD ==========
Write-Host "`n[2/4] Fetching NVD recent CVEs..." -ForegroundColor Cyan
$start   = (Get-Date).AddDays(-1 * $DaysBack).ToString("yyyy-MM-dd")
$end     = (Get-Date).ToString("yyyy-MM-dd")
$nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
$headers = @{}; if(-not [string]::IsNullOrWhiteSpace($NvdApiKey)){ $headers['apiKey'] = $NvdApiKey }

$nvdHits = @()
foreach($kw in $Keywords){
  # Build safe query
  $builder = [System.UriBuilder]$nvdBase
  $qs = [System.Web.HttpUtility]::ParseQueryString("")
  $qs["pubStartDate"]  = "$start`T00:00:00.000"
  $qs["pubEndDate"]    = "$end`T23:59:59.999"
  $qs["keywordSearch"] = $kw
  $builder.Query = $qs.ToString()
  $u = $builder.Uri.AbsoluteUri

  try{
    $nvd = Invoke-Http -Uri $u -Headers $headers
    foreach($c in $nvd.vulnerabilities){
      $id   = $c.cve.id
      $desc = ($c.cve.descriptions | Where-Object {$_.lang -eq "en"} | Select-Object -First 1).value
      $cvss = $null
      if($c.cve.metrics.cvssMetricV31){ $cvss = $c.cve.metrics.cvssMetricV31[0].cvssData.baseScore }
      elseif($c.cve.metrics.cvssMetricV30){ $cvss = $c.cve.metrics.cvssMetricV30[0].cvssData.baseScore }

      if(($desc -match [regex]::Escape($kw)) -or ($id -match [regex]::Escape($kw))){
        if($cvss -lt $CvssMin){ continue }
        $flat = ($desc -replace '\s+',' ').Trim()
        $summary = if($flat.Length -gt 160){ $flat.Substring(0,160) } else { $flat }
        $nvdHits += [pscustomobject]@{
          source = "NVD"
          cve    = $id
          name   = $kw
          added  = $null
          due    = $null
          cvss   = $cvss
          url    = "https://nvd.nist.gov/vuln/detail/$id"
          notes  = $summary
          owners = ""
        }
      }
    }
    if([string]::IsNullOrWhiteSpace($NvdApiKey)){ $delayMs = 1200 } else { $delayMs = 250 }
    Start-Sleep -Milliseconds $delayMs
  }catch{
    Write-Host ("NVD fetch failed ({0}): {1}" -f $kw, $_.Exception.Message) -ForegroundColor DarkYellow
  }
}

if($nvdHits.Count){
  $out = Join-Path $SaveDir ("nvd_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $nvdHits | Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("NVD results: {0} -> {1}" -f $nvdHits.Count, $out) -ForegroundColor Green
}else{
  Write-Host "No NVD keyword hits." -ForegroundColor Yellow
}

# ========== 3) KISA / KRCERT crawl ==========
Write-Host "`n[3/4] Crawling KISA/KRCERT pages..." -ForegroundColor Cyan

# 페이지네이션 확장 (resultList.do 인 경우 1~3페이지 순회)
$KoreaListPages = @()
foreach($base in $KoreaStartPages){
  if($base -match 'resultList\.do'){
    1..3 | ForEach-Object { $KoreaListPages += "$($base)?pageIndex=$_" }
  } else {
    $KoreaListPages += $base
  }
}

function Get-PageText {
  param([Parameter(Mandatory)][string]$Url)
  try {
    $resp = Invoke-WebRetry -Uri $Url -TimeoutSec 60
    if($resp.ParsedHtml){ return $resp.ParsedHtml.body.innerText }
    elseif($resp.Content){ return $resp.Content }
    else { return "" }
  } catch {
    Write-Host ("Fetch failed: {0}" -f $Url) -ForegroundColor DarkYellow
    return ""
  }
}

function Extract-CVEs {
  param([string]$Text)
  if([string]::IsNullOrWhiteSpace($Text)){ return @() }
  # KVE도 같이 추출
  $rx = 'CVE-\d{4}-\d{4,7}|KVE-\d{4}-\d{5}'
  return ([regex]::Matches($Text, $rx, 'IgnoreCase') | ForEach-Object { $_.Value.ToUpper() }) | Select-Object -Unique
}

$krHits = @()

foreach($startUrl in $KoreaListPages){
  Write-Host (" Start -> {0}" -f $startUrl) -ForegroundColor DarkCyan

  try {
    $root = Invoke-WebRetry -Uri $startUrl -TimeoutSec 60
  } catch {
    Write-Host ("  Failed to open: {0}" -f $startUrl) -ForegroundColor DarkYellow
    continue
  }

  # 상세 링크 수집
  $links = @()
  if($root.Links){
    $links = $root.Links.href |
      Where-Object { $_ -and ($_ -match 'detail|IDX=|view|article|notice|security|resultDetail') } |
      Select-Object -Unique
  }

# 폴백 1: raw HTML에서 href 직접 파싱
  if(-not $links -or $links.Count -eq 0){
    $raw = if($root.RawContent){ $root.RawContent } else { $root.Content }
    $hrefs = [regex]::Matches($raw, 'href\s*=\s*"([^"#]+)"', 'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }
    $links = $hrefs | Where-Object { $_ -and ($_ -match 'detail|IDX=|view|article|notice|security|resultDetail') } | Select-Object -Unique
  }

  # 디버그: 몇 개 잡혔는지 찍기
  Write-Host ("  detail links: {0}" -f ($links.Count)) -ForegroundColor DarkGray

  # 절대경로화
  $base = [System.Uri]$startUrl
  $absLinks = @()
  foreach($l in $links){
    try {
      if([System.Uri]::IsWellFormedUriString($l,[System.UriKind]::Absolute)){ $absLinks += $l }
      else { $absLinks += (New-Object System.Uri($base,$l)).AbsoluteUri }
    } catch {}
  }

  $absLinks = $absLinks | Select-Object -First $MaxKoreaPages

 # 폴백 2: 상세 링크가 전혀 없으면, 리스트 페이지 본문에서 바로 CVE/KVE 추출
  if(-not $absLinks -or $absLinks.Count -eq 0){
    $rootText = Get-PageText -Url $startUrl
    $directIds = Extract-CVEs -Text $rootText
    foreach($id in $directIds){
      $krHits += [pscustomobject]@{
        source = "KISA/KRCERT"
        cve    = $id
        name   = ""
        added  = (Get-Date -Format "yyyy-MM-dd")
        due    = $null
        cvss   = $null
        url    = $startUrl
        notes  = "Direct on list page"
        owners = ""
      }
    }
    if($directIds.Count){ continue }  # 다음 startUrl로
  }

  foreach($u in $absLinks){
    $text = Get-PageText -Url $u
    $cves = Extract-CVEs -Text $text
    if(-not $cves.Count){ continue }

    foreach($id in $cves){
      # 소유자 추정(키워드 기반)
      $owners = @()
      $hay = $text.ToLower()
      foreach($a in $Assets){
        if($hay -like ("*" + $a.product.ToLower() + "*")){ $owners += $a.owner }
      }

      $krHits += [pscustomobject]@{
        source = "KISA/KRCERT"
        cve    = $id
        name   = ""
        added  = (Get-Date -Format "yyyy-MM-dd")
        due    = $null
        cvss   = $null
        url    = $u
        notes  = "Found on: $startUrl"
        owners = ($owners -join ", ")
      }
    }
  }
}

if($krHits.Count){
  $out = Join-Path $SaveDir ("korea_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $krHits | Sort-Object cve -Unique | Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("Korea results: {0} -> {1}" -f $krHits.Count, $out) -ForegroundColor Green
} else {
  Write-Host "No CVEs extracted from KISA/KRCERT pages (check start URLs)." -ForegroundColor Yellow
}

# ========== 3.5) Vendor/CERT quick scan (폴백/보강) ==========
Write-Host "`n[3.5] Scanning vendor/CERT pages..." -ForegroundColor Cyan

$VendorPages = @(
  'https://msrc.microsoft.com/update-guide/',
  'https://www.fortiguard.com/psirt',
  'https://tools.cisco.com/security/center/publicationListing.x',
  'https://advisories.juniper.net',
  'https://confluence.atlassian.com/security/security-advisories'
)

$vendorHits = @()
foreach($vp in $VendorPages){
  try {
    $vt = (Invoke-WebRetry -Uri $vp -TimeoutSec 60).Content
    $ids = Extract-CVEs -Text $vt
    foreach($id in $ids){
      $vendorHits += [pscustomobject]@{
        source = "Vendor"
        cve    = $id
        name   = ""
        added  = (Get-Date -Format "yyyy-MM-dd")
        due    = $null
        cvss   = $null
        url    = $vp
        notes  = "regex from vendor page"
        owners = ""
      }
    }
  } catch {
    Write-Host (" vendor fail: {0}" -f $vp) -ForegroundColor DarkYellow
  }
}

if($vendorHits.Count){
  $out = Join-Path $SaveDir ("vendor_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $vendorHits | Sort-Object cve -Unique | Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("Vendor results: {0} -> {1}" -f $vendorHits.Count, $out) -ForegroundColor Green
}

# ========== 4) Unified summary (optional Teams) ==========
Write-Host "`n[4/4] Summary & notify..." -ForegroundColor Cyan
$all = @()
$all += $kevHits
$all += $nvdHits
$all += $krHits
$all += $vendorHits

if($CvssMin -gt 0){
  $all = $all | Where-Object { $_.cvss -ge $CvssMin -or -not $_.cvss }
}

if($all.Count){
  $top = $all | Select-Object -First 15
  $tbl = $top | Select-Object source,cve,name,added,due,cvss,url
  $tbl | Format-Table -AutoSize

  $msg = "**[Daily vuln digest]**`n" + ($top | ForEach-Object {
    "- [$($_.source)] **$($_.cve)** $($_.name) CVSS:$($_.cvss) `n$($_.url)"
  }) -join "`n"
  Send-Teams $msg
}else{
  Write-Host "No combined results." -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Cyan