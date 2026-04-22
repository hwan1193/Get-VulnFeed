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
 - FIXED:
     * Apache / ActiveMQ 키워드 추가
     * CISA KEV product / vulnerabilityName / notes 기반 매칭 강화
     * NVD 결과의 name 컬럼을 검색 키워드가 아니라 실제 제품명 위주로 보정
     * Unified summary 정렬 / 중복 제거 / CISA 우선 노출
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
$CvssMin        = 7.0                   # e.g. set 7.0 to keep only High+
$TeamsWebhook   = ""                    # leave empty to disable Teams notify
$NvdApiKey      = ""                    # optional: reduces 429
$MaxKoreaDepth  = 1                     # how deep to follow detail links per start page
$MaxKoreaPages  = 30                    # max detail pages to fetch per start page

# Keywords you care about (free-form, matched case-insensitively)
# [FIX] apache / activemq / active mq / tinyproxy / churchcrm / distribution / pyload 추가
$Keywords = @(
  "weblogic","sitecore","apache","apache http","activemq","active mq",
  "nginx","exchange","windows server",
  "openssh","openssl","fortinet","juniper","cisco","atlassian",
  "mssql","mysql","postgresql","redis","oracle","linux",
  "tinyproxy","churchcrm","distribution","pyload"
)

# KISA / KRCERT starting pages
$KoreaStartPages = @(
  "https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133&menuNo=205020",
  "https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000204&menuNo=205021"
)

# ---------- HTTP headers ----------
$Global:HttpHeaders = @{
  'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
  'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
  'Accept-Language'           = 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'
  'Upgrade-Insecure-Requests' = '1'
  'Sec-Ch-Ua'                 = '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"'
  'Sec-Ch-Ua-Mobile'          = '?0'
  'Sec-Ch-Ua-Platform'        = '"Windows"'
  'Sec-Fetch-Site'            = 'same-origin'
  'Sec-Fetch-Mode'            = 'navigate'
  'Sec-Fetch-User'            = '?1'
  'Sec-Fetch-Dest'            = 'document'
  'Referer'                   = 'https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133&menuNo=205020'
}

$Global:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# ---------- Helpers ----------
function Invoke-WebRetry {
  param(
    [Parameter(Mandatory)][string]$Uri,
    [int]$TimeoutSec = 60,
    [int]$MaxRetry = 5
  )
  for($i=1; $i -le $MaxRetry; $i++){
    try {
      return Invoke-WebRequest -Uri $Uri -Headers $Global:HttpHeaders -WebSession $Global:WebSession -TimeoutSec $TimeoutSec -MaximumRedirection 5 -UseBasicParsing
    } catch {
      $code = $null
      try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
      if($i -ge $MaxRetry -or -not ($code -in 429,403,500,502,503,504)){ throw }
      $sleep = [Math]::Min(60, [Math]::Pow(2, $i) + (Get-Random -Min 0 -Max 1000)/1000.0)
      Write-Host ("[Retry {0}] HTTP {1} -> sleeping {2:0.0}s" -f $i,$code,$sleep) -ForegroundColor DarkYellow
      Start-Sleep -Seconds $sleep
    }
  }
}

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
      $code = $null
      try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
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

function Get-NonEmptyString {
  param([object]$Value)
  if($null -eq $Value){ return "" }
  $s = [string]$Value
  if([string]::IsNullOrWhiteSpace($s)){ return "" }
  return $s.Trim()
}

function Join-UniqueNonEmpty {
  param([object[]]$Values, [string]$Delimiter = ' ')
  $list = New-Object System.Collections.ArrayList
  foreach($v in $Values){
    $s = Get-NonEmptyString $v
    if(-not [string]::IsNullOrWhiteSpace($s)){
      if(-not ($list -contains $s)){ [void]$list.Add($s) }
    }
  }
  return ($list -join $Delimiter)
}

function Get-CisaProductText {
  param($Vuln)
  $items = New-Object System.Collections.ArrayList

  if($null -ne $Vuln.products){
    if($Vuln.products -is [System.Array]){
      foreach($p in $Vuln.products){
        $s = Get-NonEmptyString $p
        if($s -and -not ($items -contains $s)){ [void]$items.Add($s) }
      }
    } else {
      $s = Get-NonEmptyString $Vuln.products
      if($s -and -not ($items -contains $s)){ [void]$items.Add($s) }
    }
  }

  if($null -ne $Vuln.product){
    if($Vuln.product -is [System.Array]){
      foreach($p in $Vuln.product){
        $s = Get-NonEmptyString $p
        if($s -and -not ($items -contains $s)){ [void]$items.Add($s) }
      }
    } else {
      $s = Get-NonEmptyString $Vuln.product
      if($s -and -not ($items -contains $s)){ [void]$items.Add($s) }
    }
  }

  return ($items -join ", ")
}

function Get-CisaSearchText {
  param($Vuln)

  $productText = Get-CisaProductText -Vuln $Vuln
  $shortDescription = ""
  if($null -ne $Vuln.shortDescription){ $shortDescription = Get-NonEmptyString $Vuln.shortDescription }

  return (Join-UniqueNonEmpty @(
    $Vuln.vendorProject
    $productText
    $Vuln.cveID
    $Vuln.vulnerabilityName
    $shortDescription
    $Vuln.requiredAction
    $Vuln.notes
  ) ' ')
}

function Get-CisaDisplayName {
  param($Vuln)

  $productText = Get-CisaProductText -Vuln $Vuln
  $vendorText  = Get-NonEmptyString $Vuln.vendorProject
  $vulnName    = Get-NonEmptyString $Vuln.vulnerabilityName

  return (Join-UniqueNonEmpty @(
    $vendorText
    $productText
    $vulnName
  ) ' - ')
}

function Get-CvssFromNvd {
  param($Item)
  if($null -ne $Item.cve.metrics.cvssMetricV31){ return $Item.cve.metrics.cvssMetricV31[0].cvssData.baseScore }
  if($null -ne $Item.cve.metrics.cvssMetricV30){ return $Item.cve.metrics.cvssMetricV30[0].cvssData.baseScore }
  if($null -ne $Item.cve.metrics.cvssMetricV2){  return $Item.cve.metrics.cvssMetricV2[0].cvssData.baseScore }
  return $null
}

function Get-NvdDescription {
  param($Item)
  $d = $Item.cve.descriptions | Where-Object { $_.lang -eq "en" } | Select-Object -First 1
  if($null -ne $d){ return [string]$d.value }
  return ""
}

function Get-NvdDisplayName {
  param(
    $Item,
    [string]$Desc,
    [string]$Fallback
  )

  # 1) desc 앞부분에서 제품명 추출 시도
  if(-not [string]::IsNullOrWhiteSpace($Desc)){
    if($Desc -match '^([^\.]{3,120}?)(?:\s+(?:through|before|prior to|versions?|version|is|are|contains|has|allows|could|can)\b)'){
      $candidate = $matches[1].Trim()
      if($candidate.Length -ge 3){ return $candidate }
    }
  }

  # 2) CPE에서 vendor + product 추출 시도
  try {
    if($null -ne $Item.cve.configurations){
      foreach($conf in $Item.cve.configurations){
        if($null -ne $conf.nodes){
          foreach($node in $conf.nodes){
            if($null -ne $node.cpeMatch){
              foreach($cpe in $node.cpeMatch){
                $criteria = [string]$cpe.criteria
                if($criteria -match '^cpe:2\.3:[aho]:([^:]+):([^:]+):'){
                  $vendor  = ($matches[1] -replace '_',' ').Trim()
                  $product = ($matches[2] -replace '_',' ').Trim()
                  $full = (Join-UniqueNonEmpty @($vendor, $product) ' ')
                  if(-not [string]::IsNullOrWhiteSpace($full)){ return $full }
                }
              }
            }
          }
        }
      }
    }
  } catch {}

  return $Fallback
}

function Get-OwnersFromText {
  param(
    [string]$Text,
    $AssetList
  )

  $owners = New-Object System.Collections.ArrayList
  $norm = ($Text -replace '[^\w\s\.-]',' ').ToLower()

  foreach($a in $AssetList){
    $product = ""
    try { $product = [string]$a.product } catch {}
    if([string]::IsNullOrWhiteSpace($product)){ continue }

    $p = $product.Trim().ToLower()
    if([string]::IsNullOrWhiteSpace($p)){ continue }

    if($norm -match [regex]::Escape($p)){
      $owner = ""
      try { $owner = [string]$a.owner } catch {}
      if(-not [string]::IsNullOrWhiteSpace($owner)){
        if(-not ($owners -contains $owner)){ [void]$owners.Add($owner) }
      }
    }
  }

  return ($owners -join ", ")
}

function Get-SourcePriority {
  param([string]$Source)
  switch ($Source) {
    'CISA-KEV'   { return 0 }
    'NVD'        { return 1 }
    'Vendor'     { return 2 }
    'KISA/KRCERT'{ return 3 }
    default      { return 9 }
  }
}

function Get-SortDate {
  param([object]$Value)
  if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){
    return [datetime]'1900-01-01'
  }
  try { return [datetime]$Value } catch { return [datetime]'1900-01-01' }
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
apache activemq,5.18.3,middleware@company.com
activemq,5.18.3,middleware@company.com
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
      $searchText = Get-CisaSearchText -Vuln $v
      if($searchText -match $KeywordPattern){
        $owners = Get-OwnersFromText -Text $searchText -AssetList $Assets

        $notesText = Join-UniqueNonEmpty @(
          $v.shortDescription
          $v.requiredAction
          $v.notes
        ) ' | '

        $kevHits += [pscustomobject]@{
          source = "CISA-KEV"
          cve    = [string]$v.cveID
          name   = Get-CisaDisplayName -Vuln $v
          added  = [string]$v.dateAdded
          due    = [string]$v.dueDate
          cvss   = $null
          url    = "https://nvd.nist.gov/vuln/detail/$($v.cveID)"
          notes  = $notesText
          owners = $owners
        }
      }
    }
  }
} catch {
  Write-Host ("CISA KEV fetch failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

if($kevHits.Count){
  $out = Join-Path $SaveDir ("kev_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $kevHits |
    Sort-Object @{Expression={ Get-SortDate $_.added }; Descending=$true}, cve |
    Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("KEV matches: {0} -> {1}" -f $kevHits.Count, $out) -ForegroundColor Green
}else{
  Write-Host "No KEV matches." -ForegroundColor Yellow
}

# ========== 2) NVD ==========
Write-Host "`n[2/4] Fetching NVD recent CVEs..." -ForegroundColor Cyan
$start   = (Get-Date).AddDays(-1 * $DaysBack).ToString("yyyy-MM-dd")
$end     = (Get-Date).ToString("yyyy-MM-dd")
$nvdBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
$headers = @{}
if(-not [string]::IsNullOrWhiteSpace($NvdApiKey)){ $headers['apiKey'] = $NvdApiKey }

$nvdHits = @()
foreach($kw in $Keywords){
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
      $id   = [string]$c.cve.id
      $desc = Get-NvdDescription -Item $c
      $cvss = Get-CvssFromNvd -Item $c

      $descMatch = $false
      if(-not [string]::IsNullOrWhiteSpace($desc)){
        $descMatch = ($desc -match [regex]::Escape($kw))
      }

      if($descMatch -or ($id -match [regex]::Escape($kw))){
        if($cvss -ne $null -and $cvss -lt $CvssMin){ continue }

        $flat = ($desc -replace '\s+',' ').Trim()
        $summary = if($flat.Length -gt 220){ $flat.Substring(0,220) } else { $flat }

        $displayName = Get-NvdDisplayName -Item $c -Desc $desc -Fallback $kw
        $ownerText = Get-OwnersFromText -Text ((Join-UniqueNonEmpty @($displayName, $desc, $kw) ' ')) -AssetList $Assets

        $nvdHits += [pscustomobject]@{
          source = "NVD"
          cve    = $id
          name   = $displayName
          added  = $null
          due    = $null
          cvss   = $cvss
          url    = "https://nvd.nist.gov/vuln/detail/$id"
          notes  = $summary
          owners = $ownerText
        }
      }
    }

    if([string]::IsNullOrWhiteSpace($NvdApiKey)){ $delayMs = 6000 } else { $delayMs = 250 }
    Start-Sleep -Milliseconds $delayMs
  }catch{
    Write-Host ("NVD fetch failed ({0}): {1}" -f $kw, $_.Exception.Message) -ForegroundColor DarkYellow
  }
}

if($nvdHits.Count){
  $nvdHits = $nvdHits |
    Group-Object cve |
    ForEach-Object {
      $_.Group |
        Sort-Object @{Expression={ if($_.cvss -ne $null){ [double]$_.cvss } else { -1 } }; Descending=$true}, name |
        Select-Object -First 1
    }

  $out = Join-Path $SaveDir ("nvd_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $nvdHits | Sort-Object cve | Export-Csv $out -NoTypeInformation -Encoding UTF8
  Write-Host ("NVD results: {0} -> {1}" -f $nvdHits.Count, $out) -ForegroundColor Green
}else{
  Write-Host "No NVD keyword hits." -ForegroundColor Yellow
}

# ========== 3) KISA / KRCERT crawl ==========
Write-Host "`n[3/4] Crawling KISA/KRCERT pages..." -ForegroundColor Cyan

$KoreaListPages = @()
foreach($base in $KoreaStartPages){
  1..3 | ForEach-Object { $KoreaListPages += "$($base)&pageIndex=$_" }
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
  $rx = 'CVE-\d{4}-\d{4,7}|KVE-\d{4}-\d{5}'
  return ([regex]::Matches($Text, $rx, 'IgnoreCase') | ForEach-Object { $_.Value.ToUpper() }) | Select-Object -Unique
}

$krHits = @()

<#
foreach($startUrl in $KoreaListPages){
  Write-Host (" Start -> {0}" -f $startUrl) -ForegroundColor DarkCyan

  try {
    $root = Invoke-WebRetry -Uri $startUrl -TimeoutSec 60
  } catch {
    Write-Host ("  Failed to open: {0} - 상세 사유: {1}" -f $startUrl, $_.Exception.Message) -ForegroundColor Red
    continue
  }

  $links = @()
  if($root.Links){
    $links = $root.Links.href |
      Where-Object { $_ -and ($_ -match 'detail|IDX=|view|article|notice|security|resultDetail') } |
      Select-Object -Unique
  }

  if(-not $links -or $links.Count -eq 0){
    $raw = if($root.RawContent){ $root.RawContent } else { $root.Content }
    $hrefs = [regex]::Matches($raw, 'href\s*=\s*"([^"#]+)"', 'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }
    $links = $hrefs | Where-Object { $_ -and ($_ -match 'detail|IDX=|view|article|notice|security|resultDetail') } | Select-Object -Unique
  }

  Write-Host ("  detail links: {0}" -f ($links.Count)) -ForegroundColor DarkGray

  $base = [System.Uri]$startUrl
  $absLinks = @()
  foreach($l in $links){
    try {
      if([System.Uri]::IsWellFormedUriString($l,[System.UriKind]::Absolute)){ $absLinks += $l }
      else { $absLinks += (New-Object System.Uri($base,$l)).AbsoluteUri }
    } catch {}
  }

  $absLinks = $absLinks | Select-Object -First $MaxKoreaPages

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
    if($directIds.Count){ continue }
  }

  foreach($u in $absLinks){
    $text = Get-PageText -Url $u
    Write-Host ("  [$u] 페이지 텍스트 길이: " + $text.Length) -ForegroundColor Magenta
    if($text.Length -lt 1000){
        Write-Host "  [차단 원인 분석] $text" -ForegroundColor DarkCyan
    }

    $cves = Extract-CVEs -Text $text
    if(-not $cves.Count){ continue }

    foreach($id in $cves){
      $owners = Get-OwnersFromText -Text $text -AssetList $Assets

      $krHits += [pscustomobject]@{
        source = "KISA/KRCERT"
        cve    = $id
        name   = ""
        added  = (Get-Date -Format "yyyy-MM-dd")
        due    = $null
        cvss   = $null
        url    = $u
        notes  = "Found on: $startUrl"
        owners = $owners
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
#>

# ========== 3.5) Vendor/CERT quick scan ==========
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
  # [FIX] cve 기준 대표 레코드 선택: CISA 우선 -> 최신 added -> 높은 CVSS
  $all = $all |
    Group-Object cve |
    ForEach-Object {
      $_.Group |
        Sort-Object `
          @{Expression={ Get-SourcePriority $_.source }}, `
          @{Expression={ Get-SortDate $_.added }; Descending=$true}, `
          @{Expression={ if($_.cvss -ne $null){ [double]$_.cvss } else { -1 } }; Descending=$true} |
        Select-Object -First 1
    }

  $all = $all |
    Sort-Object `
      @{Expression={ Get-SourcePriority $_.source }}, `
      @{Expression={ Get-SortDate $_.added }; Descending=$true}, `
      @{Expression={ if($_.cvss -ne $null){ [double]$_.cvss } else { -1 } }; Descending=$true}, `
      cve

  $summaryOut = Join-Path $SaveDir ("summary_hits_{0}.csv" -f (Get-Date -f yyyyMMdd))
  $all | Export-Csv $summaryOut -NoTypeInformation -Encoding UTF8

  $top = $all | Select-Object -First 30
  $tbl = $top | Select-Object source,cve,name,added,due,cvss,url,owners
  $tbl | Format-Table -AutoSize

  $msg = "**[Daily vuln digest]**`n" + (($top | ForEach-Object {
    $cvssText = if($_.cvss -ne $null){ $_.cvss } else { "-" }
    $ownerText = if(-not [string]::IsNullOrWhiteSpace($_.owners)){ " Owner:$($_.owners)" } else { "" }
    "- [$($_.source)] **$($_.cve)** $($_.name) CVSS:$cvssText$ownerText `n$($_.url)"
  }) -join "`n")
  Send-Teams $msg

  Write-Host ("Unified summary: {0} -> {1}" -f $all.Count, $summaryOut) -ForegroundColor Green
}else{
  Write-Host "No combined results." -ForegroundColor Yellow
}

Write-Host "`nDone." -ForegroundColor Cyan