<#
.SYNOPSIS
    Konversi Nessus HTML ke CSV (Rev 11: Split Plugin Output hingga 5 Kolom).
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "Hasil_Scan_Rev11_MultiSplit.csv"
)

# --- FUNGSI PEMBERSIH HTML & PENGAMAN CSV ---
function Clean-HtmlString {
    param ([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    
    $Text = $Text -replace "(?i)<br\s*/?>", "`n"
    $Text = $Text -replace "(?i)</p>", "`n"
    $Text = $Text -replace "<[^>]+>", ""
    $Text = [System.Web.HttpUtility]::HtmlDecode($Text)
    $Text = $Text.Replace('"', "'") # Ganti kutip ganda jadi kutip satu (PENTING)
    $Text = $Text -replace "[ \t]+", " "
    $Text = $Text -replace "(\r?\n\s*)+", "`n"
    
    return $Text.Trim()
}

# --- FUNGSI PEMBERSIH TABEL ---
function Clean-TableData {
    param ([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    
    $Text = $Text -replace "(?s)<thead>.*?</thead>", ""
    $Text = $Text -replace "(?i)</tr>", "###BARIS###"
    $Text = $Text -replace "(?i)</td>", " "
    $Text = $Text -replace "<[^>]+>", ""
    $Text = [System.Web.HttpUtility]::HtmlDecode($Text)
    $Text = $Text.Replace('"', "'") 
    $Text = $Text -replace "[\r\n\t]+", " "
    
    $lines = $Text -split "###BARIS###"
    $cleanLines = @()
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            $cleanLines += $trimmed
        }
    }
    return $cleanLines
}

# 1. CEK FILE
if (-not (Test-Path $InputFile)) {
    Write-Error "File input tidak ditemukan!"
    exit
}

Add-Type -AssemblyName System.Web

Write-Host "Membaca file HTML..." -ForegroundColor Cyan
$content = Get-Content -Path $InputFile -Raw -Encoding UTF8

# 2. AMBIL HOST IP
$hostIp = "Unknown"
if ($content -match '(?s)>IP:</td>\s*<td[^>]*>(.*?)</td>') {
    $hostIp = Clean-HtmlString $matches[1]
} elseif ($content -match '<div xmlns="" id="id2"[^>]*>\s*(.*?)\s*<div') {
    $hostIp = Clean-HtmlString $matches[1]
}
Write-Host "Host IP: $hostIp" -ForegroundColor Green

# 3. PROSES DATA
Write-Host "Memproses data (Split Output hingga 5 Kolom)..." -ForegroundColor Yellow

$chunks = $content -split '<div xmlns="" id="'
$vulnData = @{}
$results = @()
$counter = 0

foreach ($chunk in $chunks) {
    $counter++
    if ($counter % 50 -eq 0) { Write-Progress -Activity "Processing" -Status "$counter / $($chunks.Count)" }

    # --- BAGIAN 1: HEADER ---
    if ($chunk -match '(?s)^id(\d+)"[^>]*background: (#[0-9A-F]+)[^>]*>(.*?)<div id="id\1-toggletext"') {
        $id = $matches[1]
        $color = $matches[2]
        $rawTitle = $matches[3]

        $risk = switch ($color) {
            "#91243E" { "Critical" }
            "#DD4B50" { "High" }
            "#F18C43" { "Medium" }
            "#F8C851" { "Low" }
            "#67ACE1" { "Info" }
            Default   { "Unknown" }
        }

        $vulnData[$id] = @{
            'Risk' = $risk
            'Name' = (Clean-HtmlString $rawTitle) -replace "- \s*$", ""
        }
    }
    
    # --- BAGIAN 2: CONTAINER ---
    elseif ($chunk -match '(?s)^id(\d+)-container".*?>(.*)') {
        $id = $matches[1]
        $body = $matches[2]

        if ($vulnData.ContainsKey($id)) {
            $item = $vulnData[$id]

            $synopsis = ""; $desc = ""; $sol = ""; 
            $cvssBase = ""; $cvssTemp = ""; 
            $seeAlso = ""; $rawOutput = ""; 
            $exploit = ""; $pluginInfo = ""
            
            $cveList = @()
            $xrefList = @()

            # Ekstraksi Data Standar
            if ($body -match '(?s)>Synopsis<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $synopsis = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>Description<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $desc = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>Solution<.*?<div style[^>]*>(.*?)<div class="clear">') {
                $sol = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>Exploitable With<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $exploit = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>Plugin Information<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $pluginInfo = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>See Also<.*?class="table-wrapper see-also"[^>]*>(.*?)</table>') {
                $rawSeeAlso = Clean-TableData $matches[1]
                $seeAlso = $rawSeeAlso -join "`n"
            }
            if ($body -match '(?s)>CVSS v3.0 Base Score<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $cvssBase = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>CVSS v3.0 Temporal Score<div.*?<div style[^>]*>(.*?)<div class="clear">') {
                $cvssTemp = Clean-HtmlString $matches[1]
            }
            if ($body -match '(?s)>References<.*?class="table-wrapper see-also"[^>]*>(.*?)</table>') {
                $rawRefs = Clean-TableData $matches[1]
                foreach ($line in $rawRefs) {
                    $cleanLine = $line -replace "^(CVE|XREF|BID)[:\s]+", ""
                    if ([string]::IsNullOrWhiteSpace($cleanLine) -or $cleanLine -match "^(CVE|XREF|BID)$") { continue }
                    if ($cleanLine -match "CVE-\d{4}-\d+") {
                        $cveList += $cleanLine
                    } else {
                        $xrefList += $cleanLine
                    }
                }
            }
            
            # --- PENGAMBILAN & PEMISAHAN PLUGIN OUTPUT (HINGGA 5 KOLOM) ---
            if ($body -match '(?s)>Plugin Output<.*?<div[^>]*background: #eee[^>]*>(.*?)<div class="clear">') {
                $rawOutput = Clean-HtmlString $matches[1]
            }

            # Limit Excel per sel (aman di 32.000)
            $limit = 32000
            
            # Array penampung untuk 5 kolom
            $outs = @("", "", "", "", "") 
            $currentText = $rawOutput

            # Loop untuk memecah teks menjadi 5 bagian
            for ($i = 0; $i -lt 5; $i++) {
                if ($currentText.Length -gt $limit) {
                    $outs[$i] = $currentText.Substring(0, $limit)
                    $currentText = $currentText.Substring($limit)
                } else {
                    $outs[$i] = $currentText
                    $currentText = "" # Kosongkan sisa karena sudah habis
                    break
                }
            }
            
            # Simpan ke Object
            $results += [PSCustomObject]@{
                'Host IP'                = $hostIp
                'Risk Factor'            = $item.Risk
                'Vulnerability'          = $item.Name
                'CVSS v3.0 Base Score'   = $cvssBase
                'CVSS v3.0 Temp Score'   = $cvssTemp
                'CVE'                    = ($cveList -join "`n")
                'XREF'                   = ($xrefList -join "`n")
                'Exploitable With'       = $exploit
                'Plugin Information'     = $pluginInfo
                'Synopsis'               = $synopsis
                'Description'            = $desc
                'Solution'               = $sol
                'See Also'               = $seeAlso
                'Plugin Output'          = $outs[0]
                'Plugin Output 2'        = $outs[1]
                'Plugin Output 3'        = $outs[2]
                'Plugin Output 4'        = $outs[3]
                'Plugin Output 5'        = $outs[4]
            }
        }
    }
}

# 4. EXPORT
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "SUKSES! File CSV disimpan di: $OutputFile" -ForegroundColor Green
    Write-Host "Total Vulnerability: $($results.Count)" -ForegroundColor Cyan
}
catch {
    Write-Error "Gagal menyimpan file: $_"
}