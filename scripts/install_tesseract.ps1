$ErrorActionPreference = "Stop"

Write-Host "Installing Tesseract OCR..." -ForegroundColor Cyan

$tesseractCmd = Get-Command tesseract -ErrorAction SilentlyContinue
$tesseractPath = $null
if ($tesseractCmd) {
  $tesseractPath = $tesseractCmd.Source
} else {
  $defaultPaths = @(
    "C:\Program Files\Tesseract-OCR\tesseract.exe",
    "C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"
  )
  foreach ($path in $defaultPaths) {
    if (Test-Path $path) {
      $tesseractPath = $path
      break
    }
  }
}

if (-not $tesseractPath) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "winget is not available. Install Tesseract manually."
  }
  $wingetIds = @(
    "UB-Mannheim.TesseractOCR",
    "tesseract-ocr.tesseract",
    "Tesseract.Tesseract.Stable"
  )
  $installed = $false
  foreach ($id in $wingetIds) {
    Write-Host "Trying winget install id: $id" -ForegroundColor Cyan
    winget install -e --id $id --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) {
      $installed = $true
      break
    }
  }
  if (-not $installed) {
    throw "winget could not install Tesseract. Try installing UB-Mannheim.TesseractOCR manually."
  }
  $tesseractCmd = Get-Command tesseract -ErrorAction SilentlyContinue
  if ($tesseractCmd) {
    $tesseractPath = $tesseractCmd.Source
  } else {
    foreach ($path in $defaultPaths) {
      if (Test-Path $path) {
        $tesseractPath = $path
        break
      }
    }
  }
}

if (-not $tesseractPath) {
  throw "Tesseract install failed or is not in PATH."
}

$tesseractDir = Split-Path $tesseractPath
$tessdataDir = $env:TESSDATA_PREFIX
if (-not $tessdataDir) {
  $tessdataDir = Join-Path $tesseractDir "tessdata"
}

New-Item -ItemType Directory -Force -Path $tessdataDir | Out-Null
$testFile = Join-Path $tessdataDir ".write_test"
try {
  Set-Content -Path $testFile -Value "test" -Force
  Remove-Item -Path $testFile -Force
} catch {
  $tessdataDir = Join-Path $env:LOCALAPPDATA "Tesseract-OCR\\tessdata"
  New-Item -ItemType Directory -Force -Path $tessdataDir | Out-Null
}

Write-Host "Tesseract path: $tesseractPath" -ForegroundColor Green
Write-Host "Tessdata path: $tessdataDir" -ForegroundColor Green

$pathParts = $env:Path -split ';'
if ($pathParts -notcontains $tesseractDir) {
  $env:Path = ($pathParts + $tesseractDir) -join ';'
  [Environment]::SetEnvironmentVariable("Path", $env:Path, "User")
}
if (-not $env:TESSDATA_PREFIX) {
  $env:TESSDATA_PREFIX = $tessdataDir
  [Environment]::SetEnvironmentVariable("TESSDATA_PREFIX", $tessdataDir, "User")
}

$baseUrl = "https://github.com/tesseract-ocr/tessdata_best/raw/main"
$languages = @("eng", "rus", "chi_sim", "fas")

foreach ($lang in $languages) {
  $dest = Join-Path $tessdataDir "$lang.traineddata"
  if (Test-Path $dest) {
    Write-Host "$lang already present" -ForegroundColor Yellow
    continue
  }
  $url = "$baseUrl/$lang.traineddata"
  Write-Host "Downloading $lang from $url" -ForegroundColor Cyan
  Invoke-WebRequest -Uri $url -OutFile $dest
}

Write-Host "Tesseract and language packs installed." -ForegroundColor Green
