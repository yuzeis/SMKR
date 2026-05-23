$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Remove-ProjectPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }
  $resolvedRoot = (Resolve-Path -LiteralPath $root).Path.TrimEnd("\")
  $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
  if (-not $resolvedPath.StartsWith($resolvedRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove outside project: $resolvedPath"
  }
  Remove-Item -LiteralPath $resolvedPath -Recurse -Force
}

$targets = @(
  "runtime\logs",
  "runtime\pids",
  "runtime\cache",
  "runtime\conn_map.json",
  ".pytest_cache"
)

foreach ($target in $targets) {
  $path = Join-Path $root $target
  Remove-ProjectPath -Path $path
}

Get-ChildItem -Path $root -Directory -Recurse -Filter "__pycache__" |
  ForEach-Object { Remove-ProjectPath -Path $_.FullName }

New-Item -ItemType Directory -Force -Path (Join-Path $root "runtime\logs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root "runtime\pids") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root "runtime\cache") | Out-Null
