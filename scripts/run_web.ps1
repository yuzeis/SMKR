$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$env:PYTHONPATH = if ($env:PYTHONPATH) { "src;$env:PYTHONPATH" } else { "src" }
python -m roco_mitm web @args
