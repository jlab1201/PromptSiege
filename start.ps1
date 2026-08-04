# Thin shim around start.py.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$psArgs = if ($args) { $args } else { @() }

if (Test-Path "venv\Scripts\python.exe") {
    & "venv\Scripts\python.exe" start.py @psArgs
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 start.py @psArgs
} else {
    & python start.py @psArgs
}
exit $LASTEXITCODE
