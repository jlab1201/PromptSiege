# Thin shim: clone if needed, then hand off to install.py (the real installer).
# Works under `irm <url> | iex`, where $args is undefined.
$ErrorActionPreference = "Stop"
$psArgs = if ($args) { $args } else { @() }

if ((Test-Path "ui/server.py") -and (Test-Path "requirements.txt")) {
    Write-Host "existing PromptSiege checkout detected, installing in place"
} else {
    Write-Host "cloning PromptSiege..."
    git clone https://github.com/jlab1201/PromptSiege.git
    if ($LASTEXITCODE -ne 0) { throw "git clone failed. Install Git for Windows and re-run." }
    Set-Location PromptSiege
    $env:PROMPTSIEGE_CLONED = "1"
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 install.py @psArgs
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python install.py @psArgs
} else {
    throw "Python not found. Install Python 3.12+ from python.org (tick 'Add to PATH') and re-run."
}
exit $LASTEXITCODE
