$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

$BundledPyInstaller = Join-Path $ProjectRoot "packaging\_pyinstaller"
$BundledTcl = Join-Path $ProjectRoot "packaging\tcl_runtime"
$Python = Get-Command py -ErrorAction SilentlyContinue
if (-not $Python) {
    $Python = Get-Command python -ErrorAction SilentlyContinue
}

if ((Test-Path -LiteralPath (Join-Path $BundledPyInstaller "PyInstaller")) -and $Python) {
    $env:PYTHONPATH = $BundledPyInstaller
    if (Test-Path -LiteralPath (Join-Path $BundledTcl "tcl8.6\init.tcl")) {
        $env:TCL_LIBRARY = Join-Path $BundledTcl "tcl8.6"
        $env:TK_LIBRARY = Join-Path $BundledTcl "tk8.6"
    }
    & $Python.Source -m PyInstaller --noconfirm --clean --onefile --windowed `
        --name "慎清-C盘清理审查器" `
        --version-file "packaging\version_info.txt" `
        "app.pyw"
}
elseif (Get-Command pyinstaller -ErrorAction SilentlyContinue) {
    pyinstaller --noconfirm --clean --onefile --windowed `
        --name "慎清-C盘清理审查器" `
        --version-file "packaging\version_info.txt" `
        "app.pyw"
}
else {
    throw "未找到 PyInstaller。请先运行：py -m pip install pyinstaller"
}

Write-Host "构建完成：$ProjectRoot\dist\慎清-C盘清理审查器.exe"
