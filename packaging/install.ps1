# XMem 포터블 설치 스크립트 — 사용자 단위 설치(관리자 권한 불필요).
# 사용: pwsh -File packaging/install.ps1 -ZipPath <xmem-vX.Y.Z-windows-x64.zip> [-InstallDir <DIR>] [-SkipShortcut]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ZipPath,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\XMem'),
    [switch]$SkipShortcut
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ZipPath)) {
    throw "zip 파일을 찾을 수 없습니다: $ZipPath"
}

$temp = Join-Path $env:TEMP ("xmem-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $temp -Force
    foreach ($name in @('xmem.exe', 'xmem-gui.exe', 'xmem-target.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $temp $name))) {
            throw "zip에 $name 이(가) 없습니다"
        }
    }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $temp 'xmem.exe') $InstallDir -Force
    Copy-Item (Join-Path $temp 'xmem-gui.exe') $InstallDir -Force
    Copy-Item (Join-Path $temp 'xmem-target.exe') $InstallDir -Force
    foreach ($doc in @('README.md', 'LICENSE')) {
        $source = Join-Path $temp $doc
        if (Test-Path -LiteralPath $source) { Copy-Item $source $InstallDir -Force }
    }

    if (-not $SkipShortcut) {
        try {
            $startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut((Join-Path $startMenu 'XMem GUI.lnk'))
            $shortcut.TargetPath = Join-Path $InstallDir 'xmem-gui.exe'
            $shortcut.WorkingDirectory = $InstallDir
            $shortcut.Save()
            Write-Host "시작 메뉴 바로가기 생성: XMem GUI"
        } catch {
            Write-Warning "바로가기를 만들지 못했습니다: $($_.Exception.Message)"
        }
    }

    Write-Host "설치 완료: $InstallDir"
    Write-Host "  CLI: $InstallDir\xmem.exe --help"
    Write-Host "  GUI: $InstallDir\xmem-gui.exe"
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
