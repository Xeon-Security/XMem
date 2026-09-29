# XMem 포터블 제거 스크립트 — install.ps1이 만든 폴더와 바로가기만 제거한다.
# 사용: pwsh -File packaging/uninstall.ps1 [-InstallDir <DIR>]
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\XMem')
)

$ErrorActionPreference = 'Stop'
$shortcut = Join-Path (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs') 'XMem GUI.lnk'
if (Test-Path -LiteralPath $shortcut) {
    Remove-Item -LiteralPath $shortcut -Force
    Write-Host "바로가기 제거: $shortcut"
}
if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "설치 폴더 제거: $InstallDir"
} else {
    Write-Host "설치 폴더가 없습니다: $InstallDir"
}
