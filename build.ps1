<#
    Сборка и публикация NetworkChecker под Windows.
    usage:
        ./build.ps1                    # Debug-сборка + тесты
        ./build.ps1 -Publish           # framework-dependent publish в artifacts/win-x64
        ./build.ps1 -Publish -SelfContained
#>
param(
    [switch]$Publish,
    [switch]$SelfContained,
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "== restore" -ForegroundColor Cyan
dotnet restore

Write-Host "== build ($Configuration)" -ForegroundColor Cyan
dotnet build -c $Configuration --no-restore

Write-Host "== tests" -ForegroundColor Cyan
dotnet test -c $Configuration --no-build

if ($Publish) {
    $out = Join-Path $root "artifacts/$Runtime"
    Write-Host "== publish -> $out" -ForegroundColor Cyan
    $args = @(
        "publish", "src/NetworkChecker.App",
        "-c", $Configuration,
        "-r", $Runtime,
        "-o", $out,
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true"
    )
    if ($SelfContained) { $args += "--self-contained", "true" } else { $args += "--self-contained", "false" }
    dotnet @args
    Write-Host "Готово: $out/NetworkChecker.exe" -ForegroundColor Green
}
