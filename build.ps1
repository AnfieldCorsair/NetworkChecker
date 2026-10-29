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

function Assert-DotnetSuccess {
    if ($LASTEXITCODE -ne 0) { throw "dotnet завершился с кодом $LASTEXITCODE" }
}

Write-Host "== restore" -ForegroundColor Cyan
dotnet restore
Assert-DotnetSuccess

Write-Host "== build ($Configuration)" -ForegroundColor Cyan
dotnet build -c $Configuration --no-restore
Assert-DotnetSuccess

Write-Host "== tests" -ForegroundColor Cyan
dotnet test -c $Configuration --no-build
Assert-DotnetSuccess

if ($Publish) {
    $out = Join-Path $root "artifacts/$Runtime"
    Write-Host "== publish -> $out" -ForegroundColor Cyan
    $publishArgs = @(
        "publish", "src/NetworkChecker.App",
        "-c", $Configuration,
        "-r", $Runtime,
        "-o", $out,
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true"
    )
    if ($SelfContained) { $publishArgs += "--self-contained", "true" } else { $publishArgs += "--self-contained", "false" }
    dotnet @publishArgs
    Assert-DotnetSuccess
    Write-Host "Готово: $out/NetworkChecker.exe" -ForegroundColor Green
}
