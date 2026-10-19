$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceRoot = Join-Path $root "java\src\main\java"
$classes = Join-Path $root "build\classes"

New-Item -ItemType Directory -Force -Path $classes | Out-Null
$sources = Get-ChildItem -Path $sourceRoot -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
if ($sources.Count -eq 0) {
    throw "No Java source files found under $sourceRoot"
}

& javac -encoding UTF-8 -d $classes $sources
if ($LASTEXITCODE -ne 0) {
    throw "Java compilation failed with exit code $LASTEXITCODE"
}
$resources = Join-Path $root "java\src\main\resources"
if (Test-Path -LiteralPath $resources) {
    Copy-Item -Path (Join-Path $resources "*") -Destination $classes -Recurse -Force
}
Write-Host "Java classes compiled to $classes"
