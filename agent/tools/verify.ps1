# SPDX-License-Identifier: Apache-2.0
param([string]$Go = 'go', [string]$Gofmt = 'gofmt')
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    if (-not $IsWindows) { throw 'Use smoke-linux.sh on Linux; this script verifies Windows only' }
    $env:GOTOOLCHAIN = 'local'
    $env:CGO_ENABLED = '1'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $version = & $Go env GOVERSION
    if ($LASTEXITCODE -ne 0 -or $version -ne 'go1.27.2') { throw 'Expected Go 1.27.2' }
    $compiler = & $Go env CC
    $compilerVersion = & $compiler -dumpfullversion
    if ($LASTEXITCODE -ne 0 -or $compilerVersion -ne '16.1.0') { throw 'Expected checked Windows GCC 16.1.0' }
    $sources = @(Get-ChildItem cmd,internal -Filter '*.go' -File -Recurse | ForEach-Object FullName)
    $unformatted = & $Gofmt -l $sources
    if ($LASTEXITCODE -ne 0 -or $unformatted) { throw 'gofmt required' }
    & $Go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'module integrity failed' }
    & $Go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'vet failed' }
    & $Go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
    foreach ($command in @('serverdeck-agent','serverdeckctl')) {
        & $Go build -mod=readonly -trimpath -buildvcs=false -o "dist/windows-amd64/$command.exe" "./cmd/$command"
        if ($LASTEXITCODE -ne 0) { throw 'build failed' }
        & "./dist/windows-amd64/$command.exe" version
        if ($LASTEXITCODE -ne 0) { throw 'offline version failed' }
    }
    & './dist/windows-amd64/serverdeckctl.exe' sqlite-info
    if ($LASTEXITCODE -ne 0) { throw 'SQLite probe failed' }
} finally { Pop-Location }
