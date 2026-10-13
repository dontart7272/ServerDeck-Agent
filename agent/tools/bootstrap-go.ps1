# SPDX-License-Identifier: Apache-2.0
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$tools = Join-Path $root '.tools'
New-Item -ItemType Directory -Force -Path $tools | Out-Null
$archive = Join-Path $tools 'go1.27.2.windows-amd64.zip'
Invoke-WebRequest 'https://go.dev/dl/go1.27.2.windows-amd64.zip' -OutFile $archive
$expected = '1314008898bd40df77af4b014f777f08873dbdfbcd3d92308728ee03304fe04f'
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Go SHA256 mismatch' }
if (Test-Path -LiteralPath (Join-Path $tools 'go')) { throw 'Go directory already exists; retain it or use an explicitly empty tools directory' }
Expand-Archive -LiteralPath $archive -DestinationPath $tools
& (Join-Path $tools 'go/bin/go.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Go startup failed' }
