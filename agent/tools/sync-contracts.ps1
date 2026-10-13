$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$source = Join-Path $root 'Документация ServerDeck/Документация ServerDeck Agent/contracts'
$destination = Join-Path $PSScriptRoot '../internal/contracts/schemas'
Get-ChildItem -LiteralPath $source -Filter '*.schema.json' -File | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destination $_.Name) -Force
}
