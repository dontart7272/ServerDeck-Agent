# Verification only: no Agent/database/system mutation.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$manifest = Get-Content (Join-Path $PSScriptRoot 'build-inputs.json') -Raw | ConvertFrom-Json
foreach ($row in $manifest.files) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $root $row.path) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $row.sha256) { throw ('Build input changed: ' + $row.path) }
}
foreach ($list in @('documents.sha256', 'evidence.sha256')) {
    foreach ($line in (Get-Content -LiteralPath (Join-Path $PSScriptRoot $list))) {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw ('Invalid checksum line: ' + $list) }
        $expected, $relative = $Matches[1], $Matches[2]
        $base = if ($list -eq 'documents.sha256') { $root } else { $PSScriptRoot }
        if ((Get-FileHash -LiteralPath (Join-Path $base $relative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
            throw ('Checksum mismatch: ' + $relative)
        }
    }
}
Write-Output ('PASS: ' + $manifest.files.Count + ' tested build inputs; document/evidence checksums')
