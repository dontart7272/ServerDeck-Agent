# Documentation validation only; does not execute any Agent/server operation.
$ErrorActionPreference = 'Stop'
$agentDocs = Split-Path $PSScriptRoot -Parent
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$files = @(Get-ChildItem -LiteralPath $agentDocs -Filter '*.md' -File)
$files += Get-ChildItem -LiteralPath (Split-Path $agentDocs -Parent) -Filter '*.md' -File
$files += Get-Item -LiteralPath (Join-Path $agentDocs 'contracts/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'AGENTS.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/BUILD.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/STORAGE.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/AUTH-TRANSPORT.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/METRICS.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/evidence/E04-wsl-2026-10-13/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/evidence/E04-wsl-2026-10-13/SECURITY-REVIEW.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/evidence/E03-wsl-2026-10-13/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/evidence/E02-wsl-2026-10-13/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/THIRD_PARTY_NOTICES.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/evidence/E01-wsl-2026-10-13/README.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/SECURITY-AUDIT-2026-10-13.md')
$files += Get-Item -LiteralPath (Join-Path $workspace 'agent/API-SECURITY-AUDIT-2026-10-13.md')
$failures = [Collections.Generic.List[string]]::new()
$links = 0
$definitions = @{}
foreach ($name in @('2. Функциональные требования.md', '4. Требования безопасности.md')) {
    $body = Get-Content -LiteralPath (Join-Path $agentDocs $name) -Raw -Encoding utf8
    foreach ($match in [regex]::Matches($body, '(?m)^### ((?:AFR|ASEC)-\d{3})\.')) {
        if ($definitions.ContainsKey($match.Groups[1].Value)) { $failures.Add('Duplicate requirement: ' + $match.Groups[1].Value) }
        $definitions[$match.Groups[1].Value] = $name
    }
}
if (($definitions.Keys | Where-Object { $_ -like 'AFR-*' }).Count -ne 72) { $failures.Add('Expected 72 AFR definitions') }
if (($definitions.Keys | Where-Object { $_ -like 'ASEC-*' }).Count -ne 31) { $failures.Add('Expected 31 ASEC definitions') }
foreach ($file in $files) {
    $body = [string](Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8)
    if ([string]::IsNullOrWhiteSpace($body)) {
        if ($file.DirectoryName -eq $agentDocs) { $failures.Add('Empty Agent document: ' + $file.Name) }
        continue
    }
    if ($body.Contains([char]0xfffd)) { $failures.Add('Invalid UTF-8 replacement: ' + $file.Name) }
    foreach ($m in [regex]::Matches($body, '(?:AFR|ASEC)-\d{3}')) {
        if (-not $definitions.ContainsKey($m.Value)) { $failures.Add('Unresolved requirement ' + $m.Value + ' in ' + $file.Name) }
    }
    foreach ($m in [regex]::Matches($body, '\]\((?:<([^>]+)>|([^\s\)]+))\)')) {
        $target = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($target -match '^[a-zA-Z][a-zA-Z0-9+.-]*:' -or $target.StartsWith('#')) { continue }
        $pathPart = [Uri]::UnescapeDataString(($target -split '#', 2)[0])
        $localPath = [IO.Path]::GetFullPath((Join-Path $file.DirectoryName $pathPart))
        $links++
        if (-not (Test-Path -LiteralPath $localPath)) { $failures.Add('Broken link in ' + $file.Name + ': ' + $target) }
    }
}
$ledger = Get-Content -LiteralPath (Join-Path $agentDocs '11. Журнал проверки требований.md') -Raw -Encoding utf8
$clientFr = Get-Content -LiteralPath (Join-Path (Split-Path $agentDocs -Parent) '3. Функциональные требования.md') -Raw -Encoding utf8
if ([regex]::Matches($clientFr, '(?m)^### FR-007\.22\.').Count -ne 1) { $failures.Add('Client FR-007.22 must be unique') }
foreach ($id in $definitions.Keys) {
    $count = [regex]::Matches($ledger, '(?m)^\| ' + [regex]::Escape($id) + ' \|').Count
    if ($count -ne 1) { $failures.Add('Ledger must have one row for ' + $id + ', found ' + $count) }
}
$contracts = Join-Path $agentDocs 'contracts'
$schemaFiles = @(Get-ChildItem -LiteralPath $contracts -Filter '*.schema.json' -File)
$compiledTypes = 0
foreach ($file in $schemaFiles) {
    $schema = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    if ($schema['$schema'] -ne 'http://json-schema.org/draft-07/schema#') { $failures.Add('Unexpected schema draft: ' + $file.Name) }
    # Resolve every local JSON Pointer without downloading a remote schema.
    $walk = {
        param($node, $root)
        if ($node -is [System.Collections.IDictionary]) {
            if ($node.Contains('$ref')) {
                $pointer = $node['$ref']
                if (-not $pointer.StartsWith('#/')) { $failures.Add('Remote ref in ' + $file.Name + ': ' + $pointer) }
                else {
                    $cursor = $root
                    foreach ($part in $pointer.Substring(2).Split('/')) {
                        $key = $part.Replace('~1', '/').Replace('~0', '~')
                        if ($cursor -isnot [System.Collections.IDictionary] -or -not $cursor.Contains($key)) { $failures.Add('Missing ref in ' + $file.Name + ': ' + $pointer); break }
                        $cursor = $cursor[$key]
                    }
                }
            }
            foreach ($value in $node.Values) { & $walk $value $root }
        } elseif ($node -is [System.Collections.IList]) { foreach ($item in $node) { & $walk $item $root } }
    }
    & $walk $schema $schema
    # Compile every named type in context, including branches absent in examples.
    foreach ($typeName in $schema.definitions.Keys) {
        $wrapper = @{'$schema'=$schema['$schema']; '$id'=$schema['$id']; definitions=$schema.definitions; '$ref'='#/definitions/' + $typeName}
        $typeErrors = @()
        $null = Test-Json -Json '{}' -Schema ($wrapper | ConvertTo-Json -Depth 100 -Compress) -ErrorVariable typeErrors -ErrorAction SilentlyContinue
        foreach ($entry in $typeErrors) {
            if ($entry.FullyQualifiedErrorId -like 'InvalidJson,*' -or $entry.FullyQualifiedErrorId -like 'InvalidJsonSchema,*') { $failures.Add('Schema compilation failed: ' + $file.Name + '/' + $typeName) }
        }
        $compiledTypes++
    }
}
$exampleMap = @{ config='config'; query='api'; operation='api'; module='module'; ipc='ipc'; ui='ui'; release='release'; 'ipc-response'='ipc'; error='api'; 'operation-state'='api'; 'snapshot-response'='api' }
$exampleMap['wss-client'] = 'api'
$exampleMap['wss-server'] = 'api'
$valid = 0
$invalid = 0
foreach ($key in $exampleMap.Keys) {
    $examplePath = Join-Path $contracts ('examples/' + $key + '.json')
    $schemaPath = Join-Path $contracts ($exampleMap[$key] + '.schema.json')
    $json = Get-Content -LiteralPath $examplePath -Raw
    if (-not (Test-Json -Json $json -SchemaFile $schemaPath -ErrorAction SilentlyContinue)) { $failures.Add('Invalid example: ' + $key) } else { $valid++ }
    $mutated = $json | ConvertFrom-Json -AsHashtable -Depth 100
    $mutated['unexpected_field'] = 'must reject'
    if (Test-Json -Json ($mutated | ConvertTo-Json -Depth 100) -SchemaFile $schemaPath -ErrorAction SilentlyContinue) { $failures.Add('Unknown field accepted: ' + $key) } else { $invalid++ }
}
$cfg = Get-Content -LiteralPath (Join-Path $contracts 'examples/config.json') -Raw | ConvertFrom-Json -AsHashtable
$expected = @{'history.budget_bytes'=256000000; 'history.module_share_percent'=25; 'events.retention_days'=7; 'events.budget_bytes'=32000000; 'audit.retention_days'=30; 'audit.budget_bytes'=64000000; 'files.full_text_bytes'=1000000; 'files.edit_bytes'=512000; 'files.upload_bytes'=50000000; 'files.download_bytes'=100000000; 'trash.retention_days'=7; 'trash.budget_bytes_per_fs'=1000000000}
foreach ($key in $expected.Keys) {
    $parts = $key.Split('.')
    if ($cfg.runtime_initial[$parts[0]][$parts[1]] -ne $expected[$key]) { $failures.Add('Default mismatch: ' + $key) }
}
$apiPath = Join-Path $contracts 'api.schema.json'
$tooMany = Get-Content -LiteralPath (Join-Path $contracts 'examples/query.json') -Raw | ConvertFrom-Json -AsHashtable
$tooMany.params.max_points = 2001
if (Test-Json -Json ($tooMany | ConvertTo-Json -Depth 100) -SchemaFile $apiPath -ErrorAction SilentlyContinue) { $failures.Add('History max_points=2001 accepted') } else { $invalid++ }
$badSignal = Get-Content -LiteralPath (Join-Path $contracts 'examples/operation.json') -Raw | ConvertFrom-Json -AsHashtable
$badSignal.action = 'shell.exec'
if (Test-Json -Json ($badSignal | ConvertTo-Json -Depth 100) -SchemaFile $apiPath -ErrorAction SilentlyContinue) { $failures.Add('shell.exec accepted') } else { $invalid++ }
$catalog = Get-Content -LiteralPath (Join-Path $contracts 'examples/catalog.json') -Raw | ConvertFrom-Json -AsHashtable
$apiDoc = Get-Content -LiteralPath (Join-Path $agentDocs '3. API и форматы данных.md.md') -Raw
foreach ($name in @($catalog.queries) + @($catalog.actions)) {
    if (-not $apiDoc.Contains('`' + $name + '`')) { $failures.Add('Catalog not documented: ' + $name) }
}
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Output ('FAIL: ' + $_) }
    exit 1
}
Write-Output ('PASS: ' + $files.Count + ' documents, ' + $links + ' local links, 72 AFR + 31 ASEC, 103 ledger rows, ' + $schemaFiles.Count + ' schemas, ' + $compiledTypes + ' compiled types, ' + $valid + ' valid examples, ' + $invalid + ' negative fixtures, 12 defaults, ' + $catalog.queries.Count + ' queries, ' + $catalog.actions.Count + ' actions.')
Write-Output 'This command validates documents only; it does not execute Agent runtime/security/host checks.'
