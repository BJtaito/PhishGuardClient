param(
  [string]$ListPath = "tests\goldens.txt",
  [string]$OutDir = "tests\out"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Get-Content $ListPath | ForEach-Object {
  $u = $_.Trim()
  if ($u -and ($u -notmatch '^#')) {
    $safe = $u -replace '[^a-zA-Z0-9._-]', '_'
    Write-Output "Analyzing: $u"
    python -m analyzer.run $u --out "$OutDir\$safe.json"
  }
}