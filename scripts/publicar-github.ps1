# Publicar GeekNosy en GitHub (repositorio PRIVADO)
# Uso: .\scripts\publicar-github.ps1

$ErrorActionPreference = "Stop"

$git = "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
$gh = "C:\Program Files\GitHub CLI\gh.exe"

if (-not (Test-Path $git)) { $git = "git" }
if (-not (Test-Path $gh)) { $gh = "gh" }

Set-Location (Resolve-Path "$PSScriptRoot\..")

Write-Host "=== GeekNosy - Publicar en GitHub (privado) ===" -ForegroundColor Cyan

# Verificar sesión GitHub
& $gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Inicia sesión en GitHub (se abrirá el navegador):" -ForegroundColor Yellow
    & $gh auth login -h github.com -p https -w
}

if (-not (Test-Path ".git")) {
    & $git init
    & $git branch -M main
}

& $git add -A
$status = & $git status --porcelain
if ($status) {
    & $git commit -m @"
Publicación inicial de GeekNosy.

Herramienta defensiva de evaluación de seguridad web pública.
Autor: Favio Urrea
"@
}

$repoName = "GeekNosy"
Write-Host "Creando repositorio privado: $repoName" -ForegroundColor Green

& $gh repo create $repoName --private --source=. --remote=origin --push

if ($LASTEXITCODE -eq 0) {
    $url = & $gh repo view --json url -q .url
    Write-Host "`nListo. Repositorio privado:" -ForegroundColor Green
    Write-Host $url
} else {
    Write-Host "`nSi el repo ya existe, ejecuta:" -ForegroundColor Yellow
    Write-Host "  gh repo create $repoName --private"
    Write-Host "  git remote add origin https://github.com/TU_USUARIO/$repoName.git"
    Write-Host "  git push -u origin main"
}
