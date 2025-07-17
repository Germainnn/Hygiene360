# === Mock EDR Service Setup ===
New-Item -Path "C:\Program Files\TestEDR" -ItemType Directory -Force
Set-Content -Path "C:\Program Files\TestEDR\testedr.exe" -Value "Fake EDR binary"

# Create fake service using sc.exe (non-functional, just for display)
sc.exe create TestEDR binPath= "C:\Program Files\TestEDR\testedr.exe" start= demand

# Add registry key
New-Item -Path "HKLM:\SOFTWARE\TestEDR" -Force | Out-Null

# === Mock DLP Setup ===
New-Item -Path "C:\Program Files\TestDLP" -ItemType Directory -Force
Set-Content -Path "C:\Program Files\TestDLP\testdlp.exe" -Value "Fake DLP binary"
sc.exe create TestDLP binPath= "C:\Program Files\TestDLP\testdlp.exe" start= demand
New-Item -Path "HKLM:\SOFTWARE\TestDLP" -Force | Out-Null

Write-Output "✅ Mock EDR and DLP created. You can now test with your script."
