# NetSec Orchestrator — Windows Tool Installer
Write-Host "=== NetSec Orchestrator — Tool Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check for Chocolatey
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

$tools = @(
    @{ Name = "nmap"; Choco = "nmap" },
    @{ Name = "tshark"; Choco = "wireshark" },
    @{ Name = "clamav"; Choco = "clamav" }
)

foreach ($tool in $tools) {
    if (Get-Command $tool.Name -ErrorAction SilentlyContinue) {
        Write-Host "✓ $($tool.Name) already installed" -ForegroundColor Green
    } else {
        Write-Host "Installing $($tool.Name)..." -ForegroundColor Yellow
        choco install $tool.Choco -y --no-progress
    }
}

Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Cyan
Write-Host "Run 'python -m netsec' to start the orchestrator."
