# Install NetSec Orchestrator as a Windows service using NSSM
param(
    [string]$InstallDir = "C:\netsec-orchestrator",
    [string]$NssmPath = "C:\nssm\nssm.exe"
)

$ServiceName = "NetSecOrchestrator"
$PythonPath = Join-Path $InstallDir ".venv\Scripts\python.exe"

if (-not (Test-Path $NssmPath)) {
    Write-Error "NSSM not found at $NssmPath. Download from https://nssm.cc/"
    exit 1
}

if (-not (Test-Path $PythonPath)) {
    Write-Error "Python venv not found at $PythonPath. Run install first."
    exit 1
}

# Install service
& $NssmPath install $ServiceName $PythonPath "-m" "netsec"
& $NssmPath set $ServiceName AppDirectory $InstallDir
& $NssmPath set $ServiceName DisplayName "NetSec Orchestrator"
& $NssmPath set $ServiceName Description "Security orchestration backend"
& $NssmPath set $ServiceName Start SERVICE_AUTO_START
& $NssmPath set $ServiceName AppStdout (Join-Path $InstallDir "logs\stdout.log")
& $NssmPath set $ServiceName AppStderr (Join-Path $InstallDir "logs\stderr.log")

Write-Host "Service installed. Start with: nssm start $ServiceName"
