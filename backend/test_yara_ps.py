"""Test YARA scanner against the PowerShell fake malware content."""
import sys
sys.stdout.reconfigure(encoding="utf-8")

from app.services.ai.yara_scanner import scan_file_bytes

ps_content = b"""# Fake malware simulation for testing only

$encoded = "SGVsbG8gV29ybGQ="
$decoded = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($encoded)
)

Write-Host $decoded

# Suspicious strings for YARA testing
$api1 = "VirtualAllocEx"
$api2 = "CreateRemoteThread"
$api3 = "WriteProcessMemory"

# Fake persistence
$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Fake network IOC
$url = "http://malicious-test-domain.com/payload.exe"

Write-Host "Simulation complete"
"""

print("Testing YARA on PowerShell content...")
matches = scan_file_bytes("test_malware.ps1", ps_content)
print(f"YARA Matches: {matches}")
print(f"Match count: {len(matches)}")

if matches:
    print("SUCCESS: YARA detected suspicious patterns!")
else:
    print("WARNING: No YARA matches - rules may need updating")
