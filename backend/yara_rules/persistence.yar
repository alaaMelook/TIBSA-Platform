/*
    YARA Rules — Persistence Mechanisms
    Detects patterns associated with malware persistence:
    registry run keys, scheduled tasks, startup folder, services, WMI.
*/

rule Registry_Persistence
{
    meta:
        description = "Detects registry-based persistence mechanisms"
        author = "TIBSA"
        severity = "high"

    strings:
        // Common autorun registry paths
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
        $reg4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $reg5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $reg6 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components" ascii wide nocase
        // Registry API
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
        $api3 = "RegOpenKeyEx" ascii wide

    condition:
        any of ($reg*) and any of ($api*)
}

rule Scheduled_Task_Persistence
{
    meta:
        description = "Detects creation of scheduled tasks for persistence"
        author = "TIBSA"
        severity = "high"

    strings:
        $schtasks1 = "schtasks /create" ascii wide nocase
        $schtasks2 = "schtasks.exe /create" ascii wide nocase
        $at1 = "at.exe" ascii wide nocase
        $com1 = "Schedule.Service" ascii wide
        $com2 = "ITaskService" ascii wide
        $ps1 = "Register-ScheduledTask" ascii wide nocase
        $ps2 = "New-ScheduledTaskAction" ascii wide nocase

    condition:
        any of them
}

rule Startup_Folder_Persistence
{
    meta:
        description = "Detects file creation in startup folders"
        author = "TIBSA"
        severity = "medium"

    strings:
        $startup1 = "\\Start Menu\\Programs\\Startup" ascii wide nocase
        $startup2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii wide nocase
        $shell1 = "shell:startup" ascii wide nocase
        $shell2 = "shell:common startup" ascii wide nocase
        // File creation APIs
        $api1 = "CopyFile" ascii wide
        $api2 = "CreateFile" ascii wide
        $api3 = "WriteFile" ascii wide

    condition:
        any of ($startup*, $shell*) and any of ($api*)
}

rule Service_Persistence
{
    meta:
        description = "Detects service creation for persistence"
        author = "TIBSA"
        severity = "high"

    strings:
        $sc1 = "sc create" ascii wide nocase
        $sc2 = "sc.exe create" ascii wide nocase
        $api1 = "CreateService" ascii wide
        $api2 = "OpenSCManager" ascii wide
        $api3 = "StartService" ascii wide
        $ps1 = "New-Service" ascii wide nocase

    condition:
        ($sc1 or $sc2 or $ps1) or ($api1 and $api2) or ($api2 and $api3)
}

rule WMI_Persistence
{
    meta:
        description = "Detects WMI-based persistence mechanisms"
        author = "TIBSA"
        severity = "high"

    strings:
        $wmi1 = "Win32_ProcessStartup" ascii wide
        $wmi2 = "__EventFilter" ascii wide
        $wmi3 = "CommandLineEventConsumer" ascii wide
        $wmi4 = "__FilterToConsumerBinding" ascii wide
        $wmic1 = "wmic process call create" ascii wide nocase
        $ps1 = "Register-WmiEvent" ascii wide nocase
        $ps2 = "Set-WmiInstance" ascii wide nocase

    condition:
        2 of ($wmi*) or any of ($wmic*) or any of ($ps*)
}

rule PowerShell_Execution
{
    meta:
        description = "Detects suspicious PowerShell execution patterns"
        author = "TIBSA"
        severity = "medium"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $bypass1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
        $hidden1 = "-WindowStyle Hidden" ascii wide nocase
        $hidden2 = "-w hidden" ascii wide nocase
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase

    condition:
        ($ps1 or $ps2) and (
            any of ($enc*) or
            any of ($bypass*) or
            any of ($hidden*) or
            any of ($iex*) or
            any of ($dl*)
        )
}
