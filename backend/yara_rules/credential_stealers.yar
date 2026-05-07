/*
    YARA Rules — Credential Stealers
    Detects patterns associated with information-stealing malware:
    browser credential theft, keylogging, clipboard monitoring.
*/

rule Browser_Credential_Stealer
{
    meta:
        description = "Detects access to browser credential storage paths"
        author = "TIBSA"
        severity = "high"

    strings:
        $chrome1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii wide nocase
        $chrome2 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii wide nocase
        $firefox1 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $firefox2 = "logins.json" ascii wide nocase
        $firefox3 = "key4.db" ascii wide nocase
        $edge1 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii wide nocase
        $opera1 = "\\Opera Software\\Opera Stable\\Login Data" ascii wide nocase
        $brave1 = "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" ascii wide nocase

    condition:
        2 of them
}

rule Keylogger_Indicators
{
    meta:
        description = "Detects keylogging functionality"
        author = "TIBSA"
        severity = "high"

    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookExA" ascii wide
        $api3 = "SetWindowsHookExW" ascii wide
        $api4 = "GetKeyState" ascii wide
        $api5 = "GetKeyboardState" ascii wide
        $api6 = "MapVirtualKey" ascii wide
        $api7 = "GetForegroundWindow" ascii wide
        $api8 = "GetWindowText" ascii wide
        $hook_id = "WH_KEYBOARD_LL" ascii wide
        $hook_val = { 0D 00 00 00 }  // WH_KEYBOARD_LL = 13

    condition:
        ($api1 or $api4 or $api5) and ($api7 or $api8) or
        ($api2 or $api3) and ($hook_id or $hook_val or $api6)
}

rule Email_Credential_Stealer
{
    meta:
        description = "Detects access to email client credentials"
        author = "TIBSA"
        severity = "high"

    strings:
        $outlook1 = "Software\\Microsoft\\Office\\Outlook" ascii wide nocase
        $outlook2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" ascii wide nocase
        $thunderbird1 = "\\Thunderbird\\Profiles" ascii wide nocase
        $smtp1 = "SMTP Password" ascii wide nocase
        $imap1 = "IMAP Password" ascii wide nocase

    condition:
        2 of them
}

rule Clipboard_Monitor
{
    meta:
        description = "Detects clipboard monitoring and hijacking"
        author = "TIBSA"
        severity = "medium"

    strings:
        $api1 = "OpenClipboard" ascii wide
        $api2 = "GetClipboardData" ascii wide
        $api3 = "SetClipboardData" ascii wide
        $api4 = "AddClipboardFormatListener" ascii wide
        $api5 = "SetClipboardViewer" ascii wide

    condition:
        ($api1 and $api2) or ($api4 or $api5) and $api3
}

rule FTP_Credential_Stealer
{
    meta:
        description = "Detects access to FTP client stored credentials"
        author = "TIBSA"
        severity = "medium"

    strings:
        $filezilla1 = "\\FileZilla\\recentservers.xml" ascii wide nocase
        $filezilla2 = "\\FileZilla\\sitemanager.xml" ascii wide nocase
        $winscp1 = "Software\\Martin Prikryl\\WinSCP 2\\Sessions" ascii wide nocase
        $coreftp1 = "Software\\FTPWare\\CoreFTP" ascii wide nocase

    condition:
        any of them
}
