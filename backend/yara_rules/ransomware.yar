/*
    YARA Rules — Ransomware Indicators
    Detects patterns associated with ransomware: encryption APIs,
    ransom note patterns, file extension manipulation, shadow copy deletion.
*/

rule Ransomware_Encryption_APIs
{
    meta:
        description = "Detects heavy use of cryptographic APIs typical of ransomware"
        author = "TIBSA"
        severity = "critical"

    strings:
        $crypt1 = "CryptEncrypt" ascii wide
        $crypt2 = "CryptGenKey" ascii wide
        $crypt3 = "CryptImportKey" ascii wide
        $crypt4 = "CryptAcquireContext" ascii wide
        $crypt5 = "CryptDeriveKey" ascii wide
        $bcrypt1 = "BCryptEncrypt" ascii wide
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii wide
        // File enumeration
        $enum1 = "FindFirstFile" ascii wide
        $enum2 = "FindNextFile" ascii wide

    condition:
        2 of ($crypt*) and ($enum1 and $enum2) or
        2 of ($bcrypt*) and ($enum1 and $enum2)
}

rule Ransom_Note_Strings
{
    meta:
        description = "Detects common ransom note text patterns"
        author = "TIBSA"
        severity = "critical"

    strings:
        $note1 = "Your files have been encrypted" ascii wide nocase
        $note2 = "All your files are encrypted" ascii wide nocase
        $note3 = "pay the ransom" ascii wide nocase
        $note4 = "bitcoin wallet" ascii wide nocase
        $note5 = "decrypt your files" ascii wide nocase
        $note6 = "README_TO_DECRYPT" ascii wide nocase
        $note7 = "DECRYPT_INSTRUCTION" ascii wide nocase
        $note8 = "HOW_TO_RECOVER" ascii wide nocase
        $note9 = "YOUR_FILES_ARE_LOCKED" ascii wide nocase
        $note10 = "recovery key" ascii wide nocase

    condition:
        2 of them
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Detects Volume Shadow Copy deletion used by ransomware"
        author = "TIBSA"
        severity = "critical"

    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $wmic1 = "wmic shadowcopy delete" ascii wide nocase
        $bcdedit1 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $bcdedit2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $ps_vss = "Get-WmiObject Win32_ShadowCopy" ascii wide nocase
        $diskshadow = "diskshadow" ascii wide nocase

    condition:
        any of ($vss*) or any of ($wmic*) or any of ($bcdedit*) or $ps_vss or $diskshadow
}

rule File_Extension_Manipulation
{
    meta:
        description = "Detects file renaming with suspicious extensions typical of ransomware"
        author = "TIBSA"
        severity = "high"

    strings:
        $rename1 = "MoveFileEx" ascii wide
        $rename2 = "MoveFile" ascii wide
        $rename3 = "rename" ascii
        // Common ransomware extensions
        $ext1 = ".encrypted" ascii wide nocase
        $ext2 = ".locked" ascii wide nocase
        $ext3 = ".crypt" ascii wide nocase
        $ext4 = ".enc" ascii wide nocase
        $ext5 = ".locky" ascii wide nocase
        $ext6 = ".cerber" ascii wide nocase
        $ext7 = ".zepto" ascii wide nocase
        $ext8 = ".wnry" ascii wide nocase

    condition:
        any of ($rename*) and 2 of ($ext*)
}
