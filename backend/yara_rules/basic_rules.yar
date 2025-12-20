rule upx_packed_binary
{
    meta:
        description = "Detects common UPX section names"
        severity = "medium"
    strings:
        $mz = "MZ" at 0
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        $mz and ($upx0 or $upx1)
}

rule suspicious_process_injection_apis
{
    meta:
        description = "Detects process injection related API strings"
        severity = "high"
    strings:
        $s1 = "VirtualAlloc"
        $s2 = "VirtualProtect"
        $s3 = "WriteProcessMemory"
        $s4 = "CreateRemoteThread"
        $s5 = "OpenProcess"
    condition:
        2 of ($s*)
}

rule embedded_powershell_reference
{
    meta:
        description = "Detects PowerShell command usage"
        severity = "low"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-ExecutionPolicy" nocase
        $ps3 = "IEX" nocase
    condition:
        2 of ($ps*)
}
