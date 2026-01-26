/*
    APT (Advanced Persistent Threat) Indicators
    Detects tactics, techniques, and procedures used by APT groups
*/

rule apt_cobalt_strike_beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon implant"
        severity = "critical"
        category = "apt"
        tool = "Cobalt Strike"
        reference = "https://attack.mitre.org/software/S0154/"
    strings:
        // Beacon configuration markers
        $config1 = { 00 01 00 01 00 02 }  // Beacon config header
        $config2 = "cobaltstrike" nocase
        $config3 = "beacon" nocase

        // Named pipe (SMB beacon)
        $pipe1 = "\\\\.\\pipe\\msagent_" nocase
        $pipe2 = "\\\\.\\pipe\\postex_" nocase
        $pipe3 = "\\\\.\\pipe\\MSSE-" nocase

        // Malleable C2 profile strings
        $malleable1 = "___PARAM___" nocase
        $malleable2 = "___DATA___" nocase

        // Reflective DLL injection
        $rdll1 = "ReflectiveLoader"
        $rdll2 = { 4D 5A 41 52 55 48 89 E5 }  // MZ shellcode header

        // HTTPS C2 patterns
        $http1 = "User-Agent:" nocase
        $http2 = "Cookie:" nocase

    condition:
        2 of ($config*) or
        1 of ($pipe*) or
        ($rdll1 and $rdll2) or
        2 of ($malleable*)
}

rule apt_metasploit_meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter payload"
        severity = "critical"
        category = "apt"
        tool = "Metasploit"
    strings:
        // Meterpreter core commands
        $cmd1 = "core_loadlib"
        $cmd2 = "stdapi_sys_process_execute"
        $cmd3 = "stdapi_fs_file_upload"
        $cmd4 = "stdapi_net_socket_tcp_connect"

        // Meterpreter extensions
        $ext1 = "ext_server_stdapi"
        $ext2 = "ext_server_priv"
        $ext3 = "ext_server_espia"

        // TLV (Type-Length-Value) packet structure
        $tlv = { 00 00 00 ?? 00 00 00 ?? }

        // Reflective DLL loading
        $refl1 = "ReflectiveDLLInjection"

    condition:
        2 of ($cmd*) or
        2 of ($ext*) or
        ($tlv and $refl1)
}

rule apt_powershell_empire
{
    meta:
        description = "Detects PowerShell Empire framework"
        severity = "high"
        category = "apt"
        tool = "PowerShell Empire"
    strings:
        // Empire agent strings
        $emp1 = "PowerShell Empire" nocase
        $emp2 = "BC46C8BC" nocase  // Empire AES key
        $emp3 = "System.Management.Automation" nocase

        // Empire modules
        $mod1 = "Invoke-Mimikatz" nocase
        $mod2 = "Get-Keystrokes" nocase
        $mod3 = "Invoke-Shellcode" nocase

        // Obfuscation patterns
        $obf1 = "[System.Convert]::FromBase64String" nocase
        $obf2 = "IO.Compression.GzipStream" nocase
        $obf3 = "[System.Text.Encoding]::UTF8.GetString" nocase

        // C2 communication
        $c2_1 = "GetTask" nocase
        $c2_2 = "PostResults" nocase

    condition:
        1 of ($emp*) or
        2 of ($mod*) or
        (2 of ($obf*) and 1 of ($c2_*))
}

rule apt_mimikatz_credential_dumping
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        category = "apt"
        tool = "Mimikatz"
        reference = "https://attack.mitre.org/software/S0002/"
    strings:
        // Mimikatz strings
        $mimi1 = "mimikatz" nocase
        $mimi2 = "gentilkiwi" nocase
        $mimi3 = "sekurlsa::logonpasswords" nocase

        // Mimikatz modules
        $mod1 = "sekurlsa" nocase
        $mod2 = "kerberos" nocase
        $mod3 = "lsadump" nocase
        $mod4 = "vault" nocase

        // LSASS access
        $lsass1 = "lsass.exe" nocase
        $lsass2 = "MiniDumpWriteDump"
        $lsass3 = "SeDebugPrivilege"

        // Kerberos ticket extraction
        $kerb1 = "kerberos::golden" nocase
        $kerb2 = "kerberos::ptt" nocase
        $kerb3 = ".kirbi" nocase

    condition:
        1 of ($mimi*) or
        2 of ($mod*) or
        (1 of ($lsass*) and $lsass3) or
        1 of ($kerb*)
}

rule apt_lateral_movement_psexec
{
    meta:
        description = "Detects PsExec-style lateral movement"
        severity = "high"
        category = "apt"
        technique = "T1021.002"  # MITRE ATT&CK: Remote Services: SMB/Windows Admin Shares
    strings:
        // PsExec strings
        $psexec1 = "psexec" nocase
        $psexec2 = "PSEXESVC" nocase
        $psexec3 = "PsExec.exe" nocase

        // SMB share access
        $smb1 = "\\\\\\\\.*\\\\ADMIN$" nocase
        $smb2 = "\\\\\\\\.*\\\\C$" nocase
        $smb3 = "\\\\\\\\.*\\\\IPC$" nocase

        // Service creation
        $svc1 = "CreateService"
        $svc2 = "StartService"
        $svc3 = "sc.exe" nocase

        // Remote execution
        $exec1 = "cmd.exe /c" nocase
        $exec2 = "%COMSPEC%" nocase

    condition:
        1 of ($psexec*) or
        (1 of ($smb*) and 2 of ($svc*))
}

rule apt_wmi_persistence
{
    meta:
        description = "Detects WMI-based persistence and lateral movement"
        severity = "high"
        category = "apt"
        technique = "T1047"  # MITRE ATT&CK: Windows Management Instrumentation
    strings:
        // WMI namespaces
        $wmi1 = "root\\subscription" nocase
        $wmi2 = "root\\cimv2" nocase

        // WMI event consumers
        $consumer1 = "CommandLineEventConsumer" nocase
        $consumer2 = "ActiveScriptEventConsumer" nocase
        $consumer3 = "LogFileEventConsumer" nocase

        // WMI event filters
        $filter1 = "__EventFilter" nocase
        $filter2 = "SELECT * FROM" nocase

        // WMI process creation
        $proc1 = "Win32_Process" nocase
        $proc2 = "Create" nocase

    condition:
        1 of ($wmi*) and
        (1 of ($consumer*) or 1 of ($filter*) or ($proc1 and $proc2))
}

rule apt_scheduled_task_persistence
{
    meta:
        description = "Detects scheduled task persistence"
        severity = "medium"
        category = "apt"
        technique = "T1053.005"  # MITRE ATT&CK: Scheduled Task/Job
    strings:
        // schtasks commands
        $schtask1 = "schtasks /create" nocase
        $schtask2 = "schtasks /run" nocase
        $schtask3 = "schtasks /change" nocase

        // Task scheduler APIs
        $api1 = "ITaskScheduler"
        $api2 = "RegisterTask"
        $api3 = "CreateTask"

        // Task triggers
        $trigger1 = "TASK_TRIGGER_LOGON" nocase
        $trigger2 = "TASK_TRIGGER_BOOT" nocase
        $trigger3 = "OnLogon" nocase

    condition:
        1 of ($schtask*) or
        2 of ($api*) or
        1 of ($trigger*)
}

rule apt_registry_run_key_persistence
{
    meta:
        description = "Detects registry Run key persistence"
        severity = "medium"
        category = "apt"
        technique = "T1547.001"  # MITRE ATT&CK: Boot or Logon Autostart Execution: Registry Run Keys
    strings:
        // Run key paths
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $run3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase

        // Registry APIs
        $api1 = "RegSetValueEx"
        $api2 = "RegCreateKeyEx"
        $api3 = "RegOpenKeyEx"

        // reg.exe commands
        $reg1 = "reg add" nocase
        $reg2 = "REG_SZ" nocase

    condition:
        1 of ($run*) and
        (1 of ($api*) or 1 of ($reg*))
}

rule apt_token_manipulation
{
    meta:
        description = "Detects access token manipulation for privilege escalation"
        severity = "high"
        category = "apt"
        technique = "T1134"  # MITRE ATT&CK: Access Token Manipulation
    strings:
        // Token manipulation APIs
        $token1 = "OpenProcessToken"
        $token2 = "DuplicateTokenEx"
        $token3 = "ImpersonateLoggedOnUser"
        $token4 = "CreateProcessWithToken"
        $token5 = "SetThreadToken"

        // Privilege adjustment
        $priv1 = "AdjustTokenPrivileges"
        $priv2 = "LookupPrivilegeValue"

        // Named privileges
        $privname1 = "SeDebugPrivilege" nocase
        $privname2 = "SeImpersonatePrivilege" nocase
        $privname3 = "SeTcbPrivilege" nocase

    condition:
        3 of ($token*) or
        (1 of ($priv*) and 1 of ($privname*))
}

rule apt_dcsync_attack
{
    meta:
        description = "Detects DCSync attack (domain credential extraction)"
        severity = "critical"
        category = "apt"
        technique = "T1003.006"  # MITRE ATT&CK: OS Credential Dumping: DCSync
    strings:
        // DCSync-specific strings
        $dc1 = "DRS_Get_NC_Changes" nocase
        $dc2 = "DRS_REPL_OBJ" nocase
        $dc3 = "GetNCChanges" nocase

        // Mimikatz DCSync
        $mimi1 = "lsadump::dcsync" nocase
        $mimi2 = "/domain:" nocase
        $mimi3 = "/user:" nocase

        // DRSR protocol
        $drsr1 = "drsuapi.dll" nocase
        $drsr2 = "IDL_DRSGetNCChanges" nocase

    condition:
        1 of ($dc*) or
        ($mimi1 and 1 of ($mimi2, $mimi3)) or
        1 of ($drsr*)
}

rule apt_living_off_the_land_binaries
{
    meta:
        description = "Detects Living-Off-The-Land Binaries (LOLBins) usage"
        severity = "medium"
        category = "apt"
        technique = "T1218"  # MITRE ATT&CK: System Binary Proxy Execution
    strings:
        // Common LOLBins
        $lol1 = "certutil.exe" nocase
        $lol2 = "mshta.exe" nocase
        $lol3 = "regsvr32.exe" nocase
        $lol4 = "rundll32.exe" nocase
        $lol5 = "bitsadmin.exe" nocase
        $lol6 = "msiexec.exe" nocase

        // Suspicious parameters
        $param1 = "-decode" nocase
        $param2 = "-urlcache" nocase
        $param3 = "javascript:" nocase
        $param4 = "vbscript:" nocase
        $param5 = "/i:" nocase

    condition:
        1 of ($lol*) and 1 of ($param*)
}

rule apt_fileless_malware_indicators
{
    meta:
        description = "Detects fileless malware execution techniques"
        severity = "high"
        category = "apt"
        technique = "T1027"  # MITRE ATT&CK: Obfuscated Files or Information
    strings:
        // In-memory execution
        $mem1 = "VirtualAlloc"
        $mem2 = "VirtualProtect"
        $mem3 = "NtAllocateVirtualMemory"

        // Reflective loading
        $refl1 = "LoadLibrary"
        $refl2 = "GetProcAddress"

        // PowerShell fileless
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "IEX" nocase
        $ps3 = "[System.Reflection.Assembly]::Load" nocase

        // Download-execute pattern
        $dl1 = "WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadData" nocase

    condition:
        (all of ($mem*)) or
        (all of ($refl*) and 1 of ($mem*)) or
        (1 of ($ps*) and 1 of ($dl*))
}

rule apt_c2_dns_tunneling
{
    meta:
        description = "Detects DNS tunneling for C2 communication"
        severity = "high"
        category = "apt"
        technique = "T1071.004"  # MITRE ATT&CK: Application Layer Protocol: DNS
    strings:
        // Long DNS queries (base64 encoded data)
        $dns1 = /[a-zA-Z0-9]{30,}\..*\.com/

        // DNS tunneling tools
        $tool1 = "dnscat" nocase
        $tool2 = "iodine" nocase
        $tool3 = "dns2tcp" nocase

        // Unusual TXT record access
        $txt1 = "DnsQuery" nocase
        $txt2 = "DNS_TYPE_TEXT" nocase

    condition:
        1 of ($tool*) or
        ($txt1 and $txt2)
}
