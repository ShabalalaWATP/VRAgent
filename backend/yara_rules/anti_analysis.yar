/*
    Anti-Analysis Detection Rules
    Detects anti-debugging, anti-VM, and anti-sandbox techniques
*/

rule anti_debug_windows
{
    meta:
        description = "Detects Windows anti-debugging techniques"
        severity = "medium"
        category = "anti-analysis"
        technique = "anti-debug"
    strings:
        // IsDebuggerPresent and variants
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "NtQueryInformationProcess"
        $api4 = "OutputDebugString"

        // PEB flags
        $peb1 = "BeingDebugged"
        $peb2 = "NtGlobalFlag"
        $peb3 = "ProcessHeap"

        // Debug registers
        $dr1 = "GetThreadContext"
        $dr2 = "SetThreadContext"
        $dr3 = "CONTEXT_DEBUG_REGISTERS"

        // Timing checks
        $time1 = "GetTickCount"
        $time2 = "QueryPerformanceCounter"
        $time3 = "timeGetTime"
        $time4 = "rdtsc"

        // Exception-based detection
        $except1 = "SetUnhandledExceptionFilter"
        $except2 = "UnhandledExceptionFilter"
        $except3 = { CC }  // int 3 (breakpoint)

        // Hardware breakpoint detection
        $hwbp1 = { 33 C0 64 8B 40 30 }  // mov eax, fs:[0x30] (PEB access)

    condition:
        2 of ($api*) or
        2 of ($peb*) or
        2 of ($dr*) or
        3 of ($time*) or
        2 of ($except*)
}

rule anti_vm_detection
{
    meta:
        description = "Detects anti-VM and virtualization detection"
        severity = "medium"
        category = "anti-analysis"
        technique = "anti-vm"
    strings:
        // VMware detection
        $vm1 = "VMware" nocase
        $vm2 = "VMWARE" nocase
        $vm3 = "vmtoolsd" nocase
        $vm4 = "vmhgfs" nocase
        $vm5 = "vmmouse" nocase
        $vm6 = "VBox" nocase

        // VirtualBox detection
        $vbox1 = "VirtualBox" nocase
        $vbox2 = "VBOX" nocase
        $vbox3 = "VBoxService" nocase
        $vbox4 = "VBoxTray" nocase
        $vbox5 = "VBoxGuest" nocase

        // Hyper-V detection
        $hyperv1 = "Hyper-V" nocase
        $hyperv2 = "vmbus" nocase
        $hyperv3 = "Microsoft Hv" nocase

        // QEMU/KVM detection
        $qemu1 = "QEMU" nocase
        $qemu2 = "BOCHS" nocase
        $qemu3 = "KVMKVMKVM" nocase

        // Generic VM detection
        $generic1 = "VIRTUAL" nocase
        $generic2 = "VMEM" nocase

        // Hardware checks
        $hw1 = "Red Hat VirtIO" nocase
        $hw2 = "VMware SVGA" nocase

        // Registry keys
        $reg1 = "HARDWARE\\Description\\System" nocase
        $reg2 = "SystemBiosVersion" nocase

        // CPU instructions (VM detection)
        $cpuid = { 0F A2 }  // cpuid
        $vmcall = { 0F 01 C1 }  // vmcall

    condition:
        2 of ($vm*) or
        2 of ($vbox*) or
        1 of ($hyperv*) or
        1 of ($qemu*) or
        (1 of ($generic*) and 1 of ($reg*))
}

rule anti_sandbox_checks
{
    meta:
        description = "Detects anti-sandbox and evasion techniques"
        severity = "medium"
        category = "anti-analysis"
        technique = "anti-sandbox"
    strings:
        // Sandbox artifacts
        $sb1 = "sample" nocase
        $sb2 = "malware" nocase
        $sb3 = "sandbox" nocase
        $sb4 = "virus" nocase
        $sb5 = "cuckoo" nocase
        $sb6 = "joe sandbox" nocase

        // Analysis tools
        $tool1 = "wireshark" nocase
        $tool2 = "fiddler" nocase
        $tool3 = "procmon" nocase
        $tool4 = "process monitor" nocase
        $tool5 = "processhacker" nocase
        $tool6 = "ida" nocase
        $tool7 = "ollydbg" nocase
        $tool8 = "x64dbg" nocase

        // Sleep/delay evasion
        $sleep1 = "Sleep"
        $sleep2 = "NtDelayExecution"
        $sleep3 = "WaitForSingleObject"

        // User interaction checks
        $user1 = "GetCursorPos"
        $user2 = "GetLastInputInfo"
        $user3 = "GetForegroundWindow"

        // File system checks
        $fs1 = "GetLogicalDrives"
        $fs2 = "GetDriveType"
        $fs3 = "GetVolumeInformation"

    condition:
        2 of ($sb*) or
        3 of ($tool*) or
        (2 of ($sleep*) and 1 of ($user*))
}

rule anti_disassembly_tricks
{
    meta:
        description = "Detects anti-disassembly and code obfuscation tricks"
        severity = "low"
        category = "anti-analysis"
        technique = "anti-disassembly"
    strings:
        // Opaque predicates
        $junk1 = { 74 00 }  // je $+2 (always false)
        $junk2 = { 75 00 }  // jne $+2 (always true)
        $junk3 = { EB 00 }  // jmp $+2 (nop equivalent)

        // Overlapping instructions
        $overlap1 = { E8 ?? ?? ?? ?? E9 }  // call + jmp overlap

        // Stack manipulation
        $stack1 = { 50 58 }  // push eax; pop eax (nop)
        $stack2 = { 51 59 }  // push ecx; pop ecx (nop)

        // Conditional jumps that always branch
        $always_jmp = { 74 ?? 75 ?? }  // je + jne (both directions)

        // Function return obfuscation
        $ret_obf1 = { 50 C3 }  // push eax; ret (instead of jmp eax)

    condition:
        #junk1 > 5 or
        #junk2 > 5 or
        #junk3 > 10 or
        $overlap1 or
        (#stack1 > 10 and #stack2 > 10)
}

rule packer_armadillo
{
    meta:
        description = "Detects Armadillo packer"
        severity = "low"
        category = "anti-analysis"
        packer = "Armadillo"
    strings:
        $sig1 = "Armadillo" nocase
        $sig2 = "Silicon Realms" nocase
        $sig3 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 }

    condition:
        1 of ($sig*)
}

rule packer_themida
{
    meta:
        description = "Detects Themida/WinLicense packer"
        severity = "low"
        category = "anti-analysis"
        packer = "Themida"
    strings:
        $sig1 = "Themida" nocase
        $sig2 = "WinLicense" nocase
        $sig3 = "Oreans" nocase
        $sig4 = { 8B C0 60 E8 00 00 00 00 5D }

    condition:
        1 of ($sig*)
}

rule packer_aspack
{
    meta:
        description = "Detects ASPack packer"
        severity = "low"
        category = "anti-analysis"
        packer = "ASPack"
    strings:
        $sig1 = "ASPack" nocase
        $sig2 = ".aspack" nocase
        $sig3 = ".adata" nocase
        $sig4 = { 60 E8 ?? ?? ?? ?? 5D 81 ED }

    condition:
        2 of ($sig*)
}

rule packer_vmprotect
{
    meta:
        description = "Detects VMProtect packer"
        severity = "medium"
        category = "anti-analysis"
        packer = "VMProtect"
    strings:
        $sig1 = "VMProtect" nocase
        $sig2 = ".vmp" nocase
        $sig3 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 }

    condition:
        1 of ($sig*)
}

rule packer_mpress
{
    meta:
        description = "Detects MPRESS packer"
        severity = "low"
        category = "anti-analysis"
        packer = "MPRESS"
    strings:
        $sig1 = "MPRESS" nocase
        $sig2 = ".MPRESS1" nocase
        $sig3 = ".MPRESS2" nocase

    condition:
        1 of ($sig*)
}

rule obfuscation_dotfuscator
{
    meta:
        description = "Detects Dotfuscator obfuscation (.NET)"
        severity = "low"
        category = "anti-analysis"
        obfuscator = "Dotfuscator"
    strings:
        $sig1 = "DotfuscatorAttribute" nocase
        $sig2 = "PreEmptive" nocase

    condition:
        1 of ($sig*)
}

rule obfuscation_confuser
{
    meta:
        description = "Detects ConfuserEx obfuscation (.NET)"
        severity = "low"
        category = "anti-analysis"
        obfuscator = "ConfuserEx"
    strings:
        $sig1 = "ConfusedByAttribute" nocase
        $sig2 = "Confuser" nocase

    condition:
        1 of ($sig*)
}

rule code_injection_techniques
{
    meta:
        description = "Detects code injection and hollowing techniques"
        severity = "high"
        category = "anti-analysis"
        technique = "injection"
    strings:
        // Process hollowing
        $hollow1 = "NtUnmapViewOfSection"
        $hollow2 = "ZwUnmapViewOfSection"
        $hollow3 = "VirtualAllocEx"
        $hollow4 = "WriteProcessMemory"
        $hollow5 = "SetThreadContext"
        $hollow6 = "ResumeThread"

        // DLL injection
        $dll1 = "LoadLibrary"
        $dll2 = "GetProcAddress"
        $dll3 = "CreateRemoteThread"

        // APC injection
        $apc1 = "QueueUserAPC"
        $apc2 = "NtQueueApcThread"

        // Atom bombing
        $atom1 = "GlobalAddAtom"
        $atom2 = "GlobalGetAtomName"

    condition:
        (3 of ($hollow*)) or
        (all of ($dll*) and $dll3) or
        1 of ($apc*) or
        2 of ($atom*)
}
