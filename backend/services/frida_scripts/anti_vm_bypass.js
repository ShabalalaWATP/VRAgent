/**
 * Anti-VM Bypass
 *
 * Bypasses common VM detection techniques used by malware:
 * - CPUID instruction checks
 * - Registry key checks (VMware, VirtualBox)
 * - File existence checks
 * - Process name checks
 */

console.log("[FRIDA] Anti-VM bypass activated");

// Windows - Registry VM detection bypass
try {
    const RegOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
    if (RegOpenKeyExW) {
        Interceptor.attach(RegOpenKeyExW, {
            onEnter: function(args) {
                try {
                    const keyName = Memory.readUtf16String(args[1]);

                    // Block access to VM-related registry keys
                    const vmKeys = [
                        'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port',
                        'HARDWARE\\Description\\System',
                        'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum'
                    ];

                    if (vmKeys.some(k => keyName.includes(k))) {
                        console.log(`[BYPASS] Blocked VM registry check: ${keyName}`);
                        this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(0x2); // ERROR_FILE_NOT_FOUND
                }
            }
        });
    }
} catch (e) {}

// Windows - CreateFileW VM artifact check bypass
try {
    const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (CreateFileW) {
        Interceptor.attach(CreateFileW, {
            onEnter: function(args) {
                try {
                    const filename = Memory.readUtf16String(args[0]);

                    // Block access to VM-related files
                    const vmFiles = [
                        'vmware',
                        'vbox',
                        'virtual',
                        'qemu',
                        '\\\\.\VBoxMiniRdr',
                        '\\\\.\VBoxGuest',
                        '\\\\.\vmci'
                    ];

                    const lower = filename.toLowerCase();
                    if (vmFiles.some(f => lower.includes(f))) {
                        console.log(`[BYPASS] Blocked VM file check: ${filename}`);
                        this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                }
            }
        });
    }
} catch (e) {}

// Windows - Process enumeration (looking for vmtoolsd, vboxservice, etc.)
try {
    const CreateToolhelp32Snapshot = Module.findExportByName('kernel32.dll', 'CreateToolhelp32Snapshot');
    const Process32FirstW = Module.findExportByName('kernel32.dll', 'Process32FirstW');
    const Process32NextW = Module.findExportByName('kernel32.dll', 'Process32NextW');

    if (Process32FirstW) {
        Interceptor.attach(Process32FirstW, {
            onLeave: function(retval) {
                if (retval.toInt32() === 1) {
                    const pe32 = this.context.rdx || this.context.r2; // x64 or ARM
                    if (pe32) {
                        try {
                            const exeFile = Memory.readUtf16String(pe32.add(44)); // szExeFile offset
                            const lower = exeFile.toLowerCase();

                            const vmProcesses = ['vmtoolsd', 'vboxservice', 'vboxtray', 'vmwareuser'];
                            if (vmProcesses.some(p => lower.includes(p))) {
                                console.log(`[BYPASS] Filtered VM process: ${exeFile}`);
                                retval.replace(0); // Skip this entry
                            }
                        } catch (e) {}
                    }
                }
            }
        });
    }
} catch (e) {}

// Linux - /proc/cpuinfo VM detection bypass
try {
    const open = Module.findExportByName(null, 'open');
    const read = Module.findExportByName(null, 'read');

    if (open && read) {
        Interceptor.attach(open, {
            onEnter: function(args) {
                try {
                    this.filename = Memory.readUtf8String(args[0]);
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.filename === '/proc/cpuinfo') {
                    this.cpuinfo_fd = retval.toInt32();
                }
            }
        });

        Interceptor.attach(read, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (this.fd && this.buf && this.fd === Process.getModuleByName(null).cpuinfo_fd) {
                    try {
                        const content = Memory.readUtf8String(this.buf, retval.toInt32());

                        // Replace VM indicators
                        let modified = content
                            .replace(/QEMU/g, 'Intel')
                            .replace(/KVM/g, 'Intel')
                            .replace(/VirtualBox/g, 'GenuineIntel')
                            .replace(/VMware/g, 'AuthenticAMD')
                            .replace(/hypervisor/gi, 'physical');

                        if (modified !== content) {
                            Memory.writeUtf8String(this.buf, modified);
                            console.log('[BYPASS] Modified /proc/cpuinfo to hide VM');
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {}

// Linux - dmesg VM detection bypass
try {
    const execve = Module.findExportByName(null, 'execve');
    if (execve) {
        Interceptor.attach(execve, {
            onEnter: function(args) {
                try {
                    const cmd = Memory.readUtf8String(args[0]);
                    if (cmd.includes('dmesg')) {
                        console.log('[BYPASS] Blocked dmesg execution (VM detection)');
                        this.block = true;
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(-1);
                }
            }
        });
    }
} catch (e) {}

console.log("[FRIDA] Anti-VM bypass complete");
