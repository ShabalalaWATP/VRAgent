/**
 * Windows Registry Monitoring
 *
 * Monitors registry operations for:
 * - Persistence mechanisms (Run keys, services)
 * - Configuration changes
 * - Sensitive data access
 */

console.log("[FRIDA] Registry monitoring activated");

// Registry API hooks
const REGISTRY_APIS = {
    'RegOpenKeyExW': ['advapi32.dll', ['pointer', 'pointer', 'uint', 'uint', 'pointer'], 'long'],
    'RegCreateKeyExW': ['advapi32.dll', ['pointer', 'pointer', 'uint', 'pointer', 'uint', 'uint', 'pointer', 'pointer', 'pointer'], 'long'],
    'RegSetValueExW': ['advapi32.dll', ['pointer', 'pointer', 'uint', 'uint', 'pointer', 'uint'], 'long'],
    'RegQueryValueExW': ['advapi32.dll', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'], 'long'],
    'RegDeleteValueW': ['advapi32.dll', ['pointer', 'pointer'], 'long'],
    'RegDeleteKeyW': ['advapi32.dll', ['pointer', 'pointer'], 'long'],
    'RegCloseKey': ['advapi32.dll', ['pointer'], 'long']
};

// Persistence-related registry keys
const PERSISTENCE_KEYS = [
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunServices',
    'Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
    'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'System\\CurrentControlSet\\Services',
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders'
];

// Track open registry handles
const registryHandles = new Map();

function hookRegOpenKeyExW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    this.hKey = args[0];
                    this.lpSubKey = args[1];
                    this.phkResult = args[4];

                    const subKey = Memory.readUtf16String(this.lpSubKey);
                    this.keyName = subKey;

                    send({
                        type: 'registry_open',
                        operation: 'open',
                        key: subKey,
                        timestamp: Date.now()
                    });

                    console.log(`[REGISTRY] RegOpenKeyExW: ${subKey}`);
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.phkResult) {
                    try {
                        const handle = Memory.readPointer(this.phkResult);
                        registryHandles.set(handle.toString(), this.keyName);
                    } catch (e) {}
                }
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegOpenKeyExW: ${e.message}`);
    }
}

function hookRegCreateKeyExW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegCreateKeyExW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const subKey = Memory.readUtf16String(args[1]);
                    this.keyName = subKey;
                    this.phkResult = args[7];

                    const isPersistence = PERSISTENCE_KEYS.some(k => subKey.includes(k));

                    send({
                        type: 'registry_create',
                        operation: 'create',
                        key: subKey,
                        is_persistence: isPersistence,
                        timestamp: Date.now()
                    });

                    if (isPersistence) {
                        console.log(`[REGISTRY] [PERSISTENCE] RegCreateKeyExW: ${subKey}`);
                    } else {
                        console.log(`[REGISTRY] RegCreateKeyExW: ${subKey}`);
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.phkResult) {
                    try {
                        const handle = Memory.readPointer(this.phkResult);
                        registryHandles.set(handle.toString(), this.keyName);
                    } catch (e) {}
                }
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegCreateKeyExW: ${e.message}`);
    }
}

function hookRegSetValueExW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegSetValueExW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const handle = args[0].toString();
                    const valueName = args[1].isNull() ? '(Default)' : Memory.readUtf16String(args[1]);
                    const type = args[3].toInt32();
                    const data = args[4];
                    const dataSize = args[5].toInt32();

                    const keyName = registryHandles.get(handle) || 'Unknown';
                    const isPersistence = PERSISTENCE_KEYS.some(k => keyName.includes(k));

                    let dataValue = null;
                    try {
                        if (type === 1) { // REG_SZ
                            dataValue = Memory.readUtf16String(data);
                        } else if (type === 4) { // REG_DWORD
                            dataValue = Memory.readU32(data);
                        }
                    } catch (e) {}

                    send({
                        type: 'registry_write',
                        operation: 'set_value',
                        key: keyName,
                        value_name: valueName,
                        value_type: type,
                        value_data: dataValue,
                        data_size: dataSize,
                        is_persistence: isPersistence,
                        timestamp: Date.now()
                    });

                    if (isPersistence) {
                        console.log(`[REGISTRY] [PERSISTENCE] RegSetValueExW: ${keyName}\\${valueName} = ${dataValue}`);
                    } else {
                        console.log(`[REGISTRY] RegSetValueExW: ${keyName}\\${valueName}`);
                    }
                } catch (e) {}
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegSetValueExW: ${e.message}`);
    }
}

function hookRegQueryValueExW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const handle = args[0].toString();
                    const valueName = args[1].isNull() ? '(Default)' : Memory.readUtf16String(args[1]);
                    const keyName = registryHandles.get(handle) || 'Unknown';

                    this.keyName = keyName;
                    this.valueName = valueName;
                    this.lpData = args[4];
                    this.lpType = args[3];
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.lpData && !this.lpData.isNull()) {
                    try {
                        let dataValue = null;
                        const type = this.lpType ? Memory.readU32(this.lpType) : 0;

                        if (type === 1) { // REG_SZ
                            dataValue = Memory.readUtf16String(this.lpData);
                        } else if (type === 4) { // REG_DWORD
                            dataValue = Memory.readU32(this.lpData);
                        }

                        send({
                            type: 'registry_read',
                            operation: 'query_value',
                            key: this.keyName,
                            value_name: this.valueName,
                            value_type: type,
                            value_data: dataValue,
                            timestamp: Date.now()
                        });
                    } catch (e) {}
                }
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegQueryValueExW: ${e.message}`);
    }
}

function hookRegDeleteValueW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegDeleteValueW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const handle = args[0].toString();
                    const valueName = Memory.readUtf16String(args[1]);
                    const keyName = registryHandles.get(handle) || 'Unknown';

                    send({
                        type: 'registry_delete',
                        operation: 'delete_value',
                        key: keyName,
                        value_name: valueName,
                        timestamp: Date.now()
                    });

                    console.log(`[REGISTRY] RegDeleteValueW: ${keyName}\\${valueName}`);
                } catch (e) {}
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegDeleteValueW: ${e.message}`);
    }
}

function hookRegDeleteKeyW() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegDeleteKeyW');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const subKey = Memory.readUtf16String(args[1]);

                    send({
                        type: 'registry_delete',
                        operation: 'delete_key',
                        key: subKey,
                        timestamp: Date.now()
                    });

                    console.log(`[REGISTRY] RegDeleteKeyW: ${subKey}`);
                } catch (e) {}
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegDeleteKeyW: ${e.message}`);
    }
}

function hookRegCloseKey() {
    try {
        const addr = Module.findExportByName('advapi32.dll', 'RegCloseKey');
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                try {
                    const handle = args[0].toString();
                    registryHandles.delete(handle);
                } catch (e) {}
            }
        });
    } catch (e) {
        console.log(`[ERROR] Failed to hook RegCloseKey: ${e.message}`);
    }
}

// Hook all registry APIs
hookRegOpenKeyExW();
hookRegCreateKeyExW();
hookRegSetValueExW();
hookRegQueryValueExW();
hookRegDeleteValueW();
hookRegDeleteKeyW();
hookRegCloseKey();

console.log("[FRIDA] Registry monitoring complete");
