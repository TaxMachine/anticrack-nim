import winim
import winim/com
import os
import regex
import strutils
import registry
import constants
import algorithm

type
    WMITable = object
        Request*: string
        Components*: seq[string]

proc CheckDirectories*(): bool =
    if dirExists("C:\\Program Files\\Oracle\\VirtualBox Guest Additions"):
        return true

proc CheckWMI*(): bool =
    var wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2")
    var table: seq[WMITable] = @[]
    table.add(WMITable(Request: "SELECT SMBIOSBIOSVersion, Manufacturer FROM Win32_BIOS WHERE PrimaryBIOS = 'True'", Components: @["SMBIOSBIOSVersion", "Manufacturer"]))
    table.add(WMITable(Request: "SELECT DeviceID from Win32_CDROMDrive WHERE DriveIntegrity = 'True'", Components: @["DeviceID"]))
    table.add(WMITable(Request: "SELECT Manufacturer, Model, SystemFamily FROM Win32_ComputerSystem WHERE Status = 'Ok'", Components: @["Manufacturer", "SystemFamily", "Model"]))
    table.add(WMITable(Request: "SELECT Model FROM Win32_DiskDrive WHERE Status = 'Ok'", Components: @["Model"]))
    table.add(WMITable(Request: "SELECT Name FROM CIM_PhysicalConnector", Components: @["Name"]))
    table.add(WMITable(Request: "SELECT Manufacturer, DeviceLocator FROM CIM_PhysicalComponent WHERE DeviceLocator = 'DIMM 0'", Components: @["Manufacturer"]))
    table.add(WMITable(Request: "SELECT Vendor FROM Win32_ComputerSystemProduct", Components: @["Vendor"]))
    table.add(WMITable(Request: "SELECT DeviceName FROM Win32_DisplayConfiguration", Components: @["DeviceName"]))
    table.add(WMITable(Request: "SELECT Manufacturer FROM CIM_Chip", Components: @["Manufacturer"]))
    
    for entry in table:
        for i in wmi.ExecQuery(entry.Request):
            for component in entry.Components:
                if ($i[component]).toLowerAscii().contains(BAD_REGEX):
                    return true

proc CheckRegistry*(): bool =
    var REG = "SYSTEM\\HardwareConfig\\Current"
    var REG_KEYS: array[6, string] = ["BaseBoardManufacturer", "BaseBoardProduct", "SystemFamily", "BIOSVendor", "SystemManufacturer", "SystemProductName"]

    for i in REG_KEYS:
        if getUnicodeValue(REG, i, registry.HKEY_LOCAL_MACHINE).toLowerAscii.contains(BAD_REGEX):
            return true

proc CheckMemoryCaching*(): bool =
    var wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2")
    for i in wmi.ExecQuery("SELECT Name FROM Win32_CacheMemory"):
        return false

{.push stackTrace:off.}
proc getCpuCycles(): uint64 =
    asm """
    .intel_syntax noprefix

    lfence

    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rdi, rax

    cpuid

    lfence

    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rdi

    mov %0, rax

    .att_syntax
    :"=r"(`result`)
    :
    : "rdx", "rcx", "rax", "rbx", "rdi"
    """
{.pop.}

proc CheckCPUCyclesAverage*(): bool =
    var cycles: seq[uint64]

    let
        L = 5
        Samples = 100
        H = 5
        Threshold: uint64 = 10000

    for i in 0..(L+H+Samples):
        var counter = getCpuCycles()
        cycles.add(counter)

    cycles.sort(cmp)
    let cyclesWithoutOutliners = cycles[L..<(L+Samples)]

    var sum: uint64
    for cycle in cyclesWithoutOutliners:
        sum = sum + cycle

    var clockCycle: uint64 = sum div cast[uint64](len(cyclesWithoutOutliners))

    return clockCycle > Threshold


proc CheckDrivers*(): bool =
    var drivers: array[1024, LPVOID]
    var cb: DWORD

    if EnumDeviceDrivers(addr drivers[0], cast[DWORD](sizeof(drivers)), &cb) == TRUE and cb < sizeof(drivers):
        var count = DWORD(cb / sizeof(drivers[0]))
        var buffer: array[1024, WCHAR]

        for i in 0 ..< count:
            if GetDeviceDriverBaseName(drivers[i], cast[LPWSTR](addr buffer[0]), 1024) != 0:
                let driverName = ($cast[WideCString](addr buffer[0])).toLowerAscii()
                for badDriver in BAD_DRIVER_NAMES:
                    if driverName == badDriver:
                        return true

proc CheckPowerState*(): bool =
    var state: SYSTEM_POWER_CAPABILITIES
    if NtPowerInformation(systemPowerCapabilities, NULL, 0, &state, ULONG(sizeof(SYSTEM_POWER_CAPABILITIES))) != STATUS_SUCCESS:
        return false

    var isLaptop: bool = bool(state.SystemBatteriesPresent or state.LidPresent)

    if isLaptop and not state.SystemS2 == FALSE and state.SystemS3 == TRUE and state.SystemS4 == FALSE and state.SystemS5 == TRUE:
        return true

    if state.HiberFilePresent == FALSE:
        return true

    if state.RtcWake == 0:
        return true

proc CheckScreenResolutions*(): bool =
    if GetSystemMetrics(SM_CMONITORS) != 1:
        return false

    let commonHeights: array[5, int] = [1080, 768, 900, 864, 768]
    let commonWidths: array[5, int] = [1920, 1366, 1440, 1536, 1024]

    const SM_CYVIRTUALSCREEN = 79
    const SM_CXVIRTUALSCREEN = 78

    var height = GetSystemMetrics(SM_CYVIRTUALSCREEN)
    var width = GetSystemMetrics(SM_CXVIRTUALSCREEN)

    var found = false

    for h in commonHeights:
        if h == height:
            for w in commonWidths:
                if w == width:
                    found = true
                    break
            break

    return (not found)

proc CheckDeviceDrivers*(): bool =
    var devices: UINT
    var pDeviceList: ptr RAWINPUTDEVICELIST
    var deviceDriversList: seq[RAWINPUTDEVICELIST]

    while true:
        if GetRawInputDeviceList(NULL, &devices, UINT(sizeof(RAWINPUTDEVICELIST))) != 0:
            break

        if devices == 0:
            break

        pDeviceList = cast[ptr RAWINPUTDEVICELIST](alloc(sizeof(RAWINPUTDEVICELIST) * int(devices)))

        if pDeviceList == NULL:
            break

        devices = GetRawInputDeviceList(pDeviceList, &devices, UINT(sizeof(RAWINPUTDEVICELIST)))
        if devices == UINT.high:
            dealloc(pDeviceList)
            continue

        deviceDriversList = newSeq[RAWINPUTDEVICELIST](devices)
        copyMem(addr deviceDriversList[0], pDeviceList, sizeof(RAWINPUTDEVICELIST) * int(devices))
        dealloc(pDeviceList)
        break

    if pDeviceList == nil:
        dealloc(pDeviceList)
        return false

    for i in 0 ..< devices:
        var numChars: UINT
        GetRawInputDeviceInfoW(deviceDriversList[i].hDevice, RIDI_DEVICENAME, NULL, &numChars)

        var wDriverName: array[1024, WCHAR]
        GetRawInputDeviceInfoW(deviceDriversList[i].hDevice, RIDI_DEVICENAME, cast[LPWSTR](addr wDriverName[0]), &numChars)
        
        for badDevice in BAD_DEVICE_DRIVER_NAMES:
            let driverName = ($cast[WideCString](addr wDriverName[0])).toLowerAscii()
            if driverName.toLowerAscii().contains(badDevice):
                dealloc(pDeviceList)
                return true

    dealloc(pDeviceList)