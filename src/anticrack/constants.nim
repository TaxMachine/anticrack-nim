import winim
import regex

let BAD_WINDOW_NAMES*: array[10, string] = ["x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida"]
let BAD_DLL_NAMES*: array[21, string] = ["sbiedll.dll", "cmdvrt32.dll", "cmdvrt64.dll", "sxin.dll", "cockoomon.dll", "vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll", "vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll", "vboxoglfeedbackspu.dll", "vboxoglpackspu.dll", "vboxoglpassthroughspu.dll", "vboxdispd3d.dll", "vboxdx.dll", "vboxgl.dll", "vboxhook.dll", "vboxvboxnine.dll", "vboxsvga.dll"]
let BAD_USERNAMES*: array[11, string] = ["Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount"]
let BAD_DRIVER_NAMES*: array[9, string] = ["balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys", "vboxsf.sys", "vboxguest.sys", "vboxmouse.sys", "vboxwddm.sys"]
let BAD_NAMED_PIPES*: array[8, string] = ["\\\\.\\pipe\\cuckoo", "\\\\.\\HGFS", "\\\\.\\vmci", "\\\\.\\VBoxMiniRdrDN", "\\\\.\\VBoxGuest", "\\\\.\\pipe\\VBoxMiniRdDN", "\\\\.\\VBoxTrayIPC", "\\\\.\\pipe\\VBoxTrayIPC"]
let BAD_PROCESS_NAMES*: array[5, string] = ["vboxservice.exe", "vboxtray.exe", "vgauthservice.exe", "vmusrvc.exe", "qemu-ga.exe"]
let BAD_DEVICE_DRIVER_NAMES*: array[2, string] = ["vid_80ee", "pnp0f03"]
let BAD_SERVICE_NAMES*: array[3, string] = ["vmbus", "VMBusHID", "hyperkbd"]
let GOOD_PARENT_PROCESSES*: array[2, string] = ["explorer.exe", "cmd.exe"]

let BAD_REGEX*: Regex2 = re2("oracle|virtual|innotek|vbox|vmw|vmware|linux|bsd|qemu|seabios|boches")

proc LdrGetDllHandleEx*(flags: ULONG, dllPath: LPWSTR, dllCharacteristics: LPWSTR, libraryName: UNICODE_STRING, dllHandle: ptr HMODULE): UINT {.winapi, stdcall, dynlib: "ntdll", importc.}
proc LdrGetProcedureAddressForCaller*(hModule: HMODULE, procName: ANSI_STRING, procNumber: USHORT, hFunc: ptr HANDLE, flags: ULONG, callback: HANDLE): UINT {.winapi, stdcall, dynlib: "ntdll", importc.}

proc LLGetModuleHandle*(library: string): HMODULE =
    var hModule: HMODULE
    var unicodeString: UNICODE_STRING
    RtlInitUnicodeString(&unicodeString, library)
    LdrGetDllHandleEx(0, NULL, NULL, unicodeString, &hModule)
    return hModule

proc LLGetProcAddress*(hModule: HMODULE, function: string): HANDLE =
    var hFunc: HANDLE
    var unicodeString: UNICODE_STRING
    var ansiString: ANSI_STRING
    RtlInitUnicodeString(&unicodeString, function)
    RtlUnicodeStringToAnsiString(&ansiString, unicodeString, TRUE)
    LdrGetProcedureAddressForCaller(hModule, ansiString, 0, &hFunc, 0, 0)
    return hFunc

proc HiddenCall*[T](lbName: string, procName: string): T {.inline.} =
    var hModule = LLGetModuleHandle(lbName)
    var hFunc = LLGetProcAddress(hModule, procName)
    return cast[T](hFunc)

proc NtSetInformationThread*(thHandle: HANDLE, thInfoClass: THREAD_INFORMATION_CLASS, thInfo: PVOID, thInfoLength: ULONG): NTSTATUS {.cdecl, inline.} =
    return HiddenCall[typeof(NtSetInformationThread)]("ntdll.dll", "NtSetInformationThread")(thHandle, thInfoClass, thInfo, thInfoLength)

proc NtSetDebugFilterState*(componentId: ULONG, level: ULONG, state: WINBOOL): NTSTATUS {.cdecl, inline.} =
    return HiddenCall[typeof(NtSetDebugFilterState)]("ntdll.dll", "NtSetDebugFilterState")(componentId, level, state)

proc NtPowerInformation*(informationLevel: POWER_INFORMATION_LEVEL, inputBuffer: PVOID, inputBufferLength: ULONG, outputBuffer: PVOID, outputBufferLength: ULONG): NTSTATUS {.cdecl, inline.} =
    return HiddenCall[typeof(NtPowerInformation)]("ntdll.dll", "NtPowerInformation")(informationLevel, inputBuffer, inputBufferLength, outputBuffer, outputBufferLength)