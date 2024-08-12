import winim
import regex

let BAD_WINDOW_NAMES*: array[10, string] = ["x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida"]
let BAD_DLL_NAMES*: array[15, string] = ["SbieDll.dll", "cmdvrt32.dll", "cmdvrt64.dll", "SxIn.dll", "cockoomon.dll", "vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll", "vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll", "vboxoglfeedbackspu.dll", "vboxoglpackspu.dll", "vboxoglpassthroughspu.dll"]
let BAD_USERNAMES*: array[11, string] = ["Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount"]
let BAD_DRIVER_NAMES*: array[9, string] = ["balloon.sys", "netkvm.sys", "vioinput", "viofs.sys", "vioser.sys", "vboxsf.sys", "vboxguest.sys", "vboxmouse.sys", "vboxwddm.sys"]
let BAD_DEVICE_DRIVER_NAMES*: array[2, string] = ["vid_80ee", "pnp0f03"]
let BAD_SERVICE_NAMES*: array[3, string] = ["vmbus", "VMBusHID", "hyperkbd"]
let GOOD_PARENT_PROCESSES*: array[2, string] = ["explorer.exe", "cmd.exe"]

let BAD_REGEX*: Regex2 = re2("oracle|virtual|innotek|vbox|vmw|vmware|linux|bsd|qemu|seabios|boches")

proc NtSetInformationThread*(thHandle: HANDLE, thInfoClass: THREAD_INFORMATION_CLASS, thInfo: PVOID, thInfoLength: ULONG): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}
proc NtSetDebugFilterState*(componentId: ULONG, level: ULONG, state: WINBOOL): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}
proc NtPowerInformation*(informationLevel: POWER_INFORMATION_LEVEL, inputBuffer: PVOID, inputBufferLength: ULONG, outputBuffer: PVOID, outputBufferLength: ULONG): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}