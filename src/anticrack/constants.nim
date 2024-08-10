import winim

let BAD_WINDOW_NAMES*: array[10, string] = ["x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida"]
let GOOD_PARENT_PROCESSES*: array[2, string] = ["explorer.exe", "cmd.exe"]

proc NtSetInformationThread*(thHandle: HANDLE, thInfoClass: THREAD_INFORMATION_CLASS, thInfo: PVOID, thInfoLength: ULONG): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}
proc NtSetDebugFilterState*(componentId: ULONG, level: ULONG, state: WINBOOL): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}