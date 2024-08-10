import winim
import random
import strutils

import constants

proc CloseInvalidHandle*(): bool =
  return NtClose(cast[HANDLE](0x1231222)) != STATUS_SUCCESS

proc CloseProtectedHandle*(): bool =
  randomize()
  var lpName: LPCSTR = $rand(9999999)
  var hMutex = CreateMutexA(NULL, FALSE, lpName)
  SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)
  var success = NtClose(hMutex)
  result = success != STATUS_SUCCESS
  SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0)
  NtClose(hMutex)

proc GetProcessDebugFlag*(): bool =
  var procDebugFlags = 0
  NtQueryInformationProcess(GetCurrentProcess(), processDebugFlags, cast[PVOID](&procDebugFlags), cast[ULONG](sizeof(uint)), NULL)
  return procDebugFlags == 0

proc GetDebugPort*(): bool =
  var debuggerPresent: uint = 0
  var size = sizeof(uint)
  when defined(amd64):
    size = sizeof(uint) * 2
  NtQueryInformationProcess(GetCurrentProcess(), processDebugPort, cast[PVOID](&debuggerPresent), cast[ULONG](size), NULL)
  return debuggerPresent != 0

proc GetProcessDebugHandle*(): bool =
  var hDebugObject: uint = 0
  var size = sizeof(uint)
  when defined(amd64):
    size = sizeof(uint) * 2
  NtQueryInformationProcess(GetCurrentProcess(), processDebugObjectHandle, cast[PVOID](&hDebugObject), cast[ULONG](size), NULL)
  return hDebugObject != 0

proc PatchBreakpoint*(): bool =
  var ntDllModule = GetModuleHandle("ntdll.dll")
  var dbgUiRemoteBreakinAddr = GetProcAddress(ntDllModule, "DbgUiRemoteBreakin")
  var dbgBreakPointAddr = GetProcAddress(ntDllModule, "DbgBreakPoint")

  var int3InvalidCode: seq[byte] = @[ 0xCC ]
  var retCode: seq[byte] = @[ 0xC3 ]

  var statusUiRemote = WriteProcessMemory(GetCurrentProcess(), dbgUiRemoteBreakinAddr, cast[LPCVOID](&int3InvalidCode), 1, NULL)
  var statusBreakPoint = WriteProcessMemory(GetCurrentProcess(), dbgBreakPointAddr, cast[LPCVOID](&retCode), 1, NULL)
  return statusUiRemote and statusBreakPoint

proc KillBadWindows*(): void =
  var window: HWND = FindWindowA(NULL, NULL)
  if window == 0:
    return
  while window != 0:
    var title: string
    GetWindowTextA(window, title, 256)
    for bad in BAD_WINDOW_NAMES:
      if bad in title.toLower():
        CloseWindow(window)
    window = GetWindow(window, GW_HWNDNEXT)

proc HideThreads*(): bool =
  var anyThreadFailed = false
  var pid = GetCurrentProcessId()
  var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
  if hSnap == INVALID_HANDLE_VALUE:
    return true
  defer: CloseHandle(hSnap)

  var te32: THREADENTRY32
  te32.dwSize = cast[DWORD](sizeof(THREADENTRY32))

  if Thread32First(hSnap, &te32) == 0:
    return false

  while Thread32Next(hSnap, &te32) != 0:
    if te32.th32OwnerProcessID != pid:
      continue
    var hThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, te32.th32ThreadID)
    if hThread == INVALID_HANDLE_VALUE:
      continue

    var status = NtSetInformationThread(hThread, threadPerformanceCount, NULL, 0)
    NtClose(hThread)
    if status != STATUS_SUCCESS:
      anyThreadFailed = true
  
  return (not anyThreadFailed)

proc CheckTickCount*(): bool =
  var start = GetTickCount()
  Sleep(10)
  return (GetTickCount() - start) > 10

proc HardwareRegistersBreakpoint*(): bool =
  var ctx: CONTEXT
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  var hThread = GetCurrentThread()
  defer: CloseHandle(hThread)
  if GetThreadContext(hThread, cast[PCONTEXT](&ctx)) == 0:
    return false
  if ctx.Dr0 != 0x00 or ctx.Dr1 != 0x00 or ctx.Dr2 != 0x00 or ctx.Dr3 != 0x00:
    return true

proc CheckParentProcess*(): bool =
  var pbi: PROCESS_BASIC_INFORMATION
  if NtQueryInformationProcess(GetCurrentProcess(), processBasicInformation, cast[PVOID](&pbi), cast[ULONG](sizeof(PROCESS_BASIC_INFORMATION)), cast[PULONG](0)) != STATUS_SUCCESS:
    return false
  
  var parentPid = cast[DWORD](pbi.InheritedFromUniqueProcessId)
  if parentPid == 0:
    return false

  var hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, parentPid)
  var filenameBuf: LPSTR
  var size: array[256, int32]
  size[0] = 256
  QueryFullProcessImageNameA(hParentProcess, 0, filenameBuf, cast[PDWORD](&size))
  for goodproc in GOOD_PARENT_PROCESSES:
    if ($filenameBuf).endsWith(goodproc):
      return false
  return true

proc SetDebugFilter*(): bool =
  return NtSetDebugFilterState(0, 0, TRUE) == STATUS_SUCCESS