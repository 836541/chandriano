from ctypes import *
from ctypes import wintypes

######################################################################################################
# SETUP FILE
# File to setup win32 apis via ctypes
######################################################################################################

#### SETUP das DLLs utilizadas

kernel32   = WinDLL("kernel32",use_last_error=True)
advapi32   = WinDLL("advapi32",use_last_error=True)


#### SETUP Estruturas para as APIs de privilégio de debug

class LUID(Structure):
    _fields_ = [ 
            ("LowPart", wintypes.DWORD),
            ("HighPart", wintypes.LONG),
            ]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
            ("Luid", LUID),
            ("Attributes", wintypes.DWORD)
            ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES),
            ]

#### SETUP API OpenProcessToken()

OpenProcessToken         =  advapi32.OpenProcessToken
OpenProcessToken.restype = wintypes.BOOL

OpenProcessToken.argtypes = [

         wintypes.HANDLE,     #[in] HANDLE ProcessHandle,
         wintypes.DWORD,      #[in] DWORD DesiredAcess,
         wintypes.PHANDLE,    #[out] PHANDLE TokenHandle,
  ]
       

#### SETUP API LookupPrivilegeValueA()

LookupPrivilegeValueA          = advapi32.LookupPrivilegeValueA 
LookupPrivilegeValueA.restype  = wintypes.BOOL
LookupPrivilegeValueA.argtypes = [

         wintypes.LPCSTR,         # [in, optional] LPCSTR lpSystemName,
         wintypes.LPCSTR,         # [in]           LPCSTR lpName,
         POINTER(LUID),           # [out]          PLUID  lpLuid,

  ]

#### SETUP API AdjustTokenPrivileges

SE_PRIVILEGE_ENABLED = 0x00000002

AdjustTokenPrivileges          = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.restype  = wintypes.BOOL
AdjustTokenPrivileges.argtypes = [

        wintypes.HANDLE,          # [in] HANDLE     TokenHandle,
        wintypes.BOOL,            # [in] BOOL       DisableAllPrivileges,
        POINTER(TOKEN_PRIVILEGES),# [in, optional]  NewState,
        wintypes.DWORD,           # [in] DWORD      BufferLength,
        POINTER(TOKEN_PRIVILEGES),# [out, optional] PreviousState,
        wintypes.PDWORD,          # [out, optional] ReturnLength,

        ]

#### SETUP API CloseHandle

CloseHandle         = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes= [ wintypes.HANDLE ] # [in] HANDLE hObject



#### SETUP API GetCurrentProcess()
GetCurrentProcess         = kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE
  

TOKEN_ADJUST_PRIVILEGES = 0x0020          # Flags pro parâmetro DesiredAcess transformadas em DWORD
TOKEN_QUERY             = 0x0008


#### SETUP API OpenProcess()

OpenProcess          = kernel32.OpenProcess
OpenProcess.restype  = wintypes.HANDLE
OpenProcess.argtypes = [

        wintypes.DWORD,         # [in] DWORD dwDesiredAcess
        wintypes.BOOL,          # [in] BOOL bInheritHandle
        wintypes.DWORD          # [in] DWORD dwProcessId

 ]

PROCESS_VM_READ           = 0x0010  # dwDesiredAcess é datatype DWORD, por isso essa conversão das flags
PROCESS_QUERY_INFORMATION = 0X0400


#### SETUP API VirtualQueryEx

VirtualQueryEx32         = kernel32.VirtualQueryEx
VirtualQueryEx64         = kernel32.VirtualQueryEx
VirtualQueryEx32.restype = c_size_t
VirtualQueryEx64.restype = c_size_t

'''class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", c_ulong),
        ("__alignment1", c_ulong),
        ("RegionSize", c_ulonglong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ("__alignment2", c_ulong),
    ]'''

class MEMORY_BASIC_INFORMATION64(Structure):
     _fields_ = [
                ("BaseAddress", wintypes.LPVOID),
                ("AllocationBase", wintypes.LPVOID),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
                ]

class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAdress", wintypes.DWORD),
        ("AllocationBase", wintypes.DWORD),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


VirtualQueryEx32.argtypes = [

         wintypes.HANDLE,                   # [in]  HANDLE                    hProcess
         wintypes.LPCVOID,                  # [in]  LPCVOID                   lpAdress
         POINTER(MEMORY_BASIC_INFORMATION32), # [out] PMEMORY_BASIC_INFORMATION lpBuffer
         c_size_t,                          # [in]  SIZE_T                    lpBuffer

         ]

VirtualQueryEx64.argtypes = [

         wintypes.HANDLE,                   # [in]  HANDLE                    hProcess
         wintypes.LPCVOID,                  # [in]  LPCVOID                   lpAdress
         POINTER(MEMORY_BASIC_INFORMATION64), # [out] PMEMORY_BASIC_INFORMATION lpBuffer
         c_size_t,                          # [in]  SIZE_T                    lpBuffer

         ]


#### Setup da API ReadProcessMemory()

ReadProcessMemory          = kernel32.ReadProcessMemory
ReadProcessMemory.restype  = wintypes.BOOL
ReadProcessMemory.argtypes = [
   
    wintypes.HANDLE,    # [in]  HANDLE    hProcess
    wintypes.LPCVOID,   # [in]  LPCVOID   lpBaseAdress
    wintypes.LPVOID,    # [out] LPVOID    lpBuffer
    c_size_t,           # [in]  SIZE_T    nSize
    POINTER(c_size_t),  # [out] SIZE_T   *lpNumberOfBytesRead   

    ]

MEM_COMMIT = 0x00001000

#### Setup da API GetSystemInfo()

class SYSTEM_INFO_Structure(Structure):
    _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ]

class SYSTEM_INFO_Union(Union):
    _fields_ = [
            ("dwOemId", wintypes.DWORD),
            ("struct", SYSTEM_INFO_Structure)
            ]

class SYSTEM_INFO(Structure):
    _fields_ = [
            ("union", SYSTEM_INFO_Union),
            ("dwPageSize", wintypes.WORD),
            ("lpMinimumApplicationAdress", wintypes.LPVOID),
            ("lpMaximumApplicationAdress", wintypes.LPVOID),
            ("dwActiveProcessorMask", c_longlong),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
            ]

GetSystemInfo          = kernel32.GetSystemInfo
GetSystemInfo.restype  = c_void_p
GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)] # [out] LPSYSTEM_INFO lpSystemInfo

#### Setup API VirtualAlloc

VirtualAlloc          = kernel32.VirtualAlloc
VirtualAlloc.restype  = wintypes.LPVOID
VirtualAlloc.argtypes = [

        wintypes.LPVOID,   # [in, optional] LPVOID lpAdress,
        c_size_t,          # [in]           SIZE_T dwSize,
        wintypes.DWORD,    # [in]           DWORD  flAllocationType,
        wintypes.DWORD,    # [in]           DWORD  flProtect

        ]

#### Setup API GetLastError()

LastError            = kernel32.GetLastError
LastError.restype    = wintypes.DWORD
GetLastError         = LastError()

#### Setup API VirtualFree()

VirtualFree          = kernel32.VirtualFree
VirtualFree.restype  = wintypes.BOOL
VirtualFree.argtypes = [

    wintypes.LPVOID,   # [in] LPVOID lpAdress
    c_size_t,          # [in] SIZE_T dwSize
    wintypes.DWORD,    # [in] DWORD  dwFreeType

]

MEM_RELEASE = 0x00008000

#### Setup API IsWow64Process

IsWow64Process         = kernel32.IsWow64Process
IsWow64Process.restype = wintypes.BOOL
IsWow64Process.argtypes= [

    wintypes.HANDLE,  # [in]  HANDLE hProcess
    wintypes.PBOOL,   # [out] PBOOL  Wow64Process

]

#### Setup API VirtualProtectEX

VirtualProtectEx          = kernel32.VirtualProtectEx
VirtualProtectEx.restype  = wintypes.BOOL
VirtualProtectEx.argtypes = [

    wintypes.HANDLE,
    wintypes.LPVOID,
    c_size_t,
    wintypes.DWORD,
    wintypes.PDWORD,

]

#### Setup API TerminateProcess

GetExitCodeProcess          = kernel32.GetExitCodeProcess
GetExitCodeProcess.restype  = wintypes.BOOL
GetExitCodeProcess.argtypes = [ wintypes.HANDLE, wintypes.LPDWORD]

TerminateProcess          = kernel32.TerminateProcess
TerminateProcess.restype  = wintypes.BOOL 
TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]












        
