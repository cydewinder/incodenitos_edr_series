// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "Minhook.h"
#include "logger.hpp"
#include "unordered_map"
//look up how these pragma comments work
#if _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// NtAllocateVirtualMemory
// NtProtectVirtualMemory
// enumerate for RWX permissions


//struct to keep track of process info
struct ProcessTrackingInfo {
    bool allocatedExecutableMemory = false; //used virtual allocate memory for something
    bool wroteToExecutableMemory = false; //wrote some information into allocated memory space
    PVOID allocatedBaseAddress = nullptr; //base address of the allocated memory
    SIZE_T allocatedRegionSize = 0; //size of the allocated memory can be used for memory scanning in future
};

//map to track multiple process. Key is PID
static std::unordered_map<DWORD, ProcessTrackingInfo> processTrackingMap;

BOOL Hooked = FALSE;

typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);
//ntprotectvirtualmemory
typedef DWORD(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);
//create variable for the original funtions from ntdll
pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory = nullptr;


DWORD NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect) {

    //check the protect arg for RWX perms
    if (Protect == PAGE_EXECUTE_READWRITE && Hooked == TRUE) {
        DWORD pid = GetProcessId(ProcessHandle);
        if (pid != 0) {
            Logger::LogMessage("PAGE_EXECUTE_READWRITE permission detected in NtAllocateVirtualMemory function call! PID = " + std::to_string(pid));
            if (pid != GetCurrentProcessId()) {
                Logger::LogMessage("Suspicious PAGE_EXECUTE_READWRITE permission detected in NtAllocateVirtualMemory function call! PID = " + std::to_string(pid));
                return NULL; //Don't let the api allocate the memory
            }
            auto& trackingInfo = processTrackingMap[pid];
            trackingInfo.allocatedExecutableMemory = true;
        }
    }

    return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

DWORD NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect) {

    //check the protect arg for RWX perms
    if (NewProtect == PAGE_EXECUTE_READWRITE && Hooked == TRUE) {
        Logger::LogMessage("PAGE_EXECUTE_READWRITE permission detected in NtProtectVirtualMemory function call!");
        //if protection enabled then kill the process (future code)
    }

    return pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

void InitializeHooks() {
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        Logger::LogMessage("minhook init failed. Error code : " + status);
        return;
    }

    if (MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedNtProtectVirtualMemory, (LPVOID*)&pOriginalNtProtectVirtualMemory) != MH_OK) {
        Logger::LogMessage("Failed to hook NtProtectVirtualMemory");
    }

    if (MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedNtAllocateVirtualMemory, (LPVOID*)&pOriginalNtAllocateVirtualMemory) != MH_OK) {
        Logger::LogMessage("Failed to hook NtAllocateVirtualMemory");
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogMessage("Failed to enable hooks.");
        return;
    }

    Logger::LogMessage("Hooks Initialized Successfully");
    Hooked = TRUE;
}



//CreateConsole() no longer needed once the named pipe server is setup in the agent
//void CreateConsole() {
//    FreeConsole();
//
//    if (AllocConsole()) {
//        FILE* file;
//        freopen_s(&file, "CONOUT$", "w", stdout);
//        freopen_s(&file, "CONOUT$", "w", stderr);
//        freopen_s(&file, "CONIN$", "w", stdin);
//
//        std::cout << "Console allocated...." << std::endl;
//    }
//}

DWORD MainFunction(LPVOID lpParam) {
    //create a console
    //CreateConsole(); no longer needed due to named pipe
    //initialize hooks
    InitializeHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Logger::LogMessage("Injected Into Process\n");
        MainFunction(NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}