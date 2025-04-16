#pragma once

#include <windows.h>

//    
#ifdef PROCESSMONITOR_EXPORTS
#define PROCESSMONITOR_API __declspec(dllexport)
#else
#define PROCESSMONITOR_API __declspec(dllimport)
#endif

const int MAX_PROCESSES = 2048;
const int MAX_THREADS = 4096;

typedef struct {
    DWORD pid;
    WCHAR name[MAX_PATH];
    double cpuUsage;
    SIZE_T memoryUsage;        //    (working set)
    SIZE_T privateBytes;       //   (private working set)
    SIZE_T pagefileUsage;      //   
    ULONGLONG readBytes;       //  
    ULONGLONG writeBytes;      //  
    double diskUsage;          //   (/)
    ULONGLONG creationTime;
    ULONGLONG exitTime;
    ULONGLONG kernelTime;
    ULONGLONG userTime;
    DWORD priority;
    DWORD threadCount;
} ProcessInfo;

typedef struct {
    DWORD threadId;
    DWORD processId;
    DWORD priority;
    ULONGLONG kernelTime;
    ULONGLONG userTime;
    DWORD state;
} ThreadInfo;

#ifdef __cplusplus
extern "C" {
#endif

    PROCESSMONITOR_API BOOL PM_Initialize();
    PROCESSMONITOR_API void PM_GetProcesses(ProcessInfo* processes, int* count);
    PROCESSMONITOR_API BOOL PM_TerminateProcess(DWORD pid);
    PROCESSMONITOR_API BOOL PM_CreateProcess(LPCWSTR path);
    PROCESSMONITOR_API BOOL PM_SetProcessPriority(DWORD pid, DWORD priority);
    PROCESSMONITOR_API void PM_GetThreads(DWORD processId, ThreadInfo* threads, int* count);
    PROCESSMONITOR_API BOOL PM_GetLastError(LPWSTR errorMessage, DWORD* errorCode);
    PROCESSMONITOR_API void PM_Cleanup();

    // Проверка прав администратора
    PROCESSMONITOR_API bool PM_IsAdmin();

    // Запрос прав администратора
    PROCESSMONITOR_API bool PM_RequestAdminRights(const wchar_t* executablePath, const wchar_t* commandLine);

#ifdef __cplusplus
}
#endif // PROCESS_MONITOR_WIN32_H