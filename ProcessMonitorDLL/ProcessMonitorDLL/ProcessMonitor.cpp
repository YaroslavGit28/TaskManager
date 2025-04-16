#include "pch.h"
#include "ProcessMonitor.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

#define PROCESSMONITOR_EXPORTS

// ��������� ��� �������� ������
typedef struct {
    DWORD pid;
    ULONGLONG kernelTime;
    ULONGLONG userTime;
    double cpuUsage;
} ProcessTimeInfo;

typedef struct {
    DWORD pid;
    ULONGLONG lastReadBytes;
    ULONGLONG lastWriteBytes;
    double diskUsage;
} ProcessDiskInfo;

// ���������� ����������
static ProcessTimeInfo* g_processTimes = NULL;
static ProcessDiskInfo* g_diskInfo = NULL;
static int g_processTimesCount = 0;
static int g_diskInfoCount = 0;
static ULONGLONG g_lastUpdateTime = 0;
static DWORD g_processorCount = 0;
static PDH_HQUERY g_cpuQuery = NULL;
static PDH_HCOUNTER g_cpuTotal = NULL;
static DWORD g_lastError = 0;
static WCHAR g_lastErrorMessage[256] = { 0 };
static MEMORYSTATUSEX g_memoryStatus = { sizeof(MEMORYSTATUSEX) };

// ��������������� �������
static void SetLastError(DWORD errorCode, const WCHAR* message) {
    g_lastError = errorCode;
    wcscpy_s(g_lastErrorMessage, _countof(g_lastErrorMessage), message);
}

static int FindProcessIndex(DWORD pid) {
    for (int i = 0; i < g_processTimesCount; i++) {
        if (g_processTimes[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

static int FindDiskInfoIndex(DWORD pid) {
    for (int i = 0; i < g_diskInfoCount; i++) {
        if (g_diskInfo[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

static double CalculateProcessCpuUsage(ULONGLONG oldKernelTime, ULONGLONG oldUserTime,
    ULONGLONG newKernelTime, ULONGLONG newUserTime,
    ULONGLONG timeDelta) {
    if (timeDelta == 0) return 0.0;

    ULONGLONG kernelDiff = newKernelTime - oldKernelTime;
    ULONGLONG userDiff = newUserTime - oldUserTime;
    ULONGLONG totalDiff = kernelDiff + userDiff;

    double cpuUsage = (double)totalDiff / (double)timeDelta * 100.0;
    cpuUsage /= g_processorCount;

    if (cpuUsage < 0.0) cpuUsage = 0.0;
    if (cpuUsage > 100.0) cpuUsage = 100.0;

    return cpuUsage;
}

// �������� �������
BOOL PM_Initialize() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    g_processorCount = sysInfo.dwNumberOfProcessors;

    g_processTimes = (ProcessTimeInfo*)calloc(MAX_PROCESSES, sizeof(ProcessTimeInfo));
    g_diskInfo = (ProcessDiskInfo*)calloc(MAX_PROCESSES, sizeof(ProcessDiskInfo));

    if (!g_processTimes || !g_diskInfo) {
        SetLastError(ERROR_OUTOFMEMORY, L"�� ������� �������� ������");
        return FALSE;
    }

    // ������������� PDH ��� ������ ������������� CPU
    PDH_STATUS status = PdhOpenQuery(NULL, 0, &g_cpuQuery);
    if (status == ERROR_SUCCESS) {
        const WCHAR* counterPaths[] = {
            L"\\Processor(_Total)\\% Processor Time",
            L"\\Processor Information(_Total)\\% Processor Time",
            L"\\���������(_Total)\\% ������������� ����������"
        };

        for (int i = 0; i < _countof(counterPaths); i++) {
            status = PdhAddCounter(g_cpuQuery, counterPaths[i], 0, &g_cpuTotal);
            if (status == ERROR_SUCCESS) {
                PdhCollectQueryData(g_cpuQuery);
                break;
            }
        }
    }

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    g_lastUpdateTime = *(ULONGLONG*)&ftNow;

    // �������� ����� ���������� � ������
    GlobalMemoryStatusEx(&g_memoryStatus);

    return TRUE;
}

static void UpdateProcessTimes(ProcessInfo* processes, int count, ULONGLONG currentTime) {
    if (g_processTimes) {
        free(g_processTimes);
    }

    g_processTimes = (ProcessTimeInfo*)calloc(count, sizeof(ProcessTimeInfo));
    if (!g_processTimes) return;

    for (int i = 0; i < count; i++) {
        g_processTimes[i].pid = processes[i].pid;
        g_processTimes[i].kernelTime = processes[i].kernelTime;
        g_processTimes[i].userTime = processes[i].userTime;
        g_processTimes[i].cpuUsage = processes[i].cpuUsage;
    }

    g_processTimesCount = count;
    g_lastUpdateTime = currentTime;
}

void PM_GetProcesses(ProcessInfo* processes, int* count) {
    if (!processes || !count) {
        SetLastError(ERROR_INVALID_PARAMETER, L"Invalid parameters");
        return;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        SetLastError(GetLastError(), L"CreateToolhelp32Snapshot failed");
        *count = 0;
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG now = *(ULONGLONG*)&ftNow;
    ULONGLONG deltaTime = now - g_lastUpdateTime;
    if (deltaTime < 1000000) deltaTime = 1000000;

    GlobalMemoryStatusEx(&g_memoryStatus);

    int index = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (index >= MAX_PROCESSES) break;

            // ������ ��������� ������� ����������
            ZeroMemory(&processes[index], sizeof(ProcessInfo));
            processes[index].pid = pe.th32ProcessID;
            wcscpy_s(processes[index].name, _countof(processes[index].name), pe.szExeFile);
            processes[index].threadCount = pe.cntThreads;

            // �������� ������� ������� � ������� �������� ����
            HANDLE hProcess = NULL;
            DWORD accessFlags[] = {
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_QUERY_INFORMATION
            };

            for (DWORD i = 0; i < _countof(accessFlags) && !hProcess; i++) {
                hProcess = OpenProcess(accessFlags[i], FALSE, pe.th32ProcessID);
            }

            if (hProcess) {
                // �������� ���������� � ������
                PROCESS_MEMORY_COUNTERS_EX pmc;
                pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX);
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    processes[index].memoryUsage = pmc.WorkingSetSize;
                    processes[index].privateBytes = pmc.PrivateUsage;
                    processes[index].pagefileUsage = pmc.PagefileUsage;
                }

                // �������� CPU �����
                FILETIME ftCreate, ftExit, ftKernel, ftUser;
                if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                    processes[index].kernelTime = *(ULONGLONG*)&ftKernel;
                    processes[index].userTime = *(ULONGLONG*)&ftUser;

                    // ��������� �������� CPU
                    int timeIndex = FindProcessIndex(pe.th32ProcessID);
                    if (timeIndex >= 0) {
                        double cpuUsage = CalculateProcessCpuUsage(
                            g_processTimes[timeIndex].kernelTime,
                            g_processTimes[timeIndex].userTime,
                            processes[index].kernelTime,
                            processes[index].userTime,
                            deltaTime
                        );
                        processes[index].cpuUsage = cpuUsage;
                    }
                }

                // �������� ����������
                IO_COUNTERS ioCounters;
                if (GetProcessIoCounters(hProcess, &ioCounters)) {
                    processes[index].readBytes = ioCounters.ReadTransferCount;
                    processes[index].writeBytes = ioCounters.WriteTransferCount;
                }

                // ���������
                processes[index].priority = GetPriorityClass(hProcess);

                CloseHandle(hProcess);
            }

            index++;
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    *count = index;

    // ��������� ������� ��� CPU ��������
    UpdateProcessTimes(processes, *count, now);
}



BOOL PM_SetProcessPriority(DWORD pid, DWORD priority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) {
        SetLastError(GetLastError(), L"�� ������� ������� �������");
        return FALSE;
    }

    BOOL result = SetPriorityClass(hProcess, priority);
    if (!result) {
        SetLastError(GetLastError(), L"�� ������� ���������� ���������");
    }

    CloseHandle(hProcess);
    return result;
}

void PM_GetThreads(DWORD processId, ThreadInfo* threads, int* count) {
    if (!threads || !count) {
        SetLastError(ERROR_INVALID_PARAMETER, L"�������� ���������");
        return;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        SetLastError(GetLastError(), L"�� ������� ������� ������ �������");
        *count = 0;
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    int index = 0;
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                threads[index].threadId = te.th32ThreadID;
                threads[index].processId = te.th32OwnerProcessID;
                threads[index].priority = te.tpBasePri;
                threads[index].state = 0; // �� ���������

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    FILETIME ftCreate, ftExit, ftKernel, ftUser;
                    if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                        threads[index].kernelTime = *(ULONGLONG*)&ftKernel;
                        threads[index].userTime = *(ULONGLONG*)&ftUser;
                    }

                    // ����������� ��������� ������ (���������)
                    DWORD suspendCount = SuspendThread(hThread);
                    if (suspendCount == (DWORD)-1) {
                        // ������ - �����, ��������, ��������
                        threads[index].state = 2; // Terminated
                    }
                    else {
                        if (suspendCount > 0) {
                            threads[index].state = 1; // Suspended
                        }
                        else {
                            threads[index].state = 0; // Running
                        }
                        ResumeThread(hThread); // ��������������� ���������
                    }

                    CloseHandle(hThread);
                }
                index++;
                if (index >= MAX_THREADS) break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    *count = index;
}

BOOL PM_TerminateProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        SetLastError(GetLastError(), L"�� ������� ������� �������");
        return FALSE;
    }

    BOOL result = TerminateProcess(hProcess, 0);
    if (!result) {
        SetLastError(GetLastError(), L"�� ������� ��������� �������");
    }

    CloseHandle(hProcess);
    return result;
}

BOOL PM_CreateProcess(LPCWSTR path) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(
        path,
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        SetLastError(GetLastError(), L"�� ������� ������� �������");
    }

    return success;
}

BOOL PM_GetLastError(LPWSTR errorMessage, DWORD* errorCode) {
    if (!errorMessage || !errorCode) {
        return FALSE;
    }

    wcscpy_s(errorMessage, 256, g_lastErrorMessage);
    *errorCode = g_lastError;
    return TRUE;
}

void PM_Cleanup() {
    if (g_cpuQuery) {
        PdhCloseQuery(g_cpuQuery);
        g_cpuQuery = NULL;
    }

    if (g_processTimes) {
        free(g_processTimes);
        g_processTimes = NULL;
    }

    if (g_diskInfo) {
        free(g_diskInfo);
        g_diskInfo = NULL;
    }

    g_processTimesCount = 0;
    g_diskInfoCount = 0;
    g_lastUpdateTime = 0;
    g_processorCount = 0;
    g_lastError = 0;
    ZeroMemory(g_lastErrorMessage, sizeof(g_lastErrorMessage));
}

// Проверка прав администратора
bool PM_IsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
        {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

// Запрос прав администратора
bool PM_RequestAdminRights(const wchar_t* executablePath, const wchar_t* commandLine)
{
    if (PM_IsAdmin())
    {
        return true; // Уже запущено с правами администратора
    }

    // Запрашиваем права администратора через ShellExecute
    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.lpVerb = L"runas";
    sei.lpFile = executablePath;
    sei.lpParameters = commandLine;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei))
    {
        // Сохраняем ошибку
        SetLastError(GetLastError(), L"Failed to elevate process");
        return false;
    }

    return true;
}