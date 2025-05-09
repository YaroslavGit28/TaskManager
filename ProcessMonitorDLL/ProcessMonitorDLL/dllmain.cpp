﻿#include "pch.h"
#include "ProcessMonitor.h"

static BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Инициализация при загрузке DLL
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // Очистка при выгрузке DLL
        PM_Cleanup();
        break;
    }
    return TRUE;
}