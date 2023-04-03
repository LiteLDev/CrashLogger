#include "crashlogger/Debugger.h"

#include "crashlogger/Logger.h"

#include <windows.h>

using crashlogger::Logger::pLogger;

namespace crashlogger::Debugger {

HANDLE hTargetProcess;

bool InitDebugger() {
    if (!DebugActiveProcess(GetProcessId(hTargetProcess))) {
        pLogger->error("Failed to attach debugger! Error Code: {}", GetLastError());
        return false;
    }
    DebugSetProcessKillOnExit(false);
    return true;
}

DWORD inline OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* e) {
    CloseHandle(e->hFile);
    CloseHandle(e->hProcess);
    CloseHandle(e->hThread);
    return DBG_CONTINUE;
}

DWORD inline OnThreadCreated(const CREATE_THREAD_DEBUG_INFO* e) {
    CloseHandle(e->hThread);
    return DBG_CONTINUE;
}

DWORD inline OnDllLoaded(const LOAD_DLL_DEBUG_INFO* e) {
    CloseHandle(e->hFile);
    return DBG_CONTINUE;
}

DWORD OnException(const EXCEPTION_DEBUG_INFO* e, DWORD dwProcessId, DWORD dwThreadId) {
    using crashlogger::Logger::LogCrash;
    EXCEPTION_POINTERS exception = {nullptr};
    CONTEXT            context{};
    HANDLE             hThread;
    if (e->dwFirstChance) {
        goto Ret;
    }
    if (!(hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, dwThreadId))) {
        pLogger->error("failed to open thread! Error Code: {}", GetLastError());
        goto Ret;
    }
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        pLogger->error("failed to get context! Error Code: {}", GetLastError());
        goto Ret;
    }
    exception.ContextRecord   = &context;
    exception.ExceptionRecord = (PEXCEPTION_RECORD) & (e->ExceptionRecord);
    LogCrash(&exception, hTargetProcess, hThread, dwProcessId, dwThreadId);
Ret:
    return DBG_EXCEPTION_NOT_HANDLED;
}

void DebuggerMain(HANDLE hProcess) {
    DEBUG_EVENT debugEvent;
    bool        exitDebug = false;

    hTargetProcess = hProcess;

    if (!InitDebugger()) {
        return;
    }

    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;
        switch (debugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
                continueStatus = OnException(&debugEvent.u.Exception, debugEvent.dwProcessId, debugEvent.dwThreadId);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            continueStatus = OnThreadCreated(&debugEvent.u.CreateThread);
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            continueStatus = OnProcessCreated(&debugEvent.u.CreateProcessInfo);
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            exitDebug = true;
            break;
        case LOAD_DLL_DEBUG_EVENT:
            continueStatus = OnDllLoaded(&debugEvent.u.LoadDll);
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
        case EXIT_THREAD_DEBUG_EVENT:
        case OUTPUT_DEBUG_STRING_EVENT:
        case RIP_EVENT:
        default:
            break;
        }
        if (exitDebug) {
            break;
        }

        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
    }
}

} // namespace crashlogger::Debugger
