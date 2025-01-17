#pragma once

#include <memory>

#include "spdlog/spdlog.h"

#include <unordered_set>
#include <windows.h>

#define MACHINE_TYPE                IMAGE_FILE_MACHINE_AMD64
#define CRASHLOGGER_LOG_DIR         "./logs/crash"
#define CRASHLOGGER_TRACE_PREFIX    "trace_"
#define CRASHLOGGER_MINIDUMP_PREFIX "minidump_"

#define CRT_EXCEPTION_CODE 0xE06D7363

namespace crashlogger::Logger {

inline std::string                     minidmpPath;
inline std::string                     tracePath;
inline std::string                     minidmpName;
inline std::string                     traceName;
inline std::unordered_set<std::string> suspectedModules;

inline std::shared_ptr<spdlog::logger> pLogger;

void LogCrash(PEXCEPTION_POINTERS e, HANDLE _hProcess, HANDLE _hThread, DWORD _dProcessId, DWORD _dThreadId);

} // namespace crashlogger::Logger
